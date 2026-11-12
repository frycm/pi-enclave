import { describe, expect, it } from "vitest";
import { defaultProfile } from "../../src/config/defaults.ts";
import { canonicalize } from "../../src/policy/canonical.ts";
import { REVIEW_OUTPUT_SCHEMA } from "../../src/reviewer/output.ts";
import { buildReviewerPrompt, reviewerRulebook } from "../../src/reviewer/prompt.ts";
import {
	type CompletionRequest,
	IsolatedReviewer,
	REVIEWER_MAX_TOKENS,
	REVIEWER_SEED,
	type ReviewerCompletion,
	type ReviewerTransport,
} from "../../src/reviewer/reviewer.ts";
import { ReviewerTelemetry, type ReviewerTelemetrySummary } from "../../src/reviewer/telemetry.ts";

const PROFILE = defaultProfile({ cwd: "/work", home: "/home/u", tmp: "/tmp", agentDir: "/home/u/.pi/agent" });
const PROMPT = buildReviewerPrompt(reviewerRulebook(PROFILE.review, new Map()));

function action(command = "touch output.txt") {
	return canonicalize({
		tool: "bash",
		input: { command },
		cwd: "/work",
		home: "/home/u",
		profileName: "dev",
		writableRoots: PROFILE.sandbox.writableRoots,
	});
}

function scripted(name: string, outputs: Array<string | Error>): ReviewerCompletion & { calls: number } {
	return {
		name,
		calls: 0,
		async complete() {
			const result = outputs[this.calls++];
			if (result instanceof Error) throw result;
			if (result === undefined) throw new Error("script exhausted");
			return result;
		},
	};
}

function reviewer(primary: ReviewerTransport, fallback?: ReviewerCompletion) {
	return new IsolatedReviewer({
		profile: PROFILE,
		prompt: PROMPT,
		primary,
		...(fallback ? { fallback } : {}),
		timeoutMs: 1_000,
		evidence: { attended: "off" },
		delay: async () => {},
	});
}

describe("isolated reviewer", () => {
	it("records bounded stage metrics without copying evidence, output or provider errors", async () => {
		const seen: ReviewerTelemetrySummary[] = [];
		let calls = 0;
		const primary: ReviewerCompletion = {
			name: "fixture",
			async complete(request) {
				request.onFirstOutput?.();
				if (++calls === 1) throw new Error("PRIVATE_PROVIDER_DETAIL");
				return '{"authorized":false,"decision":"deny","risk":"high","reason":"PRIVATE_MODEL_OUTPUT"}';
			},
		};
		const result = await new IsolatedReviewer({
			profile: PROFILE,
			prompt: PROMPT,
			primary,
			timeoutMs: 1000,
			evidence: { attended: "off" },
			delay: async () => {},
			onTelemetry: (metrics) => seen.push(metrics),
		}).review({ action: action("touch PRIVATE_ACTION"), trigger: "mutating" });
		expect(result.ok).toBe(true);
		expect(seen).toHaveLength(1);
		expect(seen[0]?.stages.map((stage) => [stage.stage, stage.attempt, stage.outcome])).toEqual([
			["decision", 1, "error"],
			["decision", 2, "ok"],
		]);
		expect(
			seen[0]?.stages.every((stage) => stage.firstOutputMs !== undefined && stage.firstOutputMs <= stage.durationMs),
		).toBe(true);
		expect(JSON.stringify(seen)).not.toContain("PRIVATE_");
	});

	it("settles timeout telemetry even when a transport ignores abort and emits output later", async () => {
		let output!: () => void;
		let metrics: ReviewerTelemetrySummary | undefined;
		await new IsolatedReviewer({
			profile: PROFILE,
			prompt: PROMPT,
			primary: {
				name: "hanging",
				complete: async (request) => {
					output = request.onFirstOutput ?? (() => {});
					return new Promise<string>(() => {});
				},
			},
			timeoutMs: 5,
			maxAttempts: 1,
			evidence: { attended: "off" },
			onTelemetry: (value) => {
				metrics = value;
			},
		}).review({ action: action(), trigger: "mutating" });
		expect(metrics?.stages).toMatchObject([{ outcome: "aborted" }]);
		const before = JSON.stringify(metrics);
		output();
		expect(JSON.stringify(metrics)).toBe(before);
	});

	it("keeps raw exceptions out of pi telemetry spans and records first output only once", async () => {
		const telemetry = new ReviewerTelemetry();
		const controller = new AbortController();
		await expect(
			telemetry.measure("decision", 1, controller.signal, async (first) => {
				first();
				first();
				throw new Error("PRIVATE_EXCEPTION");
			}),
		).rejects.toThrow("PRIVATE_EXCEPTION");
		expect(JSON.stringify(telemetry.context.getSpans())).not.toContain("PRIVATE_EXCEPTION");
		expect(telemetry.context.getSpans()[0]?.events).toHaveLength(1);
		expect(telemetry.context.getMetrics().filter((entry) => entry.name.endsWith("first_output.duration"))).toHaveLength(
			1,
		);
	});

	it("asks for the verdict in one request, constrained by the output schema (#25)", async () => {
		const requests: CompletionRequest[] = [];
		const completion: ReviewerCompletion = {
			name: "primary",
			async complete(request) {
				requests.push(request);
				return '{"authorized":false,"decision":"allow","risk":"low","reason":"routine output"}';
			},
		};
		const result = await reviewer(completion).review({ action: action(), trigger: "mutating" });
		expect(result).toMatchObject({
			ok: true,
			review: { decision: "allow", risk: "medium" },
			modelReview: { authorized: false },
		});
		expect(requests).toHaveLength(1);
		expect(requests[0]).toMatchObject({ system: PROMPT.system, maxTokens: REVIEWER_MAX_TOKENS });
		expect(requests[0]?.schema).toBe(REVIEW_OUTPUT_SCHEMA);
	});

	it("builds live evidence for the exact request being reviewed", async () => {
		const completion = scripted("primary", [
			'{"authorized":false,"decision":"allow","risk":"low","reason":"routine output"}',
		]);
		const proposed = action();
		let observedHash: string | undefined;
		const result = await new IsolatedReviewer({
			profile: PROFILE,
			prompt: PROMPT,
			primary: completion,
			timeoutMs: 1_000,
			evidence: (request) => {
				observedHash = request.action.hash;
				return { attended: "off" };
			},
		}).review({ action: proposed, trigger: "mutating" });
		expect(result.ok).toBe(true);
		expect(observedHash).toBe(proposed.hash);
	});

	it("retries malformed output with the next seed, then reports it as invalid (#25)", async () => {
		const seeds: number[] = [];
		const completion: ReviewerCompletion = {
			name: "primary",
			async complete(request) {
				seeds.push(request.seed);
				return '```json\n{"authorized":false,"decision":"deny","risk":"high","reason":"x"}\n```';
			},
		};
		const result = await reviewer(completion).review({ action: action(), trigger: "mutating" });
		expect(result).toMatchObject({ ok: false, kind: "invalid-output", reason: expect.stringContaining("3 attempt") });
		expect(seeds).toEqual([REVIEWER_SEED, REVIEWER_SEED + 1, REVIEWER_SEED + 2]);
	});

	it("takes a valid verdict that follows a malformed one (#25)", async () => {
		const completion = scripted("primary", [
			" 0",
			'{"authorized":false,"decision":"deny","risk":"high","reason":"deletes the build"}',
		]);
		const result = await reviewer(completion).review({ action: action(), trigger: "mutating" });
		expect(result).toMatchObject({ ok: true, modelReview: { decision: "deny" } });
		expect(completion.calls).toBe(2);
	});

	it("gives a malformed classifier answer the same retries (#25)", async () => {
		let calls = 0;
		const result = await reviewer({
			kind: "classifier",
			name: "fake/classifier",
			numCtx: 16_384,
			thresholds: { allow: 0.9, deny: 0.5, temperature: 1 },
			classify: async () => {
				calls++;
				return {};
			},
		}).review({ action: action(), trigger: "mutating" });
		expect(result).toMatchObject({ ok: false, kind: "invalid-output" });
		expect(calls).toBe(3);
	});

	it("retries transient failures and uses an explicit fallback only on the last attempt", async () => {
		const primary = scripted("primary", [new Error("offline"), new Error("offline")]);
		const fallback = scripted("fallback", [
			'{"authorized":false,"decision":"ask","risk":"medium","reason":"needs confirmation"}',
		]);
		const result = await reviewer(primary, fallback).review({ action: action(), trigger: "mutating" });
		expect(result).toMatchObject({ ok: true, review: { decision: "ask" } });
		expect(primary.calls).toBe(2);
		expect(fallback.calls).toBe(1);
	});

	it("returns an unavailable failure after three bounded attempts", async () => {
		const completion = scripted("primary", [new Error("offline"), new Error("offline"), new Error("offline")]);
		const result = await reviewer(completion).review({ action: action(), trigger: "mutating" });
		expect(result).toMatchObject({ ok: false, kind: "unavailable" });
		expect(completion.calls).toBe(3);
	});

	it("returns at the deadline even when a transport ignores abort", async () => {
		const hanging: ReviewerCompletion = {
			name: "hanging",
			complete: async () => new Promise<string>(() => {}),
		};
		const result = await new IsolatedReviewer({
			profile: PROFILE,
			prompt: PROMPT,
			primary: hanging,
			timeoutMs: 5,
			maxAttempts: 1,
			evidence: { attended: "off" },
		}).review({ action: action(), trigger: "mutating" });
		expect(result).toMatchObject({ ok: false, kind: "unavailable" });
	});
});

it("rejects authorization revoked while the model is in flight", async () => {
	const authorization = [
		{ provenance: "direct" as const, channel: "interactive" as const, text: "Please run rm -rf build" },
	];
	const primary: ReviewerCompletion = {
		name: "fixture",
		async complete() {
			authorization.push({ provenance: "direct", channel: "interactive", text: "Do not run rm -rf build" });
			return '{"authorized":true,"decision":"allow","risk":"low","reason":"stale authorization"}';
		},
	};
	const result = await new IsolatedReviewer({
		profile: PROFILE,
		prompt: PROMPT,
		primary,
		timeoutMs: 1000,
		evidence: () => ({ attended: "off", authorization }),
	}).review({ action: action("rm -rf build"), trigger: "mutating" });
	expect(result).toMatchObject({ ok: false, reason: expect.stringContaining("authorization changed") });
});
