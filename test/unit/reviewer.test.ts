import { describe, expect, it } from "vitest";
import { defaultProfile } from "../../src/config/defaults.ts";
import { canonicalize } from "../../src/policy/canonical.ts";
import { buildReviewerPrompt, reviewerRulebook } from "../../src/reviewer/prompt.ts";
import { IsolatedReviewer, type ReviewerCompletion } from "../../src/reviewer/reviewer.ts";

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

function reviewer(primary: ReviewerCompletion, fallback?: ReviewerCompletion) {
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
	it("runs the one-token authorization stage before the strict verdict", async () => {
		const completion = scripted("primary", ["0", '{"decision":"allow","risk":"low","reason":"routine output"}']);
		const result = await reviewer(completion).review({ action: action(), trigger: "mutating" });
		expect(result).toMatchObject({ ok: true, review: { decision: "allow", risk: "medium" } });
		expect(completion.calls).toBe(2);
	});

	it("builds live evidence for the exact request being reviewed", async () => {
		const completion = scripted("primary", ["0", '{"decision":"allow","risk":"low","reason":"routine output"}']);
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

	it("does not retry malformed authorization output", async () => {
		const completion = scripted("primary", ["yes"]);
		const result = await reviewer(completion).review({ action: action(), trigger: "mutating" });
		expect(result).toMatchObject({ ok: false, kind: "invalid-output" });
		expect(completion.calls).toBe(1);
	});

	it("does not re-prompt a malformed structured verdict", async () => {
		const completion = scripted("primary", ["0", "```json\n{}\n```"]);
		const result = await reviewer(completion).review({ action: action(), trigger: "mutating" });
		expect(result).toMatchObject({ ok: false, kind: "invalid-output" });
		expect(completion.calls).toBe(2);
	});

	it("retries transient failures and uses an explicit fallback only on the last attempt", async () => {
		const primary = scripted("primary", [new Error("offline"), new Error("offline")]);
		const fallback = scripted("fallback", ["0", '{"decision":"ask","risk":"medium","reason":"needs confirmation"}']);
		const result = await reviewer(primary, fallback).review({ action: action(), trigger: "mutating" });
		expect(result).toMatchObject({ ok: true, review: { decision: "ask" } });
		expect(primary.calls).toBe(2);
		expect(fallback.calls).toBe(2);
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
