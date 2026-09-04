import { chmodSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { defaultProfile } from "../../src/config/defaults.ts";
import { reviewerCorpus, reviewerCorpusHash } from "../../src/reviewer/corpus.ts";
import { evalReviewer } from "../../src/reviewer/eval.ts";
import { buildReviewerPrompt, reviewerRulebook } from "../../src/reviewer/prompt.ts";
import {
	type QualificationRecord,
	qualificationPath,
	readQualification,
	writeQualification,
} from "../../src/reviewer/qualification.ts";
import type { CompletionRequest, ReviewerCompletion } from "../../src/reviewer/reviewer.ts";

const PROFILE = defaultProfile({ cwd: "/work", home: "/home/u", tmp: "/tmp", agentDir: "/home/u/.pi/agent" });
const PROMPT = buildReviewerPrompt(reviewerRulebook(PROFILE.review, new Map()));
const directories: string[] = [];

afterEach(() => {
	for (const directory of directories.splice(0)) rmSync(directory, { recursive: true, force: true });
});

function completion(verdict: (evidence: Record<string, unknown>) => "allow" | "deny"): ReviewerCompletion {
	return {
		name: "fake/reviewer",
		async complete(request: CompletionRequest) {
			const evidence = JSON.parse(request.user) as Record<string, unknown>;
			if (request.maxTokens === 1) {
				return Array.isArray(evidence.authorization) && evidence.authorization.length > 0 ? "1" : "0";
			}
			const decision = verdict(evidence);
			return JSON.stringify({ decision, risk: decision === "allow" ? "low" : "high", reason: "eval verdict" });
		},
	};
}

function options(transport: ReviewerCompletion) {
	return {
		model: "fake/reviewer",
		modelDigest: "cloud:sha256:abc",
		profile: PROFILE,
		prompt: PROMPT,
		completion: transport,
		timeoutMs: 10_000,
		trials: 1,
	};
}

describe("reviewer qualification", () => {
	it("ships a stable 80-case corpus", () => {
		const corpus = reviewerCorpus(PROFILE);
		expect(corpus).toHaveLength(80);
		expect(corpus.filter((entry) => entry.kind === "benign")).toHaveLength(20);
		expect(reviewerCorpusHash(corpus)).toMatch(/^sha256:[0-9a-f]{64}$/);
	});

	it("passes only a useful reviewer that rejects every injected case", async () => {
		const record = await evalReviewer(
			options(
				completion((evidence) => {
					const action = evidence.action as { input: Record<string, unknown> };
					return typeof action.input.content === "string" && action.input.content.startsWith("routine generated report")
						? "allow"
						: "deny";
				}),
			),
		);
		expect(record.passed).toBe(true);
		expect(record.metrics).toMatchObject({ injectedAllows: 0, benignFalseDenials: 0, errors: 0 });
	});

	it("fails on even one injected allow", async () => {
		const record = await evalReviewer(options(completion(() => "allow")));
		expect(record.passed).toBe(false);
		expect(record.metrics.injectedAllows).toBeGreaterThan(0);
	});

	it("writes a mode-600 record and checks every qualification binding", async () => {
		const directory = mkdtempSync(join(tmpdir(), "pi-enclave-qualification-"));
		directories.push(directory);
		chmodSync(directory, 0o700);
		const record: QualificationRecord = {
			version: 1,
			model: "fake/reviewer",
			modelDigest: "cloud:sha256:abc",
			promptHash: PROMPT.promptHash,
			corpusHash: "sha256:corpus",
			sampling: { temperature: 0, seed: 31337, numCtx: 4096, maxTokens: 256, trials: 5 },
			passed: true,
			metrics: {
				injectedAllows: 0,
				benignCases: 100,
				benignFalseDenials: 0,
				falseDenialRate: 0,
				p95LatencyMs: 10,
				errors: 0,
			},
			createdAt: new Date(0).toISOString(),
		};
		const path = writeQualification(directory, record);
		expect(path).toBe(qualificationPath(directory, record.modelDigest));
		expect(readQualification(directory, record)).toMatchObject({ ok: true });
		expect(readQualification(directory, { ...record, promptHash: "sha256:changed" })).toMatchObject({
			ok: false,
			reason: "promptHash changed since qualification",
		});
		chmodSync(path, 0o644);
		expect(readQualification(directory, record)).toMatchObject({ ok: false });
	});
});
