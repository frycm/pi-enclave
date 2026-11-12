/**
 * The per-category minimum is part of the pass bit (#27): a corpus missing a
 * category fails qualification even when every case it does hold is judged
 * right. The shipped corpus always has every category, so this file removes
 * one through a mock.
 */
import type { ClassifierAnswer } from "@earendil-works/pi-ai";
import { describe, expect, it, vi } from "vitest";
import { defaultProfile } from "../../src/config/defaults.ts";
import { buildReviewerPrompt, reviewerRulebook } from "../../src/reviewer/prompt.ts";
import type { ReviewerClassifier, ReviewerCompletion } from "../../src/reviewer/reviewer.ts";
import { corpusLabels, labelOf } from "../harness/corpus-oracle.ts";

const removed = vi.hoisted(() => ({ category: undefined as string | undefined }));

vi.mock("../../src/reviewer/corpus.ts", async (importOriginal) => {
	const original = await importOriginal<typeof import("../../src/reviewer/corpus.ts")>();
	return {
		...original,
		reviewerCorpus: (profile: Parameters<typeof original.reviewerCorpus>[0]) =>
			original.reviewerCorpus(profile).filter((entry) => entry.category !== removed.category),
	};
});

const { evalReviewer } = await import("../../src/reviewer/eval.ts");

const PROFILE = defaultProfile({
	cwd: "/work",
	home: "/nonexistent-home/u",
	tmp: "/tmp",
	agentDir: "/nonexistent-home/u/.pi/agent",
});
const PROMPT = buildReviewerPrompt(reviewerRulebook(PROFILE.review, new Map(), PROFILE.rules));
const LABELS = corpusLabels(PROFILE);

const chat: ReviewerCompletion = {
	name: "fake/oracle",
	async complete(request) {
		const benign = labelOf(LABELS, request.user) === "benign";
		return JSON.stringify({
			authorized: benign,
			decision: benign ? "allow" : "deny",
			risk: benign ? "low" : "high",
			reason: "oracle",
		});
	},
};

const classifier: ReviewerClassifier = {
	kind: "classifier",
	name: "fake/oracle-classifier",
	numCtx: 16_384,
	thresholds: { allow: 1, deny: 0.5, temperature: 1 },
	async classify(request) {
		const allow = labelOf(LABELS, JSON.stringify(request.state)) === "benign" ? 0.97 : 0.02;
		const answers: Record<string, ClassifierAnswer> = {
			authorized: { type: "bool", probability: allow },
			decision: {
				type: "choice",
				choice: allow > 0.5 ? "allow" : "deny",
				probabilities: { allow, ask: 0.01, deny: 0.99 - allow },
				confidence: 0.9,
			},
			risk: {
				type: "choice",
				choice: "low",
				probabilities: { low: 0.97, medium: 0.01, high: 0.01, critical: 0.01 },
				confidence: 0.9,
			},
		};
		return answers;
	},
};

function run(completion: ReviewerCompletion | ReviewerClassifier) {
	return evalReviewer({
		model: "fake/oracle",
		modelDigest: "cloud:sha256:abc",
		profile: PROFILE,
		prompt: PROMPT,
		completion,
		timeoutMs: 10_000,
		trials: 1,
	});
}

describe.each([
	["chat", chat],
	["classifier", classifier],
] as const)("the %s transport", (_name, completion) => {
	it("passes the full corpus with a reviewer that judges every case right", async () => {
		removed.category = undefined;
		const record = await run(completion);
		expect(record.metrics.thinCategories).toEqual([]);
		expect(record.passed).toBe(true);
	});

	it("fails when a category is missing, though every remaining case is judged right", async () => {
		removed.category = "shell";
		const record = await run(completion);
		expect(record.metrics).toMatchObject({ injectedAllows: 0, benignFalseDenials: 0, errors: 0 });
		expect(record.metrics.thinCategories).toEqual(["shell"]);
		expect(record.passed).toBe(false);
	});
});
