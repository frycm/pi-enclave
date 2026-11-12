/** The classifier protocol (#26): probabilities to verdict, and the records that bind it. */
import { chmodSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { ClassifierAnswer } from "@earendil-works/pi-ai";
import { VERSION } from "@earendil-works/pi-coding-agent";
import { afterEach, describe, expect, it } from "vitest";
import { defaultProfile } from "../../src/config/defaults.ts";
import { canonicalize } from "../../src/policy/canonical.ts";
import { qualificationBinding } from "../../src/reviewer/eval.ts";
import { classifierRuntimeVersion } from "../../src/reviewer/llama.ts";
import {
	CLASSIFIER_ALLOW_CEILING,
	CLASSIFIER_ALLOW_FLOOR,
	chooseAllowThreshold,
	classifierRisk,
	parseReviewProbabilities,
	reviewFromProbabilities,
} from "../../src/reviewer/probabilities.ts";
import { buildReviewerPrompt, reviewerRulebook } from "../../src/reviewer/prompt.ts";
import {
	isQualificationRecord,
	type QualificationRecord,
	readQualification,
	writeQualification,
} from "../../src/reviewer/qualification.ts";
import { IsolatedReviewer, type ReviewerClassifier } from "../../src/reviewer/reviewer.ts";
import type { ReviewProbabilities } from "../../src/reviewer/types.ts";
import { reviewerVerdictFields } from "../../src/state/audit.ts";

const PROFILE = defaultProfile({ cwd: "/work", home: "/home/u", tmp: "/tmp", agentDir: "/home/u/.pi/agent" });
const PROMPT = buildReviewerPrompt(reviewerRulebook(PROFILE.review, new Map()));
const THRESHOLDS = { allow: 0.9, deny: 0.5, temperature: 1 };
const directories: string[] = [];

afterEach(() => {
	for (const directory of directories.splice(0)) rmSync(directory, { recursive: true, force: true });
});

function probabilities(allow: number, deny: number, risk = [0.7, 0.2, 0.05, 0.05]): ReviewProbabilities {
	return {
		authorized: 0.5,
		decision: { allow, ask: 1 - allow - deny, deny },
		risk: { low: risk[0] ?? 0, medium: risk[1] ?? 0, high: risk[2] ?? 0, critical: risk[3] ?? 0 },
	};
}

function answers(overrides: Record<string, ClassifierAnswer | undefined> = {}): Record<string, ClassifierAnswer> {
	const base: Record<string, ClassifierAnswer> = {
		authorized: { type: "bool", probability: 0.8 },
		decision: { type: "choice", choice: "allow", probabilities: { allow: 0.95, ask: 0.03, deny: 0.02 }, confidence: 1 },
		risk: {
			type: "choice",
			choice: "low",
			probabilities: { low: 0.9, medium: 0.05, high: 0.03, critical: 0.02 },
			confidence: 1,
		},
	};
	return Object.fromEntries(
		Object.entries({ ...base, ...overrides }).filter((entry): entry is [string, ClassifierAnswer] => !!entry[1]),
	);
}

function classifier(result: Record<string, ClassifierAnswer>): ReviewerClassifier {
	return {
		kind: "classifier",
		name: "fake/classifier",
		numCtx: 8192,
		thresholds: THRESHOLDS,
		classify: async () => result,
	};
}

const ACTION = canonicalize({
	tool: "write",
	input: { path: "/work/out.txt", content: "x" },
	cwd: "/work",
	home: "/home/u",
	profileName: "dev",
	writableRoots: ["/work"],
});

describe("probabilities to verdict", () => {
	it("allows only at or above the allow threshold", () => {
		expect(reviewFromProbabilities(probabilities(0.9, 0.05), THRESHOLDS).decision).toBe("allow");
		expect(reviewFromProbabilities(probabilities(0.899, 0.05), THRESHOLDS).decision).toBe("ask");
	});

	it("denies on a deny majority and asks otherwise", () => {
		expect(reviewFromProbabilities(probabilities(0.2, 0.5), THRESHOLDS).decision).toBe("deny");
		expect(reviewFromProbabilities(probabilities(0.4, 0.4), THRESHOLDS)).toMatchObject({
			decision: "ask",
			reason: expect.stringContaining("uncertain"),
		});
	});

	it("takes the highest risk level that holds the tail mass, not the most likely one", () => {
		expect(classifierRisk({ low: 0.7, medium: 0.05, high: 0.15, critical: 0.1 })).toBe("high");
		expect(classifierRisk({ low: 0.6, medium: 0.1, high: 0.05, critical: 0.25 })).toBe("critical");
		expect(classifierRisk({ low: 0.9, medium: 0.05, high: 0.03, critical: 0.02 })).toBe("low");
	});

	it("chooses an allow threshold above every injected case, within floor and ceiling", () => {
		expect(chooseAllowThreshold([0.01, 0.2])).toBe(CLASSIFIER_ALLOW_FLOOR);
		expect(chooseAllowThreshold([0.9])).toBeCloseTo(0.95, 6);
		expect(chooseAllowThreshold([0.9]) ?? 0).toBeGreaterThan(0.9);
		expect(chooseAllowThreshold([CLASSIFIER_ALLOW_CEILING])).toBeUndefined();
		expect(chooseAllowThreshold([])).toBe(CLASSIFIER_ALLOW_FLOOR);
	});
});

describe("classifier answers are validated before they become a verdict", () => {
	it.each([
		["a missing question", answers({ risk: undefined })],
		["a bool asked as a choice", answers({ authorized: { type: "score", score: 1, confidence: 1 } })],
		[
			"an unexpected option",
			answers({
				decision: { type: "choice", choice: "allow", probabilities: { allow: 1, maybe: 0 }, confidence: 1 },
			}),
		],
		[
			"a probability above one",
			answers({
				decision: { type: "choice", choice: "allow", probabilities: { allow: 2, ask: 0, deny: 0 }, confidence: 1 },
			}),
		],
	])("treats %s as invalid output, not as a decision", async (_label, result) => {
		expect(() => parseReviewProbabilities(result)).toThrow("invalid reviewer output");
		const review = await new IsolatedReviewer({
			profile: PROFILE,
			prompt: PROMPT,
			primary: classifier(result),
			timeoutMs: 1_000,
			evidence: { attended: "off" },
		}).review({ action: ACTION, trigger: "mutating" });
		expect(review).toMatchObject({ ok: false, kind: "invalid-output" });
	});

	it("records the probabilities in the audit verdict", async () => {
		const result = await new IsolatedReviewer({
			profile: PROFILE,
			prompt: PROMPT,
			primary: classifier(answers()),
			timeoutMs: 1_000,
			evidence: { attended: "off" },
		}).review({ action: ACTION, trigger: "mutating" });
		expect(result.ok && result.modelReview.decision).toBe("allow");
		expect(reviewerVerdictFields(result, { action: ACTION, trigger: "mutating" })).toMatchObject({
			ok: true,
			modelDecision: "allow",
			probabilities: { authorized: 0.8, decision: { allow: 0.95 }, risk: { low: 0.9 } },
		});
	});

	it("keeps the rulebook in the questions and the evidence out of them", () => {
		const rulebook = reviewerRulebook(
			{ ...PROFILE.review, hard_deny: ["Never touch production databases"] },
			new Map([["review.hard_deny", new Map([["Never touch production databases", "user_global"]])]]),
		);
		const prompt = buildReviewerPrompt(rulebook);
		expect(prompt.classifier.questions.decision?.instructions).toContain("Never touch production databases");
		expect(prompt.classifier.promptHash).not.toBe(PROMPT.classifier.promptHash);
		expect(prompt.classifier.promptHash).not.toBe(prompt.promptHash);
	});
});

describe("qualification records bind the transport", () => {
	const chat: QualificationRecord = {
		version: 2,
		model: "llama.cpp/qwen3-4b",
		modelDigest: "llama.cpp:sha256:abc",
		promptHash: PROMPT.classifier.promptHash,
		corpusHash: "sha256:corpus",
		sampling: { temperature: 1, seed: 0, numCtx: 8192, maxTokens: 1, trials: 1 },
		passed: true,
		metrics: {
			injectedAllows: 0,
			benignCases: 20,
			benignFalseDenials: 0,
			falseDenialRate: 0,
			p95LatencyMs: 10,
			errors: 0,
		},
		createdAt: new Date(0).toISOString(),
	};

	const classifierRecord: QualificationRecord = {
		...chat,
		transport: "classifier",
		piVersion: "1.5.2",
		thresholds: THRESHOLDS,
	};

	it("needs thresholds for a classifier record and none for a chat record", () => {
		expect(isQualificationRecord(classifierRecord)).toBe(true);
		expect(isQualificationRecord({ ...chat, transport: "classifier", piVersion: "1.5.2" })).toBe(false);
		expect(isQualificationRecord({ ...classifierRecord, thresholds: { ...THRESHOLDS, allow: 2 } })).toBe(false);
		expect(isQualificationRecord({ ...chat, thresholds: THRESHOLDS })).toBe(false);
		expect(isQualificationRecord({ ...chat, transport: "completion" })).toBe(false);
	});

	it("reads a record from before #26 as chat, and never as a classifier qualification", () => {
		const directory = mkdtempSync(join(tmpdir(), "pi-enclave-transport-"));
		directories.push(directory);
		chmodSync(directory, 0o700);
		writeQualification(directory, chat);
		expect(readQualification(directory, chat)).toMatchObject({ ok: true });
		expect(readQualification(directory, { ...chat, transport: "chat" })).toMatchObject({ ok: true });
		expect(readQualification(directory, { ...chat, transport: "classifier" })).toMatchObject({
			ok: false,
			reason: expect.stringContaining("qualifies the chat transport, not classifier"),
		});
	});

	it("checks the thresholds on read against what qualification can choose", () => {
		for (const thresholds of [
			{ ...THRESHOLDS, allow: 0.05 },
			{ ...THRESHOLDS, allow: CLASSIFIER_ALLOW_FLOOR - 0.001 },
			{ ...THRESHOLDS, allow: CLASSIFIER_ALLOW_CEILING + 0.001 },
			{ ...THRESHOLDS, deny: 0.9 },
			{ ...THRESHOLDS, temperature: 7 },
		]) {
			expect(isQualificationRecord({ ...classifierRecord, thresholds })).toBe(false);
		}
		// The thresholds' temperature is the one the sampling binds.
		expect(
			isQualificationRecord({ ...classifierRecord, sampling: { ...classifierRecord.sampling, temperature: 0.5 } }),
		).toBe(false);
		for (const allow of [CLASSIFIER_ALLOW_FLOOR, 0.95, CLASSIFIER_ALLOW_CEILING]) {
			expect(isQualificationRecord({ ...classifierRecord, thresholds: { ...THRESHOLDS, allow } })).toBe(true);
		}
	});

	it("binds the pi version for the classifier, whose prompt pi-ai owns", () => {
		expect(isQualificationRecord({ ...classifierRecord, piVersion: undefined })).toBe(false);
		expect(isQualificationRecord({ ...chat, piVersion: "1.5.2" })).toBe(false);
		const directory = mkdtempSync(join(tmpdir(), "pi-enclave-version-"));
		directories.push(directory);
		chmodSync(directory, 0o700);
		writeQualification(directory, classifierRecord);
		expect(readQualification(directory, classifierRecord)).toMatchObject({ ok: true });
		expect(readQualification(directory, { ...classifierRecord, piVersion: "1.5.3" })).toMatchObject({
			ok: false,
			reason: expect.stringContaining("qualified on pi 1.5.2, running pi 1.5.3"),
		});
	});

	it("takes the running pi version into the classifier binding, and refuses without one", () => {
		const binding = qualificationBinding({
			model: "llama.cpp/qwen3-4b",
			modelDigest: "llama.cpp:sha256:abc",
			profile: PROFILE,
			prompt: PROMPT,
			completion: classifier(answers()),
			timeoutMs: 1_000,
		});
		expect(binding.piVersion).toBe(VERSION);
		expect(typeof VERSION).toBe("string");
		for (const missing of [null, "", 152]) {
			expect(() => classifierRuntimeVersion(missing)).toThrow("pi did not report its version");
		}
		// The chat transport's prompt is pi-enclave's own; a pi update does not touch it.
		expect(
			qualificationBinding({
				model: "ollama/reviewer",
				modelDigest: "ollama:sha256:abc",
				profile: PROFILE,
				prompt: PROMPT,
				completion: { name: "ollama/reviewer", numCtx: 8192, complete: async () => "1" },
				timeoutMs: 1_000,
			}).piVersion,
		).toBeUndefined();
	});
});
