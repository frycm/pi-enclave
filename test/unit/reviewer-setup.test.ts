import { chmodSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { ModelRegistry } from "@earendil-works/pi-coding-agent";
import { afterEach, describe, expect, it } from "vitest";
import { defaultProfile } from "../../src/config/defaults.ts";
import type { Provenance } from "../../src/config/types.ts";
import { qualificationBinding } from "../../src/reviewer/eval.ts";
import { type RuntimeModel, reviewerModelDigest } from "../../src/reviewer/model.ts";
import { buildReviewerPrompt, reviewerRulebook } from "../../src/reviewer/prompt.ts";
import { type QualificationRecord, writeQualification } from "../../src/reviewer/qualification.ts";
import { prepareQualifiedReviewer } from "../../src/reviewer/setup.ts";

const directories: string[] = [];
afterEach(() => {
	for (const directory of directories.splice(0)) rmSync(directory, { recursive: true, force: true });
});

const model = {
	provider: "cloud",
	id: "reviewer-v1",
	name: "Reviewer",
	api: "openai-completions",
	baseUrl: "https://models.example.test/v1",
	reasoning: false,
	input: ["text"],
	cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
	contextWindow: 8192,
	maxTokens: 1024,
} as RuntimeModel;

const registry = {
	find: (provider: string, id: string) => (provider === model.provider && id === model.id ? model : undefined),
	getApiKeyAndHeaders: async () => ({ ok: true }),
	hasConfiguredAuth: () => true,
	complete: async () => {
		throw new Error("not called during setup");
	},
} as unknown as ModelRegistry;

function fixture() {
	const profile = defaultProfile({ cwd: "/work", home: "/home/u", tmp: "/tmp", agentDir: "/home/u/.pi/agent" });
	profile.reviewer.model = "cloud/reviewer-v1";
	profile.review.trigger = "mutating";
	const provenance: Provenance = new Map();
	const directory = mkdtempSync(join(tmpdir(), "pi-enclave-reviewer-setup-"));
	directories.push(directory);
	chmodSync(directory, 0o700);
	return { profile, provenance, directory };
}

describe("qualified reviewer startup", () => {
	it("refuses a named model with no matching local qualification", async () => {
		const { profile, provenance, directory } = fixture();
		await expect(prepareQualifiedReviewer(profile, provenance, registry, directory)).rejects.toThrow(
			"/enclave eval-reviewer",
		);
	});

	it("accepts only a record bound to the current model, prompt, corpus, and sampling", async () => {
		const { profile, provenance, directory } = fixture();
		const prompt = buildReviewerPrompt(reviewerRulebook(profile.review, provenance, profile.rules));
		const modelDigest = await reviewerModelDigest(model, registry);
		const binding = qualificationBinding({
			model: profile.reviewer.model,
			modelDigest,
			profile,
			prompt,
			completion: { name: "unused", numCtx: null, complete: async () => "0" },
			timeoutMs: profile.reviewer.timeoutMs,
		});
		const record: QualificationRecord = {
			version: 2,
			...binding,
			passed: true,
			metrics: {
				injectedAllows: 0,
				benignCases: 100,
				benignFalseDenials: 0,
				falseDenialRate: 0,
				p95LatencyMs: 100,
				errors: 0,
			},
			createdAt: new Date(0).toISOString(),
		};
		writeQualification(directory, record);
		await expect(prepareQualifiedReviewer(profile, provenance, registry, directory)).resolves.toMatchObject({
			primary: { name: profile.reviewer.model },
		});

		profile.review.soft_deny = ["Never deploy previews"];
		await expect(prepareQualifiedReviewer(profile, provenance, registry, directory)).rejects.toThrow(
			"promptHash changed",
		);
	});

	it("does not require an unused named reviewer when auto mode is off", async () => {
		const { profile, provenance, directory } = fixture();
		profile.auto = false;
		await expect(prepareQualifiedReviewer(profile, provenance, registry, directory)).resolves.toBeUndefined();
	});
});

describe("the thinking budget at startup (#62)", () => {
	const ollama = {
		...model,
		provider: "ollama",
		id: "reviewer",
		baseUrl: "http://127.0.0.1:9/v1",
	} as RuntimeModel;
	const both = {
		...registry,
		find: (provider: string, id: string) =>
			provider === "ollama" && id === "reviewer" ? ollama : registry.find(provider, id),
	} as unknown as ModelRegistry;

	it("refuses thinking for a reviewer that is not on Ollama", async () => {
		const { profile, provenance, directory } = fixture();
		profile.reviewer.thinkingTokens = 1_024;
		await expect(prepareQualifiedReviewer(profile, provenance, both, directory)).rejects.toThrow(
			"supported only for an Ollama chat reviewer",
		);
	});

	it("refuses thinking on the classifier transport", async () => {
		const { profile, provenance, directory } = fixture();
		profile.reviewer.model = "llama.cpp/qwen3-4b";
		profile.reviewer.transport = "classifier";
		profile.reviewer.thinkingTokens = 1_024;
		await expect(prepareQualifiedReviewer(profile, provenance, both, directory)).rejects.toThrow(
			'applies only to reviewer.transport "chat"',
		);
	});

	it("refuses a budget that leaves the evidence too little room, before asking the server", async () => {
		const { profile, provenance, directory } = fixture();
		profile.reviewer.model = "ollama/reviewer";
		profile.reviewer.thinkingTokens = 2_048;
		await expect(prepareQualifiedReviewer(profile, provenance, both, directory)).rejects.toThrow(
			"reviewer.numCtx 8192 with reviewer.thinkingTokens 2048 leaves",
		);
		// Control: a larger context leaves room, and setup goes on to the server (here unreachable).
		profile.reviewer.numCtx = 16_384;
		const error = await prepareQualifiedReviewer(profile, provenance, both, directory).catch((caught) => caught);
		expect(String(error)).not.toContain("leaves");
	});
});
