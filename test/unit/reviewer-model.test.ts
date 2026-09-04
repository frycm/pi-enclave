import type { ModelRegistry } from "@earendil-works/pi-coding-agent";
import { describe, expect, it, vi } from "vitest";
import { type RuntimeModel, resolveReviewerModel, reviewerModelDigest } from "../../src/reviewer/model.ts";

const MODEL = {
	provider: "cloud",
	id: "reviewer-2026-09-01",
	name: "Reviewer",
	api: "openai-completions",
	baseUrl: "https://models.example.test/v1",
	reasoning: false,
	input: ["text"],
	cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
	contextWindow: 8192,
	maxTokens: 1024,
} as RuntimeModel;

function registry(options: { authenticated?: boolean } = {}) {
	const complete = vi.fn(async (..._args: unknown[]) => ({
		role: "assistant",
		content: [{ type: "text", text: "isolated answer" }],
		stopReason: "stop",
		timestamp: Date.now(),
	}));
	return {
		complete,
		value: {
			find: (provider: string, id: string) => (provider === MODEL.provider && id === MODEL.id ? MODEL : undefined),
			hasConfiguredAuth: () => options.authenticated ?? true,
			complete,
		} as unknown as ModelRegistry,
	};
}

describe("reviewer model transport", () => {
	it("creates a fresh completion with no session messages or tools", async () => {
		const fake = registry();
		const resolved = resolveReviewerModel(fake.value, "cloud/reviewer-2026-09-01");
		const controller = new AbortController();
		await expect(
			resolved.completion.complete({
				system: "reviewer system",
				user: '{"action":"evidence"}',
				signal: controller.signal,
				maxTokens: 256,
				temperature: 0,
				seed: 31337,
				numCtx: 4096,
			}),
		).resolves.toBe("isolated answer");

		const [, context, options] = fake.complete.mock.calls[0] ?? [];
		expect(context).toMatchObject({
			systemPrompt: "reviewer system",
			messages: [{ role: "user", content: [{ type: "text", text: '{"action":"evidence"}' }] }],
		});
		expect(context).not.toHaveProperty("tools");
		expect(options).toMatchObject({
			temperature: 0,
			maxTokens: 256,
			maxRetries: 0,
			cacheRetention: "none",
			samplingParams: { seed: 31337, num_ctx: 4096 },
		});
	});

	it("refuses an unauthenticated configured model", () => {
		expect(() => resolveReviewerModel(registry({ authenticated: false }).value, "cloud/reviewer-2026-09-01")).toThrow(
			"no configured provider authentication",
		);
	});

	it("binds remote descriptors and refuses ambiguous non-Ollama local identities", async () => {
		await expect(reviewerModelDigest(MODEL)).resolves.toMatch(/^cloud:sha256:[0-9a-f]{64}$/);
		await expect(reviewerModelDigest({ ...MODEL, baseUrl: "http://127.0.0.1:9000" })).rejects.toThrow(
			"does not expose an exact weights digest",
		);
	});
});
