import { stream as streamOpenAI } from "@earendil-works/pi-ai/api/openai-completions";
import type { ModelRegistry } from "@earendil-works/pi-coding-agent";
import { describe, expect, it, vi } from "vitest";
import { type RuntimeModel, resolveReviewerModel, reviewerModelDigest } from "../../src/reviewer/model.ts";

vi.mock("@earendil-works/pi-ai/api/openai-completions", () => ({ stream: vi.fn() }));

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
	vi.mocked(streamOpenAI).mockImplementation(
		(...args) => ({ result: () => complete(...args) }) as ReturnType<typeof streamOpenAI>,
	);
	return {
		complete,
		value: {
			find: (provider: string, id: string) => (provider === MODEL.provider && id === MODEL.id ? MODEL : undefined),
			getApiKeyAndHeaders: async () => ({ ok: true }),
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
			samplingParams: { seed: 31337 },
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

it.each([
	"http://[::1]:1234/v1",
	"http://localhost.:1234/v1",
	"http://127.0.0.2:1234/v1",
	"http://[::ffff:127.0.0.1]:1234/v1",
	"http://127.1:1234/v1",
	"http://0.0.0.0:1234/v1",
	"http://[::]:1234/v1",
])("refuses unsupported local identity %s", async (baseUrl) => {
	await expect(reviewerModelDigest({ ...MODEL, baseUrl })).rejects.toThrow("exact weights digest");
});
it("refuses adapters that ignore the required sampling seed", async () => {
	await expect(reviewerModelDigest({ ...MODEL, api: "anthropic-messages" })).rejects.toThrow("required seed");
});

it("hashes real registry auth and model metadata with absent optional fields", async () => {
	const { ModelRegistry: Registry } = await import("@earendil-works/pi-coding-agent");
	const model = {
		...MODEL,
		headers: undefined,
		samplingParams: undefined,
		compat: undefined,
	} as unknown as RuntimeModel;
	const registry = new Registry({
		getAuth: async () => ({ auth: { apiKey: "fixture-key", headers: undefined }, env: undefined }),
	} as unknown as ConstructorParameters<typeof Registry>[0]);
	await expect(reviewerModelDigest(model, registry)).resolves.toMatch(/^cloud:sha256:/);
});

it("executes the checked cloud snapshot without re-resolving auth in ModelRegistry.complete", async () => {
	const { bindReviewerCompletion } = await import("../../src/reviewer/model.ts");
	const fake = registry();
	let calls = 0;
	fake.value.getApiKeyAndHeaders = async () => ({
		ok: true,
		apiKey: "fixture-key",
		baseUrl: ++calls === 3 ? "https://unqualified.example.test/v1" : MODEL.baseUrl,
	});
	fake.value.complete = async () => {
		throw new Error("must not re-resolve auth");
	};
	const identity = await reviewerModelDigest(MODEL, fake.value);
	const resolved = resolveReviewerModel(fake.value, "cloud/reviewer-2026-09-01");
	await expect(
		bindReviewerCompletion(resolved, identity).complete({
			system: "system",
			user: "evidence",
			signal: AbortSignal.timeout(1000),
			maxTokens: 1,
			temperature: 0,
			seed: 31337,
			numCtx: 4096,
		}),
	).rejects.toThrow("identity changed");
	expect(fake.complete.mock.calls[0]?.[0]).toMatchObject({ baseUrl: MODEL.baseUrl });
});
