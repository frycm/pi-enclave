import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import type { ModelRegistry } from "@earendil-works/pi-coding-agent";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
	bindReviewerCompletion,
	type RuntimeModel,
	resolveReviewerModel,
	reviewerModelDigest,
} from "../../src/reviewer/model.ts";
import type { CompletionRequest } from "../../src/reviewer/reviewer.ts";

let server: Server;
let baseUrl: string;
let manifest: string;
let context: number;
let mutateDuringChat: boolean;
let redirect: boolean;
let received: Array<{ url: string; body: Record<string, unknown>; authorization?: string }>;

beforeEach(async () => {
	manifest = "a".repeat(64);
	context = 4096;
	mutateDuringChat = false;
	redirect = false;
	received = [];
	server = createServer(async (req, res) => {
		const chunks = [];
		for await (const chunk of req) chunks.push(chunk);
		const body = JSON.parse(Buffer.concat(chunks).toString() || "{}");
		received.push({
			url: req.url ?? "",
			body,
			...(req.headers.authorization ? { authorization: req.headers.authorization } : {}),
		});
		res.setHeader("Content-Type", "application/json");
		if (redirect) {
			res.writeHead(302, { Location: "/elsewhere" });
			res.end();
			return;
		}
		if (req.url?.endsWith("/api/tags"))
			res.end(JSON.stringify({ models: [{ name: "reviewer:latest", digest: manifest }] }));
		else if (req.url?.endsWith("/api/version")) res.end(JSON.stringify({ version: "test-runtime" }));
		else if (req.url?.endsWith("/api/ps"))
			res.end(JSON.stringify({ models: [{ name: "reviewer:latest", digest: manifest, context_length: context }] }));
		else if (req.url?.endsWith("/api/chat")) {
			if (mutateDuringChat) manifest = "b".repeat(64);
			res.end(JSON.stringify({ done: true, message: { role: "assistant", content: "1" } }));
		} else {
			res.writeHead(404);
			res.end("{}");
		}
	});
	await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
	baseUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}/proxy/v1`;
});
afterEach(async () => {
	server.closeAllConnections();
	await new Promise<void>((resolve) => server.close(() => resolve()));
});

function fixture() {
	const model = {
		provider: "ollama",
		id: "reviewer",
		name: "Reviewer",
		api: "openai-completions",
		baseUrl: "http://wrong-server.invalid/v1",
		reasoning: false,
		input: ["text"],
		cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
		contextWindow: 4096,
		maxTokens: 256,
	} as RuntimeModel;
	const registry = {
		find: () => model,
		hasConfiguredAuth: () => true,
		getApiKeyAndHeaders: async () => ({ ok: true, baseUrl, apiKey: "fixture-token" }),
		complete: async () => {
			throw new Error("Ollama must use native options");
		},
	} as unknown as ModelRegistry;
	const request: CompletionRequest = {
		system: "isolated system",
		user: "bounded evidence",
		signal: AbortSignal.timeout(2000),
		maxTokens: 1,
		temperature: 0,
		seed: 31337,
		numCtx: 4096,
	};
	return { model, registry, request, resolved: resolveReviewerModel(registry, "ollama/reviewer") };
}

describe("Ollama endpoint, manifest and effective context binding", () => {
	it("uses the auth-resolved inference endpoint, native options and no session/tools", async () => {
		const { model, registry, request, resolved } = fixture();
		const identity = await reviewerModelDigest(model, registry);
		await expect(bindReviewerCompletion(resolved, identity).complete(request)).resolves.toBe("1");
		const chat = received.find((entry) => entry.url.endsWith("/api/chat"));
		expect(chat).toMatchObject({
			url: "/proxy/api/chat",
			authorization: "Bearer fixture-token",
			body: {
				model: "reviewer",
				stream: false,
				think: false,
				messages: [
					{ role: "system", content: "isolated system" },
					{ role: "user", content: "bounded evidence" },
				],
				options: { num_ctx: 4096, seed: 31337, temperature: 0, num_predict: 1 },
			},
		});
		expect(chat?.body).not.toHaveProperty("tools");
		expect(chat?.body).not.toHaveProperty("num_ctx");
	});
	it("invalidates qualification on endpoint, manifest/config and runtime descriptor changes", async () => {
		const { model, registry, request, resolved } = fixture();
		const identity = await reviewerModelDigest(model, registry);
		const completion = bindReviewerCompletion(resolved, identity);
		manifest = "b".repeat(64);
		await expect(completion.complete(request)).rejects.toThrow("identity changed");
		manifest = "a".repeat(64);
		baseUrl = baseUrl.replace("/proxy/", "/other/");
		await expect(completion.complete(request)).rejects.toThrow("identity changed");
		expect(received.some((entry) => entry.url.endsWith("/api/chat"))).toBe(false);
	});
	it("rejects a server that ignores num_ctx even with unchanged model weights", async () => {
		const { resolved, request } = fixture();
		context = 2048;
		await expect(resolved.completion.complete(request)).rejects.toThrow("effective context changed");
	});
	it("rejects a model alias changed during inference", async () => {
		const { resolved, request } = fixture();
		mutateDuringChat = true;
		await expect(resolved.completion.complete(request)).rejects.toThrow("identity or effective context");
	});
	it("refuses redirects instead of checking identity at another service", async () => {
		const { model, registry } = fixture();
		redirect = true;
		await expect(reviewerModelDigest(model, registry)).rejects.toThrow();
		expect(received).toHaveLength(1);
	});
});

it("checks the exact inference snapshot even when auth alternates between endpoints", async () => {
	const { model, registry, request } = fixture();
	const qualifiedUrl = baseUrl;
	let calls = 0;
	registry.getApiKeyAndHeaders = async () => ({
		ok: true,
		apiKey: "fixture-token",
		baseUrl: ++calls === 3 ? qualifiedUrl.replace("/proxy/", "/other/") : qualifiedUrl,
	});
	const identity = await reviewerModelDigest(model, registry);
	const resolved = resolveReviewerModel(registry, "ollama/reviewer");
	await expect(bindReviewerCompletion(resolved, identity).complete(request)).rejects.toThrow("identity changed");
	// Before the repair the third resolution selected /other for inference,
	// with the fourth returning /proxy so independent before/after checks passed.
	expect(received.filter((entry) => entry.url.endsWith("/api/chat")).map((entry) => entry.url)).toEqual([
		"/proxy/api/chat",
	]);
});
