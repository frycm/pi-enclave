import { createHash } from "node:crypto";
import { stream as streamOpenAI } from "@earendil-works/pi-ai/api/openai-completions";
import type { ModelRegistry } from "@earendil-works/pi-coding-agent";
import { parseReviewerModelReference } from "../config/reviewer-model.ts";
import { stableSerialize } from "../policy/canonical.ts";
import { type CompletionRequest, REVIEWER_NUM_CTX, type ReviewerCompletion } from "./reviewer.ts";

export type RuntimeModel = NonNullable<ReturnType<ModelRegistry["find"]>>;
export interface ResolvedReviewerModel {
	model: RuntimeModel;
	completion: ReviewerCompletion;
	completeBound(request: CompletionRequest, expected: string): Promise<string>;
}

type Endpoint = { model: RuntimeModel; headers: Record<string, string>; authIdentity: unknown };

async function endpoint(model: RuntimeModel, registry?: ModelRegistry): Promise<Endpoint> {
	const auth = registry ? await registry.getApiKeyAndHeaders(model) : { ok: true as const };
	if (!auth.ok) throw new Error(`pi-enclave: reviewer authentication unavailable: ${auth.error}`);
	const effective = structuredClone({ ...model, baseUrl: auth.baseUrl ?? model.baseUrl });
	const url = new URL(effective.baseUrl);
	if (!["http:", "https:"].includes(url.protocol) || url.username || url.password || url.search || url.hash) {
		throw new Error("pi-enclave: reviewer endpoint must be an HTTP(S) URL without credentials, query or fragment");
	}
	url.hostname = url.hostname.replace(/\.$/, "");
	effective.baseUrl = url.href.replace(/\/$/, "");
	const headers: Record<string, string> = {};
	for (const [key, value] of Object.entries({ ...model.headers, ...auth.headers })) {
		if (typeof value === "string") headers[key] = value;
	}
	if (auth.apiKey && !Object.keys(headers).some((key) => key.toLowerCase() === "authorization")) {
		headers.Authorization = `Bearer ${auth.apiKey}`;
	}
	return { model: effective, headers, authIdentity: structuredClone(auth) };
}

function isLoopback(baseUrl: string): boolean {
	const host = new URL(baseUrl).hostname
		.replace(/\.$/, "")
		.replace(/^\[|\]$/g, "")
		.toLowerCase();
	return (
		host === "0.0.0.0" ||
		host === "::" ||
		host === "localhost" ||
		host.endsWith(".localhost") ||
		/^127\./.test(host) ||
		host === "::1" ||
		/^::ffff:7f[0-9a-f]{2}:[0-9a-f]{1,4}$/.test(host)
	);
}

function digest(value: unknown): string {
	// Pi materializes optional metadata as undefined; JSON transport omits it.
	return createHash("sha256")
		.update(stableSerialize(JSON.parse(JSON.stringify(value))))
		.digest("hex");
}

function nativeUrl(baseUrl: string, method: string): string {
	const url = new URL(baseUrl);
	// Preserve a trusted reverse proxy's prefix, e.g. /ollama/v1 -> /ollama/api/….
	url.pathname = `${url.pathname.replace(/\/?v1\/?$/, "").replace(/\/$/, "")}/api/${method}`;
	return url.href;
}

async function ollamaJson(
	target: Endpoint,
	method: string,
	signal: AbortSignal,
	body?: unknown,
): Promise<Record<string, unknown>> {
	const response = await fetch(nativeUrl(target.model.baseUrl, method), {
		method: body === undefined ? "GET" : "POST",
		headers: { ...target.headers, "Content-Type": "application/json" },
		redirect: "error",
		signal,
		...(body === undefined ? {} : { body: JSON.stringify(body) }),
	});
	if (!response.ok) throw new Error(`pi-enclave: Ollama ${method} failed (${response.status})`);
	const value: unknown = await response.json();
	if (!value || typeof value !== "object" || Array.isArray(value))
		throw new Error(`pi-enclave: invalid Ollama ${method} response`);
	return value as Record<string, unknown>;
}

function modelEntry(value: Record<string, unknown>, id: string): Record<string, unknown> | undefined {
	const normalize = (name: unknown) =>
		typeof name === "string" && !name.slice(name.lastIndexOf("/") + 1).includes(":") ? `${name}:latest` : name;
	return Array.isArray(value.models)
		? value.models.find(
				(entry) =>
					entry &&
					typeof entry === "object" &&
					(normalize(entry.name) === normalize(id) || normalize(entry.model) === normalize(id)),
			)
		: undefined;
}

async function manifest(target: Endpoint, signal: AbortSignal): Promise<string> {
	const entry = modelEntry(await ollamaJson(target, "tags", signal), target.model.id);
	const value = typeof entry?.digest === "string" ? entry.digest.replace(/^sha256:/, "") : "";
	if (!/^[0-9a-f]{64}$/.test(value))
		throw new Error("pi-enclave: Ollama did not report an exact model manifest digest");
	return value;
}

/** Identity includes inference routing and model configuration, never the CLI's server. */
async function endpointDigest(target: Endpoint, signal: AbortSignal): Promise<string> {
	const model = target.model;
	const descriptor = { model: target.model, headers: target.headers, auth: target.authIdentity, transport: 2 };
	if (model.provider === "ollama") {
		const modelManifest = await manifest(target, signal);
		const version = await ollamaJson(target, "version", signal);
		if (typeof version.version !== "string") throw new Error("pi-enclave: Ollama did not report its runtime version");
		return `ollama:sha256:${digest({ ...descriptor, modelManifest, version: version.version, numCtx: REVIEWER_NUM_CTX })}`;
	}
	if (isLoopback(target.model.baseUrl))
		throw new Error("pi-enclave: local reviewer does not expose an exact weights digest; use Ollama");
	if (model.api !== "openai-completions")
		throw new Error("pi-enclave: reviewer adapter cannot enforce the required seed; use openai-completions or Ollama");
	return `cloud:sha256:${digest(descriptor)}`;
}

export async function reviewerModelDigest(model: RuntimeModel, registry?: ModelRegistry): Promise<string> {
	return endpointDigest(await endpoint(model, registry), AbortSignal.timeout(10_000));
}

async function completeOllama(target: Endpoint, request: CompletionRequest): Promise<string> {
	const before = await manifest(target, request.signal);
	const response = await ollamaJson(target, "chat", request.signal, {
		model: target.model.id,
		messages: [
			{ role: "system", content: request.system },
			{ role: "user", content: request.user },
		],
		stream: false,
		think: false,
		options: {
			temperature: request.temperature,
			seed: request.seed,
			num_ctx: request.numCtx,
			num_predict: request.maxTokens,
		},
	});
	const loaded = modelEntry(await ollamaJson(target, "ps", request.signal), target.model.id);
	if (
		loaded?.digest !== before ||
		loaded.context_length !== request.numCtx ||
		(await manifest(target, request.signal)) !== before
	) {
		throw new Error("pi-enclave: Ollama model identity or effective context changed; requalification required");
	}
	const message = response.message as { role?: unknown; content?: unknown; tool_calls?: unknown } | undefined;
	if (
		response.done !== true ||
		message?.role !== "assistant" ||
		typeof message.content !== "string" ||
		message.tool_calls
	) {
		throw new Error("pi-enclave: invalid isolated Ollama completion");
	}
	return message.content;
}

async function completeSnapshot(target: Endpoint, request: CompletionRequest): Promise<string> {
	if (target.model.provider === "ollama") return completeOllama(target, request);
	if (isLoopback(target.model.baseUrl) || target.model.api !== "openai-completions")
		throw new Error("pi-enclave: unsupported reviewer identity or sampling adapter");
	// Invoke the pinned adapter with the exact checked endpoint/auth snapshot.
	// ModelRegistry.complete would resolve auth (including baseUrl) again.
	const response = await streamOpenAI(
		{ ...target.model, api: "openai-completions", samplingParams: {} },
		{
			systemPrompt: request.system,
			messages: [{ role: "user", content: [{ type: "text", text: request.user }], timestamp: Date.now() }],
		},
		{
			headers: target.headers,
			signal: request.signal,
			temperature: request.temperature,
			maxTokens: request.maxTokens,
			maxRetries: 0,
			cacheRetention: "none",
			samplingParams: { seed: request.seed },
			fetch: (url, init) => fetch(url, { ...init, redirect: "error" }),
		},
	).result();
	if (response.stopReason === "error" || response.stopReason === "aborted")
		throw new Error(response.errorMessage ?? `completion stopped with ${response.stopReason}`);
	return response.content
		.filter((part) => part.type === "text")
		.map((part) => part.text)
		.join("");
}

export function resolveReviewerModel(registry: ModelRegistry, reference: string): ResolvedReviewerModel {
	const parsed = parseReviewerModelReference(reference);
	if (!parsed) throw new Error(`pi-enclave: invalid reviewer model reference ${JSON.stringify(reference)}`);
	const model = registry.find(parsed.provider, parsed.id);
	if (!model) throw new Error(`pi-enclave: reviewer model ${reference} is not present in pi's model registry`);
	if (!registry.hasConfiguredAuth(model))
		throw new Error(`pi-enclave: reviewer model ${reference} has no configured provider authentication`);
	const completeBound = async (request: CompletionRequest, expected?: string): Promise<string> => {
		const target = await endpoint(model, registry);
		const actual = await endpointDigest(target, request.signal);
		if (expected !== undefined && actual !== expected)
			throw new Error("pi-enclave: reviewer identity changed; requalification required");
		const result = await completeSnapshot(target, request);
		if (
			(await endpointDigest(target, request.signal)) !== actual ||
			(await reviewerModelDigest(model, registry)) !== actual
		)
			throw new Error("pi-enclave: reviewer identity changed during completion; requalification required");
		return result;
	};
	return {
		model,
		completeBound,
		completion: {
			name: reference,
			numCtx: model.provider === "ollama" ? REVIEWER_NUM_CTX : null,
			complete: (request) => completeBound(request),
		},
	};
}

/** The identity check and the request share one immutable endpoint/auth snapshot. */
export function bindReviewerCompletion(resolved: ResolvedReviewerModel, expected: string): ReviewerCompletion {
	return { ...resolved.completion, complete: (request) => resolved.completeBound(request, expected) };
}
