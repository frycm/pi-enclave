import { createHash } from "node:crypto";
import { stream as streamOpenAI } from "@earendil-works/pi-ai/api/openai-completions";
import { normalizeContext } from "@earendil-works/pi-ai/utils/transcript";
import type { ModelRegistry } from "@earendil-works/pi-coding-agent";
import { parseReviewerModelReference } from "../config/reviewer-model.ts";
import { stableSerialize } from "../policy/canonical.ts";
import { chatPromptBound } from "./budget.ts";
import { type CompletionRequest, REVIEWER_NUM_CTX, type ReviewerCompletion } from "./reviewer.ts";
import type { RuntimeReport } from "./telemetry.ts";

export type RuntimeModel = NonNullable<ReturnType<ModelRegistry["find"]>>;
export interface ResolvedReviewerModel {
	model: RuntimeModel;
	completion: ReviewerCompletion;
	completeBound(request: CompletionRequest, expected: string): Promise<string>;
}

/** Any registry entry a reviewer can be: a chat model or a classifier model (#26). */
type EndpointModel = Pick<RuntimeModel, "provider" | "id" | "api" | "baseUrl" | "headers">;

/** One immutable endpoint/auth snapshot, shared by the identity check and the request. */
export type Endpoint<M extends EndpointModel = RuntimeModel> = {
	model: M;
	headers: Record<string, string>;
	authIdentity: unknown;
	apiKey?: string;
};

export async function endpoint<M extends EndpointModel = RuntimeModel>(
	model: M,
	registry?: ModelRegistry,
): Promise<Endpoint<M>> {
	// The registry resolves auth by provider; a classifier entry resolves like a chat entry.
	const auth: Awaited<ReturnType<ModelRegistry["getApiKeyAndHeaders"]>> = registry
		? await registry.getApiKeyAndHeaders(model as unknown as RuntimeModel)
		: { ok: true };
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
	return {
		model: effective,
		headers,
		authIdentity: structuredClone(auth),
		...(auth.apiKey ? { apiKey: auth.apiKey } : {}),
	};
}

export function isLoopback(baseUrl: string): boolean {
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

export function digest(value: unknown): string {
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
	onIdentityCall?: () => void,
): Promise<Record<string, unknown>> {
	if (method !== "chat") onIdentityCall?.();
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

async function manifest(target: Endpoint, signal: AbortSignal, onIdentityCall?: () => void): Promise<string> {
	const entry = modelEntry(await ollamaJson(target, "tags", signal, undefined, onIdentityCall), target.model.id);
	const value = typeof entry?.digest === "string" ? entry.digest.replace(/^sha256:/, "") : "";
	if (!/^[0-9a-f]{64}$/.test(value))
		throw new Error("pi-enclave: Ollama did not report an exact model manifest digest");
	return value;
}

/** What the Ollama server says about the model, fetched once per request (#25). */
interface OllamaIdentity {
	modelManifest: string;
	version: string;
}

async function ollamaIdentity(
	target: Endpoint,
	signal: AbortSignal,
	onIdentityCall?: () => void,
): Promise<OllamaIdentity> {
	const modelManifest = await manifest(target, signal, onIdentityCall);
	const version = await ollamaJson(target, "version", signal, undefined, onIdentityCall);
	if (typeof version.version !== "string") throw new Error("pi-enclave: Ollama did not report its runtime version");
	if (!refusesOverlongPrompts(version.version)) {
		throw new Error(
			`pi-enclave: Ollama ${version.version} silently truncates a prompt longer than num_ctx; the reviewer needs ${OLLAMA_MIN_VERSION.join(".")} or later, which can refuse it instead (#17)`,
		);
	}
	return { modelManifest, version: version.version };
}

/**
 * Identity includes inference routing and model configuration, never the CLI's
 * server. Pure: the Ollama part is passed in, so a check after the request can
 * recompute it from a fresh endpoint snapshot without asking the server again.
 */
function identityDigest(target: Endpoint, numCtx: number, ollama?: OllamaIdentity): string {
	const model = target.model;
	const descriptor = { model: target.model, headers: target.headers, auth: target.authIdentity, transport: 4 };
	if (model.provider === "ollama") {
		if (!ollama) throw new Error("pi-enclave: internal error: Ollama identity missing");
		return `ollama:sha256:${digest({ ...descriptor, modelManifest: ollama.modelManifest, version: ollama.version, numCtx })}`;
	}
	if (isLoopback(target.model.baseUrl))
		throw new Error(
			model.provider === "llama.cpp"
				? 'pi-enclave: a llama.cpp reviewer is identified by its GGUF digest only on the classifier transport; set reviewer.transport to "classifier" or use Ollama'
				: "pi-enclave: local reviewer does not expose an exact weights digest; use Ollama, or llama.cpp with reviewer.transport classifier",
		);
	if (model.api !== "openai-completions")
		throw new Error("pi-enclave: reviewer adapter cannot enforce the required seed; use openai-completions or Ollama");
	return `cloud:sha256:${digest(descriptor)}`;
}

async function endpointDigest(
	target: Endpoint,
	signal: AbortSignal,
	numCtx: number,
	onIdentityCall?: () => void,
): Promise<{ digest: string; ollama?: OllamaIdentity }> {
	const ollama = target.model.provider === "ollama" ? await ollamaIdentity(target, signal, onIdentityCall) : undefined;
	return { digest: identityDigest(target, numCtx, ollama), ...(ollama ? { ollama } : {}) };
}

export async function reviewerModelDigest(
	model: RuntimeModel,
	registry?: ModelRegistry,
	numCtx: number = REVIEWER_NUM_CTX,
): Promise<string> {
	return (await endpointDigest(await endpoint(model, registry), AbortSignal.timeout(10_000), numCtx)).digest;
}

/** The first Ollama release whose /api/chat takes `truncate` and `shift` (ollama/ollama#12582). */
export const OLLAMA_MIN_VERSION = [0, 12, 6] as const;

/** Release versions only; a development build ("0.0.0") or anything unparsable is refused. */
export function refusesOverlongPrompts(version: string): boolean {
	const match = /^v?(\d+)\.(\d+)\.(\d+)(?:[-+].*)?$/.exec(version.trim());
	if (!match) return false;
	const parts = match.slice(1, 4).map(Number);
	for (let index = 0; index < 3; index++) {
		const part = parts[index] ?? 0;
		const minimum = OLLAMA_MIN_VERSION[index] ?? 0;
		if (part !== minimum) return part > minimum;
	}
	return true;
}

/**
 * When Ollama reports cached prompt tokens, its count is the whole prompt, and a
 * count far below the request's size means part of it was never read. No
 * tokenizer in use averages this many bytes a token on JSON evidence; a long
 * run of one repeated character can, and then the review fails closed.
 */
const MAX_BYTES_PER_TOKEN = 16;

/**
 * Ollama's own count of the prompt it evaluated, against the request (#17).
 * Above the worst-case bound, the budget's assumptions about the chat template
 * are wrong; far below the request, the runtime did not read all of it. Both
 * are an unavailable reviewer, never a verdict.
 */
function checkPromptCount(response: Record<string, unknown>, request: CompletionRequest): void {
	const evaluated = response.prompt_eval_count;
	const cached = response.prompt_eval_cached_count;
	if (typeof evaluated !== "number" || !Number.isFinite(evaluated) || evaluated < 0) {
		throw new Error("pi-enclave: Ollama did not report how many prompt tokens it evaluated");
	}
	const total = evaluated + (typeof cached === "number" && Number.isFinite(cached) ? cached : 0);
	const bound = chatPromptBound(request.system, request.user);
	if (total > bound || total > request.numCtx - request.maxTokens) {
		throw new Error(
			`pi-enclave: Ollama evaluated ${total} prompt tokens, above the ${Math.min(bound, request.numCtx - request.maxTokens)}-token budget; the chat template adds more than the reserve`,
		);
	}
	// Without a cached count, a prompt-cache hit lowers the count legitimately.
	const requested = Buffer.byteLength(request.system) + Buffer.byteLength(request.user);
	if (typeof cached === "number" && total * MAX_BYTES_PER_TOKEN < requested) {
		throw new Error(
			`pi-enclave: Ollama evaluated ${total} prompt tokens for a ${requested}-byte prompt; part of the prompt was not read`,
		);
	}
}

/**
 * One chat request, checked by two identity calls after it (#25): the loaded
 * model and its context (`ps`), and the manifest again (`tags`). The caller
 * made the two before it (`tags`, `version`), so a review costs four.
 */
async function completeOllama(target: Endpoint, request: CompletionRequest, before: OllamaIdentity): Promise<string> {
	const response = await ollamaJson(target, "chat", request.signal, {
		model: target.model.id,
		messages: [
			{ role: "system", content: request.system },
			{ role: "user", content: request.user },
		],
		stream: false,
		think: false,
		// Fail instead of dropping part of the prompt or the context (#17).
		truncate: false,
		shift: false,
		// A grammar from the schema: the answer can only be the verdict object (#25).
		...(request.schema ? { format: request.schema } : {}),
		options: {
			temperature: request.temperature,
			seed: request.seed,
			num_ctx: request.numCtx,
			num_predict: request.maxTokens,
		},
	});
	const loaded = modelEntry(
		await ollamaJson(target, "ps", request.signal, undefined, request.onIdentityCall),
		target.model.id,
	);
	if (
		loaded?.digest !== before.modelManifest ||
		loaded.context_length !== request.numCtx ||
		(await manifest(target, request.signal, request.onIdentityCall)) !== before.modelManifest
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
	checkPromptCount(response, request);
	request.onRuntime?.(runtimeReport(response));
	request.onFirstOutput?.();
	return message.content;
}

function count(value: unknown): number | undefined {
	return typeof value === "number" && Number.isFinite(value) && value >= 0 ? value : undefined;
}

/** Ollama's counts and its load time (reported in nanoseconds), for telemetry only. */
function runtimeReport(response: Record<string, unknown>): RuntimeReport {
	const promptTokens = count(response.prompt_eval_count);
	const cachedPromptTokens = count(response.prompt_eval_cached_count);
	const load = count(response.load_duration);
	return {
		...(promptTokens !== undefined ? { promptTokens } : {}),
		...(cachedPromptTokens !== undefined ? { cachedPromptTokens } : {}),
		...(load !== undefined ? { loadMs: load / 1e6 } : {}),
	};
}

/**
 * Loads the reviewer model with the configured context: Ollama loads a model
 * for a chat request with no messages and generates nothing (#25).
 */
async function warmOllama(target: Endpoint, numCtx: number, signal: AbortSignal): Promise<void> {
	await ollamaJson(target, "chat", signal, {
		model: target.model.id,
		messages: [],
		stream: false,
		options: { num_ctx: numCtx },
	});
}

async function completeSnapshot(
	target: Endpoint,
	request: CompletionRequest,
	ollama: OllamaIdentity | undefined,
): Promise<string> {
	if (target.model.provider === "ollama") {
		if (!ollama) throw new Error("pi-enclave: internal error: Ollama identity missing");
		return completeOllama(target, request, ollama);
	}
	if (isLoopback(target.model.baseUrl) || target.model.api !== "openai-completions")
		throw new Error("pi-enclave: unsupported reviewer identity or sampling adapter");
	// Invoke the pinned adapter with the exact checked endpoint/auth snapshot.
	// ModelRegistry.complete would resolve auth (including baseUrl) again.
	const stream = streamOpenAI(
		{ ...target.model, api: "openai-completions", samplingParams: {} },
		normalizeContext({
			messages: [
				{ role: "system", content: [{ type: "text", text: request.system }], timestamp: Date.now() },
				{ role: "user", content: [{ type: "text", text: request.user }], timestamp: Date.now() },
			],
		}),
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
	);
	let observed = false;
	for await (const event of stream) {
		if (!observed && event.type === "text_delta" && event.delta.length > 0) {
			observed = true;
			request.onFirstOutput?.();
		}
	}
	const response = await stream.result();
	if (response.stopReason === "error" || response.stopReason === "aborted")
		throw new Error(response.errorMessage ?? `completion stopped with ${response.stopReason}`);
	return response.content
		.filter((part) => part.type === "text")
		.map((part) => part.text)
		.join("");
}

export function resolveReviewerModel(
	registry: ModelRegistry,
	reference: string,
	numCtx: number = REVIEWER_NUM_CTX,
): ResolvedReviewerModel {
	const parsed = parseReviewerModelReference(reference);
	if (!parsed) throw new Error(`pi-enclave: invalid reviewer model reference ${JSON.stringify(reference)}`);
	const model = registry.find(parsed.provider, parsed.id);
	if (!model) throw new Error(`pi-enclave: reviewer model ${reference} is not present in pi's model registry`);
	if (!registry.hasConfiguredAuth(model))
		throw new Error(`pi-enclave: reviewer model ${reference} has no configured provider authentication`);
	const completeBound = async (request: CompletionRequest, expected?: string): Promise<string> => {
		const target = await endpoint(model, registry);
		const before = await endpointDigest(target, request.signal, numCtx, request.onIdentityCall);
		if (expected !== undefined && before.digest !== expected)
			throw new Error("pi-enclave: reviewer identity changed; requalification required");
		// The Ollama path re-reads the loaded model and the manifest after the request.
		const result = await completeSnapshot(target, request, before.ollama);
		// The configuration and auth as they are now, against the same server
		// answers: one review asks the server four times, not eighteen (#25).
		if (identityDigest(await endpoint(model, registry), numCtx, before.ollama) !== before.digest)
			throw new Error("pi-enclave: reviewer identity changed during completion; requalification required");
		return result;
	};
	const warm = async (signal: AbortSignal): Promise<void> => {
		if (model.provider !== "ollama") return;
		await warmOllama(await endpoint(model, registry), numCtx, signal);
	};
	return {
		model,
		completeBound,
		completion: {
			name: reference,
			numCtx: model.provider === "ollama" ? numCtx : null,
			complete: (request) => completeBound(request),
			...(model.provider === "ollama" ? { warm } : {}),
		},
	};
}

/** The identity check and the request share one immutable endpoint/auth snapshot. */
export function bindReviewerCompletion(resolved: ResolvedReviewerModel, expected: string): ReviewerCompletion {
	return { ...resolved.completion, complete: (request) => resolved.completeBound(request, expected) };
}
