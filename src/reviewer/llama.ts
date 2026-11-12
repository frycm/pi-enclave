/**
 * The classifier reviewer transport on a llama.cpp router (#26).
 *
 * Identity: the Ollama-only rule existed because a reviewer qualification must
 * bind exact weights. llama.cpp gives no manifest digest, so the trusted pi
 * process hashes the GGUF file the router reports it loaded, and binds the
 * server build, the slot context, the chat template and the load arguments
 * beside it. A model the pi user cannot read is refused, never trusted by name.
 *
 * Requests: pi-ai's classifier API module is called directly with the pinned
 * endpoint/auth snapshot, for the same reason the chat path avoids
 * ModelRegistry.complete: the registry would resolve auth (and baseUrl) again.
 */
import { createHash } from "node:crypto";
import type { BigIntStats } from "node:fs";
import { createReadStream } from "node:fs";
import { realpath, stat } from "node:fs/promises";
import { basename, dirname, isAbsolute, join } from "node:path";
import type { ClassifierAnswer, ClassifierApi, ClassifierModel, ClassifierResult } from "@earendil-works/pi-ai";
import { classify as llamaCppClassify } from "@earendil-works/pi-ai/api/llama-cpp-classify";
import { classify as systemOneClassify } from "@earendil-works/pi-ai/api/typesafe-system-one";
import { type ModelRegistry, VERSION } from "@earendil-works/pi-coding-agent";
import { parseReviewerModelReference } from "../config/reviewer-model.ts";
import { digest, type Endpoint, endpoint, isLoopback } from "./model.ts";
import type { ClassifyRequest, ReviewerClassifier } from "./reviewer.ts";
import type { ClassifierThresholds } from "./types.ts";

export type ClassifierRuntimeModel = ClassifierModel<ClassifierApi>;

export const LLAMA_PROVIDER = "llama.cpp";
/** Chat GGUFs read through next-token label probabilities, and native decision models. */
export const LLAMA_CLASSIFIER_APIS = ["llama-cpp-classify", "typesafe-system-one"] as const;

/** Values the router changes on every spawn of the same model; everything else is bound. */
const VOLATILE_ARGS = new Set(["--port", "--log-colors"]);

export interface ResolvedReviewerClassifier {
	model: ClassifierRuntimeModel;
	classifyBound(request: ClassifyRequest, expected: string): Promise<Record<string, ClassifierAnswer>>;
}

function fail(message: string): never {
	throw new Error(`pi-enclave: ${message}`);
}

/**
 * The pi version a classifier qualification binds: pi-ai's classifier module
 * owns the system prompt, the layout of state and question, and the label
 * readout. Without a version nothing would notice a change, so none is refused.
 */
export function classifierRuntimeVersion(version: unknown = VERSION): string {
	if (typeof version !== "string" || version === "") {
		fail("pi did not report its version; a classifier reviewer qualification must bind it");
	}
	return version;
}

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** pi's llama.cpp classifier entries carry either the server root or its OpenAI `/v1` URL. */
function serverRoot(baseUrl: string): string {
	return baseUrl.replace(/\/+$/u, "").replace(/\/v1$/u, "");
}

async function routerJson(
	target: Endpoint<ClassifierRuntimeModel>,
	path: string,
	signal: AbortSignal,
): Promise<Record<string, unknown>> {
	const response = await fetch(`${serverRoot(target.model.baseUrl)}${path}`, {
		headers: target.headers,
		redirect: "error",
		signal,
	});
	if (!response.ok) fail(`llama.cpp ${path.split("?")[0]} failed (${response.status})`);
	const value: unknown = await response.json();
	if (!isRecord(value)) fail(`invalid llama.cpp ${path.split("?")[0]} response`);
	return value;
}

/**
 * Load arguments that add weights beside the GGUF (llama.cpp `common/arg.cpp`).
 * Only the GGUF is hashed, so these would be bound by their path alone, and a
 * new adapter at the same path would keep the old qualification. LoRA scales
 * can also change at runtime (`POST /lora-adapters`) with no argument change.
 * A reviewer is served without them. Projectors and draft models do not change
 * a text prompt's next-token probabilities, but they are weights all the same.
 */
const WEIGHT_ARGS = new Set([
	"--lora",
	"--lora-scaled",
	"--control-vector",
	"--control-vector-scaled",
	"-mm",
	"--mmproj",
	"-mmu",
	"--mmproj-url",
	"-md",
	"--model-draft",
	"--spec-draft-model",
	"-hfd",
	"-hfrd",
	"--hf-repo-draft",
	"--spec-draft-hf",
]);

function flagName(arg: string): string {
	return arg.split("=")[0] ?? arg;
}

function loadArgs(id: string, args: unknown): string[] {
	if (!Array.isArray(args) || !args.every((arg) => typeof arg === "string")) {
		fail(`the llama.cpp router did not report the load arguments of ${id}`);
	}
	const extra = args.find((arg) => WEIGHT_ARGS.has(flagName(arg)));
	if (extra) {
		fail(
			`llama.cpp model ${id} is loaded with ${flagName(extra)}, whose weights pi-enclave does not hash; ` +
				"serve the reviewer model without adapters, control vectors, projectors (--no-mmproj) or draft models",
		);
	}
	return args;
}

function stableArgs(args: readonly string[]): string[] {
	const out: string[] = [];
	for (let index = 0; index < args.length; index++) {
		const arg = args[index] as string;
		if (VOLATILE_ARGS.has(flagName(arg))) {
			// A flag's value is the next token unless that token is the next flag.
			if (!arg.includes("=") && !(args[index + 1] ?? "-").startsWith("-")) index++;
			continue;
		}
		out.push(arg);
	}
	return out;
}

// --- GGUF digest -------------------------------------------------------------

interface FileDigest {
	name: string;
	size: number;
	sha256: string;
}

/**
 * Digests by file identity. A changed file gets a new key (ctime cannot be set
 * back by its owner), so a replaced or rewritten model is hashed again.
 */
const FILE_DIGESTS = new Map<string, Promise<string>>();

async function sha256File(path: string): Promise<string> {
	const hash = createHash("sha256");
	for await (const chunk of createReadStream(path)) hash.update(chunk as Buffer);
	return hash.digest("hex");
}

async function fileDigest(reported: string): Promise<FileDigest> {
	let real: string;
	let info: BigIntStats;
	try {
		real = await realpath(reported);
		info = await stat(real, { bigint: true });
	} catch (error) {
		const code = (error as NodeJS.ErrnoException).code;
		fail(
			code === "EACCES"
				? `the llama.cpp model file ${reported} is not readable by the pi user; grant read access so its weights can be hashed`
				: `cannot stat the llama.cpp model file ${reported} (${code ?? (error as Error).message}); the router and pi must run on the same host`,
		);
	}
	if (!info.isFile()) fail(`the llama.cpp model path ${reported} is not a regular file`);
	const key = [real, info.dev, info.ino, info.size, info.mtimeNs, info.ctimeNs].join("\0");
	let pending = FILE_DIGESTS.get(key);
	if (!pending) {
		pending = sha256File(real);
		FILE_DIGESTS.set(key, pending);
		pending.catch(() => FILE_DIGESTS.delete(key));
	}
	try {
		return { name: basename(reported), size: Number(info.size), sha256: await pending };
	} catch (error) {
		const code = (error as NodeJS.ErrnoException).code;
		fail(
			code === "EACCES"
				? `the llama.cpp model file ${reported} is not readable by the pi user; grant read access so its weights can be hashed`
				: `cannot hash the llama.cpp model file ${reported}: ${(error as Error).message}`,
		);
	}
}

/** Every shard of a split GGUF, in order; a single file otherwise. */
export async function ggufDigest(modelPath: string): Promise<FileDigest[]> {
	if (!isAbsolute(modelPath))
		fail(`llama.cpp reported a model path that is not absolute: ${JSON.stringify(modelPath)}`);
	const shard = /^(.*)-(\d{5})-of-(\d{5})\.gguf$/u.exec(basename(modelPath));
	if (!shard) return [await fileDigest(modelPath)];
	const total = Number(shard[3]);
	if (!(total >= 1 && total <= 9999)) fail(`llama.cpp reported an invalid split model ${modelPath}`);
	const files: FileDigest[] = [];
	for (let index = 1; index <= total; index++) {
		const name = `${shard[1]}-${String(index).padStart(5, "0")}-of-${shard[3]}.gguf`;
		files.push(await fileDigest(join(dirname(modelPath), name)));
	}
	return files;
}

// --- identity ----------------------------------------------------------------

function requireLlamaClassifier(model: ClassifierRuntimeModel): void {
	if (model.provider !== LLAMA_PROVIDER) {
		fail(
			`the classifier reviewer transport supports ${LLAMA_PROVIDER} models only; ${model.provider} is not supported`,
		);
	}
	if (!(LLAMA_CLASSIFIER_APIS as readonly string[]).includes(model.api)) {
		fail(`unsupported llama.cpp classifier API ${JSON.stringify(model.api)}`);
	}
}

/** The router's own report of what serves this model, plus a hash of the weights it loaded. */
async function classifierIdentity(
	target: Endpoint<ClassifierRuntimeModel>,
	signal: AbortSignal,
): Promise<{ digest: string; nCtx: number }> {
	const model = target.model;
	requireLlamaClassifier(model);
	if (!isLoopback(model.baseUrl)) {
		fail("a llama.cpp classifier reviewer must be served on loopback, so pi can hash the weights the router loaded");
	}
	const list = await routerJson(target, "/models", signal);
	const entry = Array.isArray(list.data)
		? (list.data as unknown[]).find((item) => isRecord(item) && item.id === model.id)
		: undefined;
	if (!isRecord(entry) || !isRecord(entry.status)) {
		fail(`the llama.cpp router does not list ${model.id}; the router must run in router mode`);
	}
	const status = entry.status.value;
	if (status !== "loaded" && status !== "sleeping") {
		fail(`llama.cpp model ${model.id} is ${String(status)}; load it with /llama before reviewing`);
	}
	const args = loadArgs(model.id, entry.status.args);
	// As pi's own client does: a model unloaded since /models is refused, not loaded by the check.
	const props = await routerJson(target, `/props?model=${encodeURIComponent(model.id)}&autoload=false`, signal);
	const settings = isRecord(props.default_generation_settings) ? props.default_generation_settings : {};
	const nCtx = settings.n_ctx;
	if (typeof props.model_path !== "string" || props.model_path === "none" || props.model_path === "") {
		fail(`llama.cpp did not report the model file of ${model.id}`);
	}
	if (typeof props.build_info !== "string" || props.build_info === "") fail("llama.cpp did not report its build");
	if (typeof nCtx !== "number" || !Number.isSafeInteger(nCtx) || nCtx <= 0) {
		fail(`llama.cpp did not report the context size of ${model.id}`);
	}
	const gguf = await ggufDigest(props.model_path);
	const identity = `llama.cpp:sha256:${digest({
		transport: "classifier",
		// Catalog fields such as contextWindow come from pi's cached refreshes and
		// vary without the server changing; the server's own report is bound below.
		model: { provider: model.provider, id: model.id, api: model.api, baseUrl: model.baseUrl },
		headers: target.headers,
		auth: target.authIdentity,
		gguf,
		build: props.build_info,
		nCtx,
		slots: typeof props.total_slots === "number" ? props.total_slots : null,
		chatTemplate: createHash("sha256")
			.update(typeof props.chat_template === "string" ? props.chat_template : "")
			.digest("hex"),
		args: stableArgs(args),
		architecture: isRecord(entry.architecture) ? entry.architecture : null,
	})}`;
	return { digest: identity, nCtx };
}

async function classifierDigest(target: Endpoint<ClassifierRuntimeModel>, signal: AbortSignal): Promise<string> {
	return (await classifierIdentity(target, signal)).digest;
}

/** The digest and the slot context it binds; the context sizes the evidence (#17). */
export async function reviewerClassifierIdentity(
	model: ClassifierRuntimeModel,
	registry?: ModelRegistry,
): Promise<{ digest: string; nCtx: number }> {
	return classifierIdentity(await endpoint(model, registry), AbortSignal.timeout(120_000));
}

export async function reviewerClassifierDigest(
	model: ClassifierRuntimeModel,
	registry?: ModelRegistry,
): Promise<string> {
	return (await reviewerClassifierIdentity(model, registry)).digest;
}

// --- requests ----------------------------------------------------------------

/** No tokenizer averages this many bytes a token; a count below it means part of the prompt was not read. */
const MAX_BYTES_PER_TOKEN = 16;

/**
 * llama-server's own report on a `/completion` prompt (#17). The evidence is
 * sized so the prompt fits the slot, and llama-server refuses one that does
 * not (400 exceed_context_size_error). A build or setting that truncates
 * instead answers 200 with `truncated: true`, which pi-ai does not read; the
 * label probabilities would then come from a cut prompt. That, a missing
 * report, or a token count that cannot cover the prompt is an error, never a
 * verdict.
 */
export function checkCompletionReport(body: unknown, prompt: unknown, nCtx: number): void {
	if (!isRecord(body)) fail("llama.cpp returned no completion report");
	if (body.truncated !== false) fail("llama.cpp truncated the classifier prompt");
	const evaluated = body.tokens_evaluated;
	if (typeof evaluated !== "number" || !Number.isSafeInteger(evaluated) || evaluated <= 0) {
		fail("llama.cpp did not report how many prompt tokens it evaluated");
	}
	const bytes = typeof prompt === "string" ? Buffer.byteLength(prompt) : 0;
	if (evaluated >= nCtx || evaluated * MAX_BYTES_PER_TOKEN < bytes) {
		fail(`llama.cpp evaluated ${evaluated} prompt tokens for a ${bytes}-byte prompt in a ${nCtx}-token slot`);
	}
}

/** Pinned to the snapshot: no redirects, and every label read checked against the bound slot context. */
function checkedFetch(nCtx: number): typeof fetch {
	return async (input, init) => {
		const response = await fetch(input, { ...init, redirect: "error" });
		const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
		if (!response.ok || !new URL(url).pathname.endsWith("/completion")) return response;
		const sent = typeof init?.body === "string" ? (JSON.parse(init.body) as { prompt?: unknown }) : {};
		const body: unknown = await response
			.clone()
			.json()
			.catch(() => undefined);
		checkCompletionReport(body, sent.prompt, nCtx);
		return response;
	};
}

async function classifySnapshot(
	target: Endpoint<ClassifierRuntimeModel>,
	request: ClassifyRequest,
	nCtx: number,
): Promise<Record<string, ClassifierAnswer>> {
	const run = target.model.api === "typesafe-system-one" ? systemOneClassify : llamaCppClassify;
	const result: ClassifierResult = await run(
		target.model,
		{ state: request.state, questions: request.questions },
		{
			// System One requires a key; llama.cpp ignores one it was not started with.
			apiKey: target.apiKey ?? "local",
			headers: target.headers,
			signal: request.signal,
			temperature: request.temperature,
			maxRetries: 0,
			fetch: checkedFetch(nCtx),
		},
	);
	if (result.stopReason !== "stop") fail(result.errorMessage ?? `classifier stopped with ${result.stopReason}`);
	return result.answers;
}

export function resolveReviewerClassifier(registry: ModelRegistry, reference: string): ResolvedReviewerClassifier {
	const parsed = parseReviewerModelReference(reference);
	if (!parsed) fail(`invalid reviewer model reference ${JSON.stringify(reference)}`);
	const model = registry.getModelOfType("classifier", parsed.provider, parsed.id);
	if (!model) {
		fail(
			`reviewer model ${reference} is not a classifier model in pi's model registry` +
				(parsed.provider === LLAMA_PROVIDER ? "; load it on the llama.cpp router with /llama" : ""),
		);
	}
	requireLlamaClassifier(model);
	if (!registry.hasConfiguredAuth(model as never)) {
		fail(`reviewer model ${reference} has no configured provider authentication`);
	}
	return {
		model,
		classifyBound: async (request, expected) => {
			const target = await endpoint(model, registry);
			const identity = await classifierIdentity(target, request.signal);
			const actual = identity.digest;
			if (actual !== expected) fail("reviewer identity changed; requalification required");
			const answers = await classifySnapshot(target, request, identity.nCtx);
			if (
				(await classifierDigest(target, request.signal)) !== actual ||
				(await reviewerClassifierDigest(model, registry)) !== actual
			) {
				fail("reviewer identity changed during classification; requalification required");
			}
			return answers;
		},
	};
}

/** Identity and thresholds travel together: a threshold is only meaningful for the model it was chosen on. */
export function bindReviewerClassifier(
	resolved: ResolvedReviewerClassifier,
	identity: { digest: string; nCtx: number },
	thresholds: ClassifierThresholds,
): ReviewerClassifier {
	const expected = identity.digest;
	return {
		kind: "classifier",
		name: `${resolved.model.provider}/${resolved.model.id}`,
		numCtx: identity.nCtx,
		thresholds,
		classify: (request) => resolved.classifyBound(request, expected),
	};
}
