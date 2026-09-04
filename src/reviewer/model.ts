import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { promisify } from "node:util";
import type { ModelRegistry } from "@earendil-works/pi-coding-agent";
import { parseReviewerModelReference } from "../config/reviewer-model.ts";
import type { CompletionRequest, ReviewerCompletion } from "./reviewer.ts";

const execFileAsync = promisify(execFile);

export type RuntimeModel = NonNullable<ReturnType<ModelRegistry["find"]>>;

export interface ResolvedReviewerModel {
	model: RuntimeModel;
	completion: ReviewerCompletion;
}

export function resolveReviewerModel(registry: ModelRegistry, reference: string): ResolvedReviewerModel {
	const parsed = parseReviewerModelReference(reference);
	if (!parsed) throw new Error(`pi-enclave: invalid reviewer model reference ${JSON.stringify(reference)}`);
	const model = registry.find(parsed.provider, parsed.id);
	if (!model) throw new Error(`pi-enclave: reviewer model ${reference} is not present in pi's model registry`);
	if (!registry.hasConfiguredAuth(model)) {
		throw new Error(`pi-enclave: reviewer model ${reference} has no configured provider authentication`);
	}
	return {
		model,
		completion: {
			name: reference,
			complete: (request) => completeIsolated(registry, model, request),
		},
	};
}

async function completeIsolated(
	registry: ModelRegistry,
	model: RuntimeModel,
	request: CompletionRequest,
): Promise<string> {
	const response = await registry.complete(
		model,
		{
			systemPrompt: request.system,
			messages: [
				{
					role: "user",
					content: [{ type: "text", text: request.user }],
					timestamp: Date.now(),
				},
			],
			// Deliberately no tools and no session messages.
		},
		{
			signal: request.signal,
			temperature: request.temperature,
			maxTokens: request.maxTokens,
			maxRetries: 0,
			cacheRetention: "none",
			samplingParams: { seed: request.seed, num_ctx: request.numCtx },
		},
	);
	if (response.stopReason === "error" || response.stopReason === "aborted") {
		throw new Error(response.errorMessage ?? `completion stopped with ${response.stopReason}`);
	}
	return response.content
		.filter((part): part is Extract<(typeof response.content)[number], { type: "text" }> => part.type === "text")
		.map((part) => part.text)
		.join("");
}

function descriptorDigest(model: RuntimeModel): string {
	const descriptor = JSON.stringify({
		provider: model.provider,
		id: model.id,
		api: model.api,
		baseUrl: model.baseUrl,
	});
	return `cloud:sha256:${createHash("sha256").update(descriptor).digest("hex")}`;
}

function isLoopback(baseUrl: string): boolean {
	try {
		const host = new URL(baseUrl).hostname;
		return host === "localhost" || host === "127.0.0.1" || host === "::1";
	} catch {
		return false;
	}
}

async function ollamaDigest(model: RuntimeModel): Promise<string> {
	let stdout: string;
	try {
		({ stdout } = await execFileAsync("ollama", ["show", model.id, "--modelfile"], {
			encoding: "utf8",
			timeout: 10_000,
			maxBuffer: 1024 * 1024,
		}));
	} catch (error) {
		throw new Error(`pi-enclave: cannot obtain the exact Ollama digest for ${model.id}: ${(error as Error).message}`);
	}
	const digest = /\bsha256[:-]([0-9a-f]{64})\b/i.exec(stdout)?.[1];
	if (!digest) {
		throw new Error(`pi-enclave: Ollama did not report an exact weights digest for ${model.id}`);
	}
	return `ollama:sha256:${digest.toLowerCase()}`;
}

/** Resolve the identity that qualification binds to; ambiguous local identities are refused. */
export async function reviewerModelDigest(model: RuntimeModel): Promise<string> {
	if (model.provider === "ollama") return ollamaDigest(model);
	if (isLoopback(model.baseUrl)) {
		throw new Error(
			`pi-enclave: local reviewer ${model.provider}/${model.id} does not expose an exact weights digest; use an Ollama digest-backed model or a versioned cloud model`,
		);
	}
	return descriptorDigest(model);
}
