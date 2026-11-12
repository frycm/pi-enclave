/**
 * The reviewer's prompt budget in tokens (#17).
 *
 * The evidence used to be bounded in bytes (32 KiB) and the context in tokens
 * (4,096), with nothing relating the two. The relation used here is a
 * worst-case bound for byte-level BPE and SentencePiece vocabularies, the
 * ones chat GGUFs ship: a token covers at least one byte of UTF-8 (a byte,
 * a byte-fallback token, or one <unk> per character). So a prompt of B bytes
 * is at most B tokens, plus what the chat template adds around it, which is
 * the fixed reserve below. A tokenizer that normalizes first (NFKC expands
 * U+FDFA to eighteen characters) can exceed it; the runtimes' overflow checks
 * then refuse the prompt instead of cutting it. Evidence is sized so that
 *
 *   system bytes + evidence bytes + template reserve + output tokens <= context
 *
 * for every stage. It is pessimistic (real text runs 3 to 4 bytes a token),
 * which is the price of a bound that does not depend on a tokenizer.
 */
import type { ClassifierQuestion, JsonObject } from "@earendil-works/pi-ai";
import { renderQuestion } from "@earendil-works/pi-ai/api/llama-cpp-classify";
import { REVIEWER_MAX_TOKENS } from "./reviewer.ts";
import type { ReviewerPrompt } from "./types.ts";

/** Role headers, BOS and the generation prompt of a chat template, in tokens. */
export const TEMPLATE_RESERVE_TOKENS = 512;
/**
 * pi's llama.cpp classifier system prompt (`llama-cpp-classify`), with room to
 * spare. A test pins it against the prompt the pinned pi-ai version sends.
 */
export const CLASSIFIER_SYSTEM_BYTES = 512;
/** Below this much room for evidence, a reviewer could judge little more than the hash. */
export const MIN_EVIDENCE_BYTES = 2_048;

export class ReviewerBudgetError extends Error {
	constructor(message: string) {
		super(`pi-enclave: ${message}`);
		this.name = "ReviewerBudgetError";
	}
}

export type EvidenceFits = (rendered: string) => boolean;

function bytes(text: string): number {
	return Buffer.byteLength(text);
}

/** Bytes of evidence the chat transport can send at `numCtx` without the bound failing. */
export function chatEvidenceBytes(prompt: ReviewerPrompt, numCtx: number): number {
	const authorization = numCtx - TEMPLATE_RESERVE_TOKENS - 1 - bytes(prompt.authorizationSystem);
	const decision =
		numCtx -
		TEMPLATE_RESERVE_TOKENS -
		REVIEWER_MAX_TOKENS -
		Math.max(bytes(prompt.decisionSystem["0"]), bytes(prompt.decisionSystem["1"]));
	return Math.min(authorization, decision);
}

/** The worst-case token count of one chat stage, as the Ollama post-check compares it. */
export function chatPromptBound(system: string, user: string): number {
	return bytes(system) + bytes(user) + TEMPLATE_RESERVE_TOKENS;
}

export function chatFits(prompt: ReviewerPrompt, numCtx: number): EvidenceFits {
	const budget = chatEvidenceBytes(prompt, numCtx);
	return (rendered) => bytes(rendered) <= budget;
}

/**
 * The classifier renders the state twice in every question's prompt, pretty
 * printed, beside every question. The exact text comes from pi-ai's own
 * renderer, so the bound follows the transport if it changes.
 */
export function classifierPromptBytes(questions: Record<string, ClassifierQuestion>, state: JsonObject): number {
	let largest = 0;
	for (const id of Object.keys(questions)) {
		largest = Math.max(largest, bytes(renderQuestion({ state, questions }, id).content));
	}
	return largest + CLASSIFIER_SYSTEM_BYTES;
}

export function classifierFits(prompt: ReviewerPrompt, nCtx: number): EvidenceFits {
	// One label token is read; llama.cpp refuses a prompt of n_ctx tokens or more.
	const limit = nCtx - TEMPLATE_RESERVE_TOKENS - 1;
	return (rendered) => classifierPromptBytes(prompt.classifier.questions, JSON.parse(rendered) as JsonObject) <= limit;
}

/** Refuses at session start a configuration whose system text leaves the evidence no room. */
export function assertEvidenceRoom(available: number, what: string): void {
	if (available < MIN_EVIDENCE_BYTES) {
		throw new ReviewerBudgetError(
			`${what} leaves ${Math.max(0, available)} bytes for evidence, below the ${MIN_EVIDENCE_BYTES}-byte minimum; ` +
				"raise the context or shorten the review.* rulebook",
		);
	}
}

export function classifierEvidenceBytes(prompt: ReviewerPrompt, nCtx: number): number {
	const fixed = classifierPromptBytes(prompt.classifier.questions, {});
	// The state appears twice; `{}` is already counted twice in `fixed`.
	return Math.floor((nCtx - TEMPLATE_RESERVE_TOKENS - 1 - fixed) / 2);
}
