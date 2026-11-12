import type { ModelRegistry } from "@earendil-works/pi-coding-agent";
import type { EffectiveProfile, Provenance } from "../config/types.ts";
import { assertEvidenceRoom, chatEvidenceBytes, classifierEvidenceBytes } from "./budget.ts";
import { qualificationBinding } from "./eval.ts";
import { bindReviewerClassifier, resolveReviewerClassifier, reviewerClassifierIdentity } from "./llama.ts";
import { bindReviewerCompletion, resolveReviewerModel, reviewerModelDigest } from "./model.ts";
import { CLASSIFIER_DENY_THRESHOLD, CLASSIFIER_TEMPERATURE } from "./probabilities.ts";
import { buildReviewerPrompt, reviewerRulebook } from "./prompt.ts";
import { readQualification } from "./qualification.ts";
import {
	type IsolatedReviewerOptions,
	isClassifier,
	REVIEWER_MAX_TOKENS,
	REVIEWER_NUM_CTX,
	REVIEWER_SEED,
	REVIEWER_TEMPERATURE,
	type ReviewerTransport,
} from "./reviewer.ts";
import type { ReviewerPrompt } from "./types.ts";

export interface QualifiedReviewerSetup {
	prompt: ReviewerPrompt;
	primary: ReviewerTransport;
	fallback?: ReviewerTransport;
}

function notQualified(reference: string, reason: string): Error {
	return new Error(
		`pi-enclave: reviewer ${reference} is not qualified for the current model, prompt, corpus, and sampling parameters (${reason}).\n` +
			`  Run /enclave eval-reviewer in pi.`,
	);
}

/**
 * The identity-bound transport for one configured reviewer, after checking
 * that its context leaves room for evidence (#17). The classifier's real
 * thresholds come from its qualification record; these are placeholders.
 */
export async function reviewerTarget(
	registry: ModelRegistry,
	reference: string,
	profile: EffectiveProfile,
	prompt: ReviewerPrompt,
): Promise<{ modelDigest: string; completion: ReviewerTransport }> {
	const thinking = profile.reviewer.thinkingTokens;
	if (profile.reviewer.transport === "classifier") {
		// The classifier reads one label's probability; there is no answer to think before (#62).
		if (thinking > 0)
			throw new Error('pi-enclave: reviewer.thinkingTokens applies only to reviewer.transport "chat"; set it to 0');
		const resolved = resolveReviewerClassifier(registry, reference);
		const identity = await reviewerClassifierIdentity(resolved.model, registry);
		assertEvidenceRoom(
			classifierEvidenceBytes(prompt, identity.nCtx),
			`the llama.cpp slot context of ${reference} (${identity.nCtx} tokens)`,
		);
		const thresholds = { allow: 1, deny: CLASSIFIER_DENY_THRESHOLD, temperature: CLASSIFIER_TEMPERATURE };
		return { modelDigest: identity.digest, completion: bindReviewerClassifier(resolved, identity, thresholds) };
	}
	const resolved = resolveReviewerModel(registry, reference, profile.reviewer.numCtx, thinking);
	const numCtx = resolved.completion.numCtx;
	if (typeof numCtx === "number") {
		assertEvidenceRoom(
			chatEvidenceBytes(prompt, numCtx, thinking),
			thinking > 0 ? `reviewer.numCtx ${numCtx} with reviewer.thinkingTokens ${thinking}` : `reviewer.numCtx ${numCtx}`,
		);
	}
	const modelDigest = await reviewerModelDigest(resolved.model, registry, profile.reviewer.numCtx);
	return { modelDigest, completion: bindReviewerCompletion(resolved, modelDigest) };
}

async function qualifiedCompletion(
	reference: string,
	profile: EffectiveProfile,
	prompt: ReviewerPrompt,
	registry: ModelRegistry,
	qualifiedDir: string,
): Promise<ReviewerTransport> {
	const { modelDigest, completion } = await reviewerTarget(registry, reference, profile, prompt);
	const binding = qualificationBinding({
		model: reference,
		modelDigest,
		profile,
		prompt,
		completion,
		timeoutMs: profile.reviewer.timeoutMs,
	});
	const qualification = readQualification(qualifiedDir, binding);
	if (!qualification.ok) throw notQualified(reference, qualification.reason);
	if (!isClassifier(completion)) return completion;
	if (!qualification.record.thresholds) throw notQualified(reference, "the record has no classifier thresholds");
	return { ...completion, thresholds: qualification.record.thresholds };
}

export async function prepareQualifiedReviewer(
	profile: EffectiveProfile,
	provenance: Provenance,
	registry: ModelRegistry,
	qualifiedDir: string,
): Promise<QualifiedReviewerSetup | undefined> {
	if (!profile.auto || profile.reviewer.model === "none") return undefined;
	const prompt = buildReviewerPrompt(reviewerRulebook(profile.review, provenance, profile.rules));
	const primary = await qualifiedCompletion(profile.reviewer.model, profile, prompt, registry, qualifiedDir);
	const fallback =
		profile.reviewer.fallback === "none"
			? undefined
			: await qualifiedCompletion(profile.reviewer.fallback, profile, prompt, registry, qualifiedDir);
	return { prompt, primary, ...(fallback ? { fallback } : {}) };
}

export function reviewerSamplingSummary(): string {
	return `temperature=${REVIEWER_TEMPERATURE}, seed=${REVIEWER_SEED}, Ollama num_ctx=reviewer.numCtx (default ${REVIEWER_NUM_CTX}, verified); remote context=provider-managed, maxTokens=${REVIEWER_MAX_TOKENS}, Ollama thinking=reviewer.thinkingTokens (default 0, off)`;
}

export type ReviewerEvidenceSource = IsolatedReviewerOptions["evidence"];
