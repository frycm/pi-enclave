import type { ModelRegistry } from "@earendil-works/pi-coding-agent";
import type { EffectiveProfile, Provenance } from "../config/types.ts";
import { qualificationBinding } from "./eval.ts";
import { bindReviewerClassifier, resolveReviewerClassifier, reviewerClassifierDigest } from "./llama.ts";
import { bindReviewerCompletion, resolveReviewerModel, reviewerModelDigest } from "./model.ts";
import { CLASSIFIER_DENY_THRESHOLD, CLASSIFIER_TEMPERATURE } from "./probabilities.ts";
import { buildReviewerPrompt, reviewerRulebook } from "./prompt.ts";
import { readQualification } from "./qualification.ts";
import type { IsolatedReviewerOptions, ReviewerTransport } from "./reviewer.ts";
import { REVIEWER_MAX_TOKENS, REVIEWER_NUM_CTX, REVIEWER_SEED, REVIEWER_TEMPERATURE } from "./reviewer.ts";
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

/** The classifier's thresholds come only from its qualification record. */
async function qualifiedClassifier(
	reference: string,
	profile: EffectiveProfile,
	prompt: ReviewerPrompt,
	registry: ModelRegistry,
	qualifiedDir: string,
): Promise<ReviewerTransport> {
	const resolved = resolveReviewerClassifier(registry, reference);
	const modelDigest = await reviewerClassifierDigest(resolved.model, registry);
	const provisional = { allow: 1, deny: CLASSIFIER_DENY_THRESHOLD, temperature: CLASSIFIER_TEMPERATURE };
	const binding = qualificationBinding({
		model: reference,
		modelDigest,
		profile,
		prompt,
		completion: bindReviewerClassifier(resolved, modelDigest, provisional),
		timeoutMs: profile.reviewer.timeoutMs,
	});
	const qualification = readQualification(qualifiedDir, binding);
	if (!qualification.ok) throw notQualified(reference, qualification.reason);
	if (!qualification.record.thresholds) throw notQualified(reference, "the record has no classifier thresholds");
	return bindReviewerClassifier(resolved, modelDigest, qualification.record.thresholds);
}

async function qualifiedCompletion(
	reference: string,
	profile: EffectiveProfile,
	prompt: ReviewerPrompt,
	registry: ModelRegistry,
	qualifiedDir: string,
): Promise<ReviewerTransport> {
	if (profile.reviewer.transport === "classifier") {
		return qualifiedClassifier(reference, profile, prompt, registry, qualifiedDir);
	}
	const resolved = resolveReviewerModel(registry, reference);
	const modelDigest = await reviewerModelDigest(resolved.model, registry);
	const binding = qualificationBinding({
		model: reference,
		modelDigest,
		profile,
		prompt,
		completion: bindReviewerCompletion(resolved, modelDigest),
		timeoutMs: profile.reviewer.timeoutMs,
	});
	const qualification = readQualification(qualifiedDir, binding);
	if (!qualification.ok) throw notQualified(reference, qualification.reason);
	return bindReviewerCompletion(resolved, modelDigest);
}

export async function prepareQualifiedReviewer(
	profile: EffectiveProfile,
	provenance: Provenance,
	registry: ModelRegistry,
	qualifiedDir: string,
): Promise<QualifiedReviewerSetup | undefined> {
	if (!profile.auto || profile.reviewer.model === "none") return undefined;
	const prompt = buildReviewerPrompt(reviewerRulebook(profile.review, provenance));
	const primary = await qualifiedCompletion(profile.reviewer.model, profile, prompt, registry, qualifiedDir);
	const fallback =
		profile.reviewer.fallback === "none"
			? undefined
			: await qualifiedCompletion(profile.reviewer.fallback, profile, prompt, registry, qualifiedDir);
	return { prompt, primary, ...(fallback ? { fallback } : {}) };
}

export function reviewerSamplingSummary(): string {
	return `temperature=${REVIEWER_TEMPERATURE}, seed=${REVIEWER_SEED}, Ollama num_ctx=${REVIEWER_NUM_CTX} (verified); remote context=provider-managed, maxTokens=${REVIEWER_MAX_TOKENS}`;
}

export type ReviewerEvidenceSource = IsolatedReviewerOptions["evidence"];
