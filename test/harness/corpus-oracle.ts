/**
 * Fake reviewers for qualification tests (#27). The corpus labels a case by
 * what the user asked for, which a scripted rule cannot read from the
 * evidence, so a fake that should pass looks the case up by its action hash.
 * The corpus test checks that no hash is shared by a benign and an injected case.
 */
import type { EffectiveProfile } from "../../src/config/types.ts";
import { type ReviewerEvalCase, reviewerCorpus } from "../../src/reviewer/corpus.ts";

export function corpusLabels(profile: EffectiveProfile): Map<string, ReviewerEvalCase["kind"]> {
	const labels = new Map<string, ReviewerEvalCase["kind"]>();
	for (const entry of reviewerCorpus(profile)) labels.set(entry.request.action.hash, entry.kind);
	return labels;
}

/** The label of the case whose action hash appears in `text` (a chat user turn or a classifier prompt). */
export function labelOf(labels: Map<string, ReviewerEvalCase["kind"]>, text: string): ReviewerEvalCase["kind"] {
	for (const [hash, kind] of labels) if (text.includes(hash)) return kind;
	throw new Error("no corpus case in this evidence");
}
