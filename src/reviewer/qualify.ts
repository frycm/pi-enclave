import type { ModelRegistry } from "@earendil-works/pi-coding-agent";
import type { EffectiveProfile, Provenance } from "../config/types.ts";
import { evalReviewer } from "./eval.ts";
import { buildReviewerPrompt, reviewerRulebook } from "./prompt.ts";
import {
	type CategoryMetrics,
	type OutcomeCounts,
	type QualificationRecord,
	writeQualification,
} from "./qualification.ts";
import { reviewerTarget } from "./setup.ts";

export interface QualificationRun {
	model: string;
	record: QualificationRecord;
	path: string;
}

export async function qualifyConfiguredReviewers(options: {
	profile: EffectiveProfile;
	provenance: Provenance;
	registry: ModelRegistry;
	qualifiedDir: string;
	onProgress?: (model: string, completed: number, total: number) => void;
}): Promise<QualificationRun[]> {
	if (options.profile.reviewer.model === "none") {
		throw new Error('reviewer.model is "none"; configure an explicit provider/model-id before qualification');
	}
	const prompt = buildReviewerPrompt(
		reviewerRulebook(options.profile.review, options.provenance, options.profile.rules),
	);
	const references = [options.profile.reviewer.model];
	if (
		options.profile.reviewer.fallback !== "none" &&
		options.profile.reviewer.fallback !== options.profile.reviewer.model
	) {
		references.push(options.profile.reviewer.fallback);
	}

	const runs: QualificationRun[] = [];
	for (const reference of references) {
		const { modelDigest, completion } = await reviewerTarget(options.registry, reference, options.profile, prompt);
		const record = await evalReviewer({
			model: reference,
			modelDigest,
			profile: options.profile,
			prompt,
			completion,
			timeoutMs: options.profile.reviewer.timeoutMs,
			...(options.onProgress
				? { onProgress: (completed: number, total: number) => options.onProgress?.(reference, completed, total) }
				: {}),
		});
		const path = writeQualification(options.qualifiedDir, record);
		runs.push({ model: reference, record, path });
	}
	return runs;
}

function total(counts: OutcomeCounts): number {
	return counts.allow + counts.ask + counts.deny + counts.error;
}

function percent(part: number, whole: number): string {
	return whole === 0 ? "n/a" : `${((part / whole) * 100).toFixed(0)}%`;
}

/**
 * One line per corpus category (#27): how many trials were allowed, by the
 * model and after the floors, and the precision and recall of the model's
 * allow (allowed benign trials over all allowed trials, and over all benign ones).
 */
export function formatCategory(name: string, metrics: CategoryMetrics): string {
	const parts: string[] = [];
	const benign = total(metrics.benign);
	const injected = total(metrics.injected);
	if (benign > 0)
		parts.push(`benign allowed ${metrics.benign.allow}/${benign} (effective ${metrics.effectiveBenign.allow})`);
	if (injected > 0) {
		parts.push(
			`injected allowed ${metrics.injected.allow}/${injected} (effective ${metrics.effectiveInjected.allow}; ask ${metrics.injected.ask}, deny ${metrics.injected.deny})`,
		);
	}
	const errors = metrics.benign.error + metrics.injected.error;
	if (errors > 0) parts.push(`errors ${errors}`);
	const allowed = metrics.benign.allow + metrics.injected.allow;
	if (allowed > 0 && injected > 0) parts.push(`precision ${percent(metrics.benign.allow, allowed)}`);
	if (benign > 0) parts.push(`recall ${percent(metrics.benign.allow, benign)}`);
	return `    ${name} (${metrics.cases} cases): ${parts.join(", ")}`;
}

export function formatQualificationRuns(runs: readonly QualificationRun[]): string {
	const lines: string[] = [];
	for (const run of runs) {
		const result = run.record.passed ? "QUALIFIED" : "FAILED";
		const metrics = run.record.metrics;
		lines.push(
			`${run.model}: ${result} (${run.record.transport ?? "chat"} transport)`,
			`  injected allows: ${metrics.injectedAllows}`,
			`  benign false-denial rate: ${(metrics.falseDenialRate * 100).toFixed(1)}%`,
			`  p95 latency: ${metrics.p95LatencyMs.toFixed(0)} ms`,
			`  completion errors: ${metrics.errors}`,
			`  record: ${run.path}`,
		);
		const thresholds = run.record.thresholds;
		if (thresholds) {
			lines.push(
				`  allow threshold: P(allow) >= ${thresholds.allow} (most allow-like injected case ${metrics.maxInjectedAllow ?? "n/a"}, least allow-like benign case ${metrics.minBenignAllow ?? "n/a"})`,
				`  deny threshold: P(deny) >= ${thresholds.deny}`,
			);
		}
		for (const [label, value] of [
			["decision", metrics.p95DecisionMs],
			["first output", metrics.p95FirstOutputMs],
		] as const) {
			if (value !== undefined) lines.push(`  p95 ${label}: ${value.toFixed(0)} ms`);
		}
		if (metrics.effectiveInjectedAllows !== undefined && metrics.effectiveFalseDenialRate !== undefined) {
			lines.push(
				`  effective, after the deterministic floors: injected allows ${metrics.effectiveInjectedAllows}, benign not allowed ${(metrics.effectiveFalseDenialRate * 100).toFixed(1)}%`,
			);
		}
		if (metrics.categories) {
			lines.push("  per category (model decision; effective after the floors):");
			for (const [name, category] of Object.entries(metrics.categories)) lines.push(formatCategory(name, category));
		}
		if (metrics.thinCategories && metrics.thinCategories.length > 0) {
			lines.push(`  categories below the minimum case count: ${metrics.thinCategories.join(", ")}`);
		}
		if (metrics.unstableCases && metrics.unstableCases.length > 0) {
			lines.push(`  decision changed between trials: ${metrics.unstableCases.join(", ")}`);
		}
	}
	return lines.join("\n");
}
