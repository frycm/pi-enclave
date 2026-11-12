import type { ModelRegistry } from "@earendil-works/pi-coding-agent";
import type { EffectiveProfile, Provenance } from "../config/types.ts";
import { evalReviewer } from "./eval.ts";
import { buildReviewerPrompt, reviewerRulebook } from "./prompt.ts";
import { type QualificationRecord, writeQualification } from "./qualification.ts";
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
	const prompt = buildReviewerPrompt(reviewerRulebook(options.profile.review, options.provenance));
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
	}
	return lines.join("\n");
}
