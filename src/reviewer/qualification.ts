import { createHash, randomUUID } from "node:crypto";
import { readFileSync, renameSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type { ReviewerTransportKind } from "../config/types.ts";
import { checkSecureFile } from "../state/dir.ts";
import {
	CLASSIFIER_ALLOW_CEILING,
	CLASSIFIER_ALLOW_FLOOR,
	CLASSIFIER_DENY_THRESHOLD,
	CLASSIFIER_TEMPERATURE,
} from "./probabilities.ts";
import type { ClassifierThresholds } from "./types.ts";

export const QUALIFICATION_VERSION = 2;
export const DEFAULT_QUALIFICATION_TRIALS = 5;

export interface ReviewerSampling {
	temperature: number;
	seed: number;
	numCtx: number | null;
	maxTokens: number;
	/**
	 * `reviewer.thinkingTokens` (#62). A record without it predates the
	 * setting, when the reviewer never thought, so it reads as 0.
	 */
	thinkingTokens?: number;
	trials: number;
}

export interface QualificationBinding {
	model: string;
	/**
	 * A chat qualification never qualifies the classifier transport, or the
	 * reverse (#26). Absent means chat: records written before #26 have none.
	 */
	transport?: ReviewerTransportKind;
	/**
	 * Classifier transport only: the running pi version. pi-ai's classifier
	 * module owns the system prompt, the prompt layout and the label readout,
	 * so a pi update changes what the model reads without any pi-enclave change.
	 */
	piVersion?: string;
	modelDigest: string;
	promptHash: string;
	corpusHash: string;
	sampling: ReviewerSampling;
}

export interface QualificationMetrics {
	injectedAllows: number;
	benignCases: number;
	benignFalseDenials: number;
	falseDenialRate: number;
	p95LatencyMs: number;
	errors: number;
	p95DecisionMs?: number;
	p95FirstOutputMs?: number;
	/** Classifier transport: the most allow-like injected case and the least allow-like benign one. */
	maxInjectedAllow?: number;
	minBenignAllow?: number;
}

export interface QualificationRecord extends QualificationBinding {
	version: typeof QUALIFICATION_VERSION;
	/** Required for the classifier transport: the thresholds qualification chose. */
	thresholds?: ClassifierThresholds;
	passed: boolean;
	metrics: QualificationMetrics;
	createdAt: string;
}

export type QualificationCheck = { ok: true; record: QualificationRecord } | { ok: false; reason: string };

function recordName(modelDigest: string): string {
	return `${createHash("sha256").update(modelDigest).digest("hex")}.json`;
}

export function qualificationPath(directory: string, modelDigest: string): string {
	return join(directory, recordName(modelDigest));
}

function isFiniteNumber(value: unknown): value is number {
	return typeof value === "number" && Number.isFinite(value);
}

function isProbability(value: unknown): value is number {
	return isFiniteNumber(value) && value >= 0 && value <= 1;
}

/** The values qualification can choose, checked again on read; the temperature is the one sampling binds. */
function isThresholds(value: unknown, sampling: Partial<ReviewerSampling> | undefined): value is ClassifierThresholds {
	if (!value || typeof value !== "object" || Array.isArray(value)) return false;
	const thresholds = value as Partial<ClassifierThresholds>;
	return (
		isProbability(thresholds.allow) &&
		thresholds.allow >= CLASSIFIER_ALLOW_FLOOR &&
		thresholds.allow <= CLASSIFIER_ALLOW_CEILING &&
		thresholds.deny === CLASSIFIER_DENY_THRESHOLD &&
		thresholds.temperature === CLASSIFIER_TEMPERATURE &&
		sampling?.temperature === CLASSIFIER_TEMPERATURE
	);
}

export function recordTransport(record: Pick<QualificationBinding, "transport">): ReviewerTransportKind {
	return record.transport ?? "chat";
}

export function isQualificationRecord(value: unknown): value is QualificationRecord {
	if (!value || typeof value !== "object" || Array.isArray(value)) return false;
	const record = value as Partial<QualificationRecord>;
	const sampling = record.sampling as Partial<ReviewerSampling> | undefined;
	const metrics = record.metrics as Partial<QualificationMetrics> | undefined;
	return (
		record.version === QUALIFICATION_VERSION &&
		(record.transport === undefined || record.transport === "chat" || record.transport === "classifier") &&
		(record.transport === "classifier"
			? isThresholds(record.thresholds, sampling) && typeof record.piVersion === "string" && record.piVersion !== ""
			: record.thresholds === undefined && record.piVersion === undefined) &&
		typeof record.model === "string" &&
		typeof record.modelDigest === "string" &&
		typeof record.promptHash === "string" &&
		typeof record.corpusHash === "string" &&
		typeof record.passed === "boolean" &&
		typeof record.createdAt === "string" &&
		!!sampling &&
		isFiniteNumber(sampling.temperature) &&
		isFiniteNumber(sampling.seed) &&
		(sampling.numCtx === null || isFiniteNumber(sampling.numCtx)) &&
		isFiniteNumber(sampling.maxTokens) &&
		(sampling.thinkingTokens === undefined || isFiniteNumber(sampling.thinkingTokens)) &&
		isFiniteNumber(sampling.trials) &&
		!!metrics &&
		isFiniteNumber(metrics.injectedAllows) &&
		isFiniteNumber(metrics.benignCases) &&
		isFiniteNumber(metrics.benignFalseDenials) &&
		isFiniteNumber(metrics.falseDenialRate) &&
		isFiniteNumber(metrics.p95LatencyMs) &&
		isFiniteNumber(metrics.errors) &&
		[metrics.p95DecisionMs, metrics.p95FirstOutputMs].every((value) => value === undefined || isFiniteNumber(value)) &&
		[metrics.maxInjectedAllow, metrics.minBenignAllow].every((value) => value === undefined || isProbability(value))
	);
}

function equalSampling(a: ReviewerSampling, b: ReviewerSampling): boolean {
	return (
		a.temperature === b.temperature &&
		a.seed === b.seed &&
		a.numCtx === b.numCtx &&
		a.maxTokens === b.maxTokens &&
		a.trials === b.trials
	);
}

export function readQualification(directory: string, expected: QualificationBinding): QualificationCheck {
	const path = qualificationPath(directory, expected.modelDigest);
	const insecure = checkSecureFile(path);
	if (insecure) return { ok: false, reason: insecure };
	let value: unknown;
	try {
		value = JSON.parse(readFileSync(path, "utf8"));
	} catch (error) {
		return { ok: false, reason: `${path} is not valid JSON: ${(error as Error).message}` };
	}
	if (!isQualificationRecord(value)) return { ok: false, reason: `${path} is not a valid qualification record` };
	if (!value.passed) return { ok: false, reason: `${path} records a failed evaluation` };
	if (recordTransport(value) !== recordTransport(expected)) {
		return {
			ok: false,
			reason: `${path} qualifies the ${recordTransport(value)} transport, not ${recordTransport(expected)}`,
		};
	}
	if (value.piVersion !== expected.piVersion) {
		return {
			ok: false,
			reason: `qualified on pi ${value.piVersion ?? "(none)"}, running pi ${expected.piVersion ?? "(none)"}; pi's classifier prompt may have changed`,
		};
	}
	for (const key of ["model", "modelDigest", "promptHash", "corpusHash"] as const) {
		if (value[key] !== expected[key]) return { ok: false, reason: `${key} changed since qualification` };
	}
	const thinking = (sampling: ReviewerSampling) => sampling.thinkingTokens ?? 0;
	if (thinking(value.sampling) !== thinking(expected.sampling)) {
		return {
			ok: false,
			reason: `qualified with reviewer.thinkingTokens ${thinking(value.sampling)}, configured ${thinking(expected.sampling)}`,
		};
	}
	if (!equalSampling(value.sampling, expected.sampling)) {
		return { ok: false, reason: "reviewer sampling parameters changed since qualification" };
	}
	return { ok: true, record: value };
}

export function writeQualification(directory: string, record: QualificationRecord): string {
	const path = qualificationPath(directory, record.modelDigest);
	const temporary = join(directory, `.${recordName(record.modelDigest)}.${process.pid}.${randomUUID()}.tmp`);
	writeFileSync(temporary, `${JSON.stringify(record, null, 2)}\n`, { encoding: "utf8", flag: "wx", mode: 0o600 });
	renameSync(temporary, path);
	return path;
}
