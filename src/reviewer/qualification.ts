import { createHash, randomUUID } from "node:crypto";
import { readFileSync, renameSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { checkSecureFile } from "../state/dir.ts";

export const QUALIFICATION_VERSION = 1;
export const DEFAULT_QUALIFICATION_TRIALS = 5;

export interface ReviewerSampling {
	temperature: number;
	seed: number;
	numCtx: number;
	maxTokens: number;
	trials: number;
}

export interface QualificationBinding {
	model: string;
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
}

export interface QualificationRecord extends QualificationBinding {
	version: typeof QUALIFICATION_VERSION;
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

export function isQualificationRecord(value: unknown): value is QualificationRecord {
	if (!value || typeof value !== "object" || Array.isArray(value)) return false;
	const record = value as Partial<QualificationRecord>;
	const sampling = record.sampling as Partial<ReviewerSampling> | undefined;
	const metrics = record.metrics as Partial<QualificationMetrics> | undefined;
	return (
		record.version === QUALIFICATION_VERSION &&
		typeof record.model === "string" &&
		typeof record.modelDigest === "string" &&
		typeof record.promptHash === "string" &&
		typeof record.corpusHash === "string" &&
		typeof record.passed === "boolean" &&
		typeof record.createdAt === "string" &&
		!!sampling &&
		isFiniteNumber(sampling.temperature) &&
		isFiniteNumber(sampling.seed) &&
		isFiniteNumber(sampling.numCtx) &&
		isFiniteNumber(sampling.maxTokens) &&
		isFiniteNumber(sampling.trials) &&
		!!metrics &&
		isFiniteNumber(metrics.injectedAllows) &&
		isFiniteNumber(metrics.benignCases) &&
		isFiniteNumber(metrics.benignFalseDenials) &&
		isFiniteNumber(metrics.falseDenialRate) &&
		isFiniteNumber(metrics.p95LatencyMs) &&
		isFiniteNumber(metrics.errors)
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
	for (const key of ["model", "modelDigest", "promptHash", "corpusHash"] as const) {
		if (value[key] !== expected[key]) return { ok: false, reason: `${key} changed since qualification` };
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
