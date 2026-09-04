import type { BuildEvidenceOptions, ReviewContextEntry, ReviewEvidence } from "./types.ts";

/** Bounds keep injected context from crowding direct authorization out of a local model's prompt. */
export const MAX_AUTHORIZATION_ENTRIES = 8;
export const MAX_CONTEXT_ENTRIES = 12;
export const MAX_EVIDENCE_TEXT_CHARS = 2_048;
export const MAX_EVIDENCE_JSON_BYTES = 32_768;
const MAX_COLLECTION_ENTRIES = 32;
const MAX_VALUE_DEPTH = 6;

interface Budget {
	remaining: number;
	truncated: boolean;
}

function boundedText(value: string, budget?: Budget): string {
	const allowed = Math.max(0, Math.min(MAX_EVIDENCE_TEXT_CHARS, budget?.remaining ?? MAX_EVIDENCE_TEXT_CHARS));
	if (budget) budget.remaining -= Math.min(value.length, allowed);
	if (value.length <= allowed) return value;
	if (budget) budget.truncated = true;
	return value.slice(0, allowed);
}

function boundedValue(value: unknown, budget: Budget, depth = 0): unknown {
	// Charge every node, not only string content. Without a structural budget,
	// an array-of-arrays full of booleans could expand exponentially while never
	// consuming a single character from the budget.
	if (budget.remaining <= 0) {
		budget.truncated = true;
		return "[budget limit]";
	}
	budget.remaining--;
	if (typeof value === "string") return boundedText(value, budget);
	if (value === null || typeof value === "boolean" || typeof value === "number") return value;
	if (depth >= MAX_VALUE_DEPTH) {
		budget.truncated = true;
		return "[depth limit]";
	}
	if (Array.isArray(value)) {
		if (value.length > MAX_COLLECTION_ENTRIES) budget.truncated = true;
		return value.slice(0, MAX_COLLECTION_ENTRIES).map((entry) => boundedValue(entry, budget, depth + 1));
	}
	if (value && typeof value === "object") {
		const entries = Object.entries(value);
		if (entries.length > MAX_COLLECTION_ENTRIES) budget.truncated = true;
		return Object.fromEntries(
			entries
				.slice(0, MAX_COLLECTION_ENTRIES)
				.map(([key, entry]) => [boundedText(key, budget), boundedValue(entry, budget, depth + 1)]),
		);
	}
	budget.truncated = true;
	return `[${typeof value}]`;
}

function boundedRecord(
	input: Record<string, unknown>,
	chars: number,
): { value: Record<string, unknown>; truncated: boolean } {
	const budget: Budget = { remaining: chars, truncated: false };
	const value = boundedValue(input, budget);
	return { value: value as Record<string, unknown>, truncated: budget.truncated };
}

function boundedContext(entries: readonly ReviewContextEntry[]): ReviewContextEntry[] {
	return entries.slice(-MAX_CONTEXT_ENTRIES).map((entry) => {
		const input = boundedRecord(entry.input, 2_048);
		return {
			provenance: "assistant_tool_call",
			tool: boundedText(entry.tool),
			input: input.value,
			...(input.truncated ? { truncated: true } : {}),
		};
	});
}

function boundedViolation(value: NonNullable<ReviewEvidence["violation"]>): NonNullable<ReviewEvidence["violation"]> {
	const budget: Budget = { remaining: 2_048, truncated: false };
	return {
		kind: value.kind,
		source: value.source,
		op: boundedText(value.op, budget),
		backend: value.backend,
		...(value.path ? { path: boundedText(value.path, budget) } : {}),
		...(value.host ? { host: boundedText(value.host, budget) } : {}),
		...(value.raw ? { raw: boundedText(value.raw, budget) } : {}),
	};
}

function serializedBytes(value: unknown): number {
	return Buffer.byteLength(JSON.stringify(value));
}

/**
 * Emergency representation for adversarial structures whose JSON escaping or
 * non-string shape still exceeds the aggregate bound. It keeps identity and
 * the newest direct authorization, drops low-trust context, and forces the
 * deterministic high-risk floor through action.truncated.
 */
function minimalEvidence(evidence: ReviewEvidence): ReviewEvidence {
	const violation = evidence.violation
		? {
				kind: evidence.violation.kind,
				source: evidence.violation.source,
				op: evidence.violation.op.slice(0, 128),
				backend: evidence.violation.backend,
				...(evidence.violation.path ? { path: evidence.violation.path.slice(0, 128) } : {}),
				...(evidence.violation.host ? { host: evidence.violation.host.slice(0, 128) } : {}),
			}
		: null;
	return {
		action: {
			tool: evidence.action.tool.slice(0, 128),
			input: { truncated: "complete input omitted; action.hash binds it" },
			cwd: evidence.action.cwd.slice(0, 256),
			paths: evidence.action.paths.slice(0, 2).map((path) => ({
				raw: path.raw.slice(0, 128),
				resolved: path.resolved.slice(0, 128),
				writes: path.writes,
			})),
			hash: evidence.action.hash,
			trigger: evidence.action.trigger,
			confident: evidence.action.confident,
			truncated: true,
		},
		violation,
		requestedCapability: evidence.requestedCapability
			? { kind: evidence.requestedCapability.kind, value: evidence.requestedCapability.value.slice(0, 256) }
			: null,
		authorization: evidence.authorization.slice(-2).map((entry) => ({
			provenance: "direct",
			channel: entry.channel,
			text: entry.text.slice(0, 512),
		})),
		context: [],
		profile: { name: evidence.profile.name.slice(0, 128), attended: evidence.profile.attended },
	};
}

export function buildReviewEvidence(options: BuildEvidenceOptions): ReviewEvidence {
	const { action } = options;
	const input = boundedRecord(action.input, 8_192);
	const detailBudget: Budget = { remaining: 4_096, truncated: false };
	const argv = action.shell?.commands
		.slice(0, MAX_COLLECTION_ENTRIES)
		.map((command) => [command.name, ...command.args].map((value) => boundedText(value, detailBudget)));
	const paths = action.paths.slice(0, MAX_COLLECTION_ENTRIES).map((path) => ({
		raw: boundedText(path.raw, detailBudget),
		resolved: boundedText(path.resolved, detailBudget),
		writes: path.writes,
	}));
	const toolSource = options.toolSource ? boundedText(options.toolSource, detailBudget) : undefined;
	const requestedCapability = action.capability
		? { kind: action.capability.kind, value: boundedText(action.capability.value, detailBudget) }
		: null;
	const actionTruncated =
		input.truncated ||
		detailBudget.truncated ||
		action.paths.length > MAX_COLLECTION_ENTRIES ||
		(action.shell?.commands.length ?? 0) > MAX_COLLECTION_ENTRIES;
	const evidence: ReviewEvidence = {
		action: {
			tool: boundedText(action.tool),
			input: input.value,
			...(argv ? { argv } : {}),
			cwd: boundedText(action.cwd),
			paths,
			hash: action.hash,
			trigger: options.trigger,
			confident: action.confident,
			truncated: actionTruncated,
			...(toolSource ? { toolSource } : {}),
		},
		violation: options.violation ? boundedViolation(options.violation) : null,
		requestedCapability,
		authorization: (options.authorization ?? []).slice(-MAX_AUTHORIZATION_ENTRIES).map((entry) => ({
			provenance: "direct",
			channel: entry.channel,
			text: boundedText(entry.text),
		})),
		context: boundedContext(options.context ?? []),
		profile: { name: action.profileName, attended: options.attended },
	};
	// Context is least trusted and least important. Remove oldest entries if
	// structural JSON overhead still exceeds the hard evidence bound.
	while (evidence.context.length > 0 && serializedBytes(evidence) > MAX_EVIDENCE_JSON_BYTES) {
		evidence.context.shift();
	}
	if (serializedBytes(evidence) <= MAX_EVIDENCE_JSON_BYTES) return evidence;
	const minimal = minimalEvidence(evidence);
	if (serializedBytes(minimal) > MAX_EVIDENCE_JSON_BYTES) {
		throw new Error("pi-enclave: internal error: minimal reviewer evidence exceeds its hard byte bound");
	}
	return minimal;
}

/** Stable because object construction above fixes every key's order. */
export function renderReviewEvidence(evidence: ReviewEvidence): string {
	return JSON.stringify(evidence);
}
