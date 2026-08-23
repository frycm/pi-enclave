/**
 * The audit log: one JSONL record per decision, chained.
 *
 * The claim it supports is precise, and worth stating in the negative first.
 * This is **not** tamper-proof: anything running as the user can delete the
 * file. It is tamper-*evident* against the agent and against accidents, which
 * is the honest version of what a userspace log can offer -- each record
 * carries a sequence number and the hash of the line before it, so a deletion,
 * a truncation or an edit anywhere in the file is detectable by re-chaining it.
 *
 * Two implementation choices that are not incidental:
 *
 * **Writes go through one queue.** `seq` and `prevHash` are each derived from
 * the record before, so an interleaving would break the chain -- and a chain
 * that breaks under ordinary parallel tool use cannot be told apart from
 * tampering. Worth being precise about what the queue currently buys: the write
 * is `appendFileSync` and the sequence and hash are computed in the same
 * synchronous block, so JavaScript's own single-threadedness already prevents
 * interleaving today. A mutation check that removed the serialization could not
 * be made to fail for exactly that reason. The queue is what keeps that true if
 * the write ever becomes asynchronous, which is a change someone would
 * otherwise make without noticing it breaks the chain.
 *
 * **A decision is never awaited on a write.** The gate records and moves on.
 * An audit log that adds latency to every tool call is one someone will turn
 * off, and the record is not the control -- the denial already happened.
 */

import { createHash } from "node:crypto";
import { appendFileSync, closeSync, createReadStream, existsSync, openSync, readFileSync } from "node:fs";
import { join } from "node:path";
import type { EffectiveProfile } from "../config/types.ts";
import type { CanonicalAction } from "../policy/canonical.ts";
import type { RuleMatch } from "../policy/match.ts";
import { redact } from "./redact.ts";

export type AuditKind =
	| "session_start"
	| "config"
	| "decision"
	| "violation"
	| "breaker"
	| "attendance"
	| "pending"
	| "refusal";

export interface AuditRecord {
	seq: number;
	ts: string;
	kind: AuditKind;
	sessionId: string;
	/** SHA-256 of the previous line, or the genesis marker for the first. */
	prevHash: string;
	[field: string]: unknown;
}

export const GENESIS = "sha256:0000000000000000000000000000000000000000000000000000000000000000";

function hashLine(line: string): string {
	return `sha256:${createHash("sha256").update(line).digest("hex")}`;
}

export interface AuditOptions {
	dir: string;
	sessionId: string;
	/** Injected by tests. */
	now?: () => Date;
	/** Paths whose mention implies their contents, for redaction. */
	readDeny?: readonly string[];
	/** Called when a write fails. The session continues; the log says it did not. */
	onError?: (error: Error) => void;
}

export class AuditLog {
	readonly path: string;
	private seq = 0;
	private prevHash = GENESIS;
	private queue: Promise<void> = Promise.resolve();
	private failed = false;

	constructor(private readonly options: AuditOptions) {
		this.path = join(options.dir, `${options.sessionId}.jsonl`);
		// A resumed session appends to its own file, so the chain continues
		// across a restart rather than starting again with a fresh genesis.
		if (existsSync(this.path)) {
			const tail = lastCompleteRecord(this.path);
			if (tail) {
				this.seq = tail.record.seq;
				this.prevHash = hashLine(tail.line);
			}
		}
	}

	/** True once a write has failed. Surfaced in the status line. */
	get degraded(): boolean {
		return this.failed;
	}

	/**
	 * Append a record. Returns immediately; the write is queued.
	 *
	 * Fields are redacted here rather than by the caller, so no call site can
	 * forget.
	 */
	append(kind: AuditKind, fields: Record<string, unknown>): void {
		const body = redact(fields, { ...(this.options.readDeny ? { readDeny: this.options.readDeny } : {}) }) as Record<
			string,
			unknown
		>;
		this.queue = this.queue.then(() => {
			try {
				const record: AuditRecord = {
					seq: ++this.seq,
					ts: (this.options.now?.() ?? new Date()).toISOString(),
					kind,
					sessionId: this.options.sessionId,
					prevHash: this.prevHash,
					...body,
				};
				const line = JSON.stringify(record);
				appendFileSync(this.path, `${line}\n`, { mode: 0o600 });
				this.prevHash = hashLine(line);
			} catch (error) {
				this.failed = true;
				this.options.onError?.(error as Error);
			}
		});
	}

	/** Wait for queued writes. Used at session shutdown and by the tests. */
	async flush(): Promise<void> {
		await this.queue;
	}

	/** Create the file so a session with no decisions still leaves a trace. */
	touch(): void {
		if (existsSync(this.path)) return;
		try {
			closeSync(openSync(this.path, "a", 0o600));
		} catch (error) {
			this.failed = true;
			this.options.onError?.(error as Error);
		}
	}
}

// ---------------------------------------------------------------------------
// Record builders
// ---------------------------------------------------------------------------

/**
 * A decision record.
 *
 * Carries the canonical hash rather than the full action: the hash is what ties
 * the record to a pending approval, and the full action is a copy of everything
 * the agent said, which the pending record already stores where it is needed.
 */
export function decisionFields(options: {
	action: CanonicalAction;
	outcome: string;
	matches: readonly RuleMatch[];
	turnIndex: number;
	attended: string;
	reason?: string;
}): Record<string, unknown> {
	return {
		outcome: options.outcome,
		tool: options.action.tool,
		hash: options.action.hash,
		cwd: options.action.cwd,
		turnIndex: options.turnIndex,
		attended: options.attended,
		profile: options.action.profileName,
		confident: options.action.confident,
		commands: options.action.shell?.commands.map((command) => [command.name, ...command.args].join(" ")) ?? undefined,
		paths: options.action.paths.map((path) => ({ path: path.resolved, writes: path.writes })),
		capability: options.action.capability ?? undefined,
		// Every match, not only the decisive one: a skipReview entry that is
		// being silently overridden is something the user needs to see.
		matches: options.matches.map((match) => ({ list: match.list, pattern: match.pattern, target: match.target })),
		reason: options.reason,
	};
}

export function configFields(
	profile: EffectiveProfile,
	configHash: string,
	sources: readonly string[],
): Record<string, unknown> {
	return {
		profile: profile.name,
		configHash,
		sources,
		auto: profile.auto,
		attended: profile.attended.mode,
		reviewer: profile.reviewer.model,
		trigger: profile.review.trigger,
		writableRoots: profile.sandbox.writableRoots,
		rules: {
			deny: profile.rules.deny.length,
			ask: profile.rules.ask.length,
			skipReview: profile.rules.skipReview.length,
		},
	};
}

/** A stable hash of the effective configuration, for the record and for resume. */
export function configHash(profile: EffectiveProfile): string {
	return `sha256:${createHash("sha256").update(JSON.stringify(profile)).digest("hex")}`;
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

export interface VerifyResult {
	ok: boolean;
	records: number;
	/** The first record whose chain or sequence is wrong. */
	brokenAt?: number;
	problem?: string;
	/** True when the last line is a partial write rather than a broken chain. */
	truncatedTail?: boolean;
}

/**
 * Re-chain a log file and report the first break.
 *
 * A torn final line is reported separately from a broken chain, because they
 * mean different things: the first is a crash mid-write, which is expected and
 * harmless, and the second is an edit.
 */
export function verifyLog(path: string): VerifyResult {
	let text: string;
	try {
		text = readFileSync(path, "utf8");
	} catch (error) {
		return { ok: false, records: 0, problem: `cannot read ${path}: ${(error as Error).message}` };
	}

	const lines = text.split("\n");
	const truncatedTail = lines.length > 0 && lines[lines.length - 1] !== "";
	const complete = truncatedTail ? lines.slice(0, -1) : lines.filter((line) => line !== "");

	let expectedPrev = GENESIS;
	let expectedSeq = 1;
	let count = 0;

	for (const line of complete) {
		if (line === "") continue;
		let record: AuditRecord;
		try {
			record = JSON.parse(line) as AuditRecord;
		} catch {
			return { ok: false, records: count, brokenAt: expectedSeq, problem: "not valid JSON", truncatedTail };
		}
		if (record.seq !== expectedSeq) {
			return {
				ok: false,
				records: count,
				brokenAt: expectedSeq,
				problem: `expected seq ${expectedSeq}, found ${record.seq} -- ${record.seq > expectedSeq ? "records are missing" : "a record was repeated"}`,
				truncatedTail,
			};
		}
		if (record.prevHash !== expectedPrev) {
			return {
				ok: false,
				records: count,
				brokenAt: record.seq,
				problem: "prevHash does not match the previous line -- an earlier record was edited or removed",
				truncatedTail,
			};
		}
		expectedPrev = hashLine(line);
		expectedSeq = record.seq + 1;
		count++;
	}

	return { ok: true, records: count, truncatedTail };
}

/** The last line that parses, for continuing a chain after a resume. */
function lastCompleteRecord(path: string): { record: AuditRecord; line: string } | undefined {
	let text: string;
	try {
		text = readFileSync(path, "utf8");
	} catch {
		return undefined;
	}
	const lines = text.split("\n").filter((line) => line !== "");
	for (let i = lines.length - 1; i >= 0; i--) {
		const line = lines[i] as string;
		try {
			return { record: JSON.parse(line) as AuditRecord, line };
		} catch {
			// A torn final line. Skip it and chain from the last complete one.
		}
	}
	return undefined;
}

export function formatVerifyResult(path: string, result: VerifyResult): string {
	const lines = [`${path}: ${result.records} record(s)`];
	if (result.ok) {
		lines.push("  chain verifies");
	} else {
		lines.push(`  CHAIN BROKEN at seq ${result.brokenAt}: ${result.problem}`);
		lines.push("  This log is not trustworthy from that record onward.");
	}
	if (result.truncatedTail) {
		lines.push("  the final line is incomplete (a crash mid-write; records before it are intact)");
	}
	return lines.join("\n");
}

export { createReadStream };
