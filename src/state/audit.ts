/**
 * The audit log: one JSONL record per decision, chained.
 *
 * The claim it supports is precise, and worth stating in the negative first.
 * This is **not** tamper-proof: anything running as the user can delete the
 * file. It is tamper-*evident* against the agent and against accidents, which
 * is the honest version of what a userspace log can offer -- each record
 * carries a sequence number and the hash of the line before it, so a deletion
 * or an edit of any record *before the last one* is detectable by re-chaining
 * it.
 *
 * The chain alone cannot see the end of the file: removing the newest records,
 * or the whole file, leaves a valid chain (#37). So every append also writes
 * the head (the newest seq and its hash) to a separate anchor file, and
 * optionally to syslog. `verifyLog` compares the file against the anchor, and
 * a session that resumes from a log shorter than its anchor records the gap
 * in the chain before it writes anything else. The anchor sits beside the log
 * and belongs to the same user, so it catches accidents, retention and a
 * careless cleanup, not someone who rewrites both; the syslog mirror is the
 * copy the user cannot rewrite on a server that forwards or protects syslog.
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
 *
 * **The queue serializes one instance, not two processes.** Two `pi` runs that
 * somehow share a session id (resuming a session while it is still live) would
 * each seed from the same tail and both append `seq = N+1`, forking the chain.
 * `verifyLog` then reports a repeated seq -- which reads as tampering. This is
 * the safe direction (a concurrent-resume race degrades to "looks tampered", it
 * does not hide a real edit) and pending records are still protected by atomic
 * rename, so it is left as a known limitation rather than guarded with a
 * lockfile whose stale-lock failure mode would block legitimate resumes.
 */

import { createHash } from "node:crypto";
import {
	appendFileSync,
	closeSync,
	createReadStream,
	existsSync,
	openSync,
	readFileSync,
	renameSync,
	statSync,
	truncateSync,
	writeFileSync,
} from "node:fs";
import { join } from "node:path";
import type { EffectiveProfile } from "../config/types.ts";
import type { CanonicalAction } from "../policy/canonical.ts";
import type { RuleMatch } from "../policy/match.ts";
import type { ReviewerResult } from "../reviewer/types.ts";
import { redact } from "./redact.ts";

export type AuditKind =
	| "session_start"
	| "config"
	| "decision"
	| "violation"
	| "breaker"
	| "attendance"
	| "pending"
	| "reviewer"
	| "refusal"
	/** An allowed tool call finished: exit code, duration, error (#37). */
	| "executed"
	/** A `!`/`!!` command the person typed. */
	| "user_command"
	/** `pi-enclave approve` ran, declined or refused a pending action. */
	| "approval"
	/** The log's own events: a missing tail found at resume, the session cap. */
	| "audit";

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

/** Longest command or reviewer text stored in one record. */
export const MAX_AUDIT_TEXT = 8192;

/** A bounded copy of free text, with a flag when it was cut. */
export function boundedText(value: unknown, max = MAX_AUDIT_TEXT): { text?: string; truncated?: true } {
	if (typeof value !== "string") return {};
	return value.length > max ? { text: value.slice(0, max), truncated: true } : { text: value };
}

/** The newest record of a log, as the anchor and the syslog mirror keep it. */
export interface AuditHead {
	sessionId: string;
	seq: number;
	/** SHA-256 of the newest line, the value the next record's prevHash carries. */
	head: string;
	kind: AuditKind;
	ts: string;
	/** Set by retention when it deleted the log on purpose. */
	retired?: { ts: string; reason: string };
}

/** The anchor beside a log: `<session>.jsonl` → `<session>.head`. */
export function anchorPathFor(logPath: string): string {
	return logPath.replace(/\.jsonl$/, ".head");
}

export function readAnchor(path: string): AuditHead | undefined {
	try {
		const value = JSON.parse(readFileSync(path, "utf8")) as AuditHead;
		return typeof value.seq === "number" && typeof value.head === "string" ? value : undefined;
	} catch {
		return undefined;
	}
}

/** Atomic: a crash leaves the old anchor or the new one, never half of one. */
export function writeAnchor(path: string, head: AuditHead): void {
	const tmp = `${path}.tmp`;
	writeFileSync(tmp, `${JSON.stringify(head)}\n`, { mode: 0o600 });
	renameSync(tmp, path);
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
	/** Where the head is kept after every append. Default: beside the log. `false` turns it off. */
	anchorPath?: string | false;
	/** The most one session's file may hold. Past it the log writes one last record and stops. */
	maxBytes?: number;
	/** Called with the head after every append, for an external copy such as syslog. */
	mirror?: (head: AuditHead) => void;
}

export class AuditLog {
	readonly path: string;
	private seq = 0;
	private prevHash = GENESIS;
	private queue: Promise<void> = Promise.resolve();
	private failed = false;
	private capped = false;
	private bytes = 0;
	readonly anchorPath: string | undefined;

	constructor(private readonly options: AuditOptions) {
		this.path = join(options.dir, `${options.sessionId}.jsonl`);
		this.anchorPath = options.anchorPath === false ? undefined : (options.anchorPath ?? anchorPathFor(this.path));
		// A resumed session appends to its own file, so the chain continues
		// across a restart rather than starting again with a fresh genesis.
		if (existsSync(this.path)) {
			// Drop a torn final line (a crash mid-write) *before* appending, so the
			// next record starts on a clean newline boundary. Without this the new
			// record was concatenated onto the partial bytes as one line, which
			// verifyLog then reported as a broken chain -- making an ordinary
			// crash+resume indistinguishable from tampering.
			this.truncateTornTail();
			const tail = lastCompleteRecord(this.path);
			if (tail) {
				this.seq = tail.record.seq;
				this.prevHash = hashLine(tail.line);
			}
			try {
				this.bytes = statSync(this.path).size;
			} catch {
				// Counted from zero; the cap is a bound, not an accounting.
			}
		}
		this.checkAnchorOnOpen();
	}

	/**
	 * A log that is behind its anchor lost its newest records (or the whole
	 * file) since the last write. Appending would overwrite the anchor with a
	 * lower seq and erase the evidence, so the gap is recorded in the chain
	 * first.
	 */
	private checkAnchorOnOpen(): void {
		if (!this.anchorPath) return;
		const anchor = readAnchor(this.anchorPath);
		if (!anchor || anchor.retired) return;
		const behind = anchor.seq > this.seq;
		const differs = anchor.seq === this.seq && anchor.head !== this.prevHash;
		if (!behind && !differs) return;
		this.append("audit", {
			event: behind ? "tail-missing" : "tail-differs",
			anchorSeq: anchor.seq,
			anchorHead: anchor.head,
			anchorTs: anchor.ts,
			logSeq: this.seq,
			note: behind
				? `the log ends at seq ${this.seq} but its anchor recorded seq ${anchor.seq}: the newest records were removed before this session resumed`
				: "the newest record does not match its anchor: it was replaced before this session resumed",
		});
	}

	/** Truncate any bytes after the last newline: an unterminated final record. */
	private truncateTornTail(): void {
		try {
			const raw = readFileSync(this.path);
			if (raw.length === 0) return;
			const lastNewline = raw.lastIndexOf(0x0a);
			// `lastNewline + 1` keeps everything through the final newline and
			// drops the rest; -1 (no newline at all) truncates to empty.
			if (lastNewline !== raw.length - 1) truncateSync(this.path, lastNewline + 1);
		} catch (error) {
			this.failed = true;
			this.options.onError?.(error as Error);
		}
	}

	/** True once a write has failed or the session cap was reached. Surfaced in the status line. */
	get degraded(): boolean {
		return this.failed;
	}

	/** True once the session cap stopped the log. */
	get full(): boolean {
		return this.capped;
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
			if (this.capped) return;
			const max = this.options.maxBytes;
			if (max !== undefined && this.bytes >= max) {
				// One last record, allowed past the cap, so the chain itself says
				// why it ends here rather than looking cut off.
				this.capped = true;
				this.write("audit", { event: "cap-reached", maxBytes: max, dropped: kind });
				this.failed = true;
				this.options.onError?.(
					new Error(`the session's audit log reached its cap of ${Math.round(max / (1024 * 1024))} MB and stopped`),
				);
				return;
			}
			this.write(kind, body);
		});
	}

	private write(kind: AuditKind, body: Record<string, unknown>): void {
		// seq and prevHash advance only after the write lands. Incrementing
		// first meant a transient write failure (a full disk for one append)
		// skipped a sequence number permanently, so every later record carried
		// a gap that verifyLog reported as "records missing" forever after --
		// a recoverable blip made indistinguishable from tampering.
		const nextSeq = this.seq + 1;
		// Reserved chain fields are spread *after* the body, so a caller field
		// that happens to share a name (a `decision` body with a `kind`, or a
		// stray `seq`/`prevHash`) can never clobber the record's own identity
		// or break the chain. The body's colliding field is dropped, which is
		// the safe direction; call sites use non-reserved names for their data.
		const record: AuditRecord = {
			...body,
			seq: nextSeq,
			ts: (this.options.now?.() ?? new Date()).toISOString(),
			kind,
			sessionId: this.options.sessionId,
			prevHash: this.prevHash,
		};
		const line = JSON.stringify(record);
		try {
			appendFileSync(this.path, `${line}\n`, { mode: 0o600 });
		} catch (error) {
			this.failed = true;
			this.options.onError?.(error as Error);
			return;
		}
		this.seq = nextSeq;
		this.prevHash = hashLine(line);
		this.bytes += Buffer.byteLength(line) + 1;
		const head: AuditHead = {
			sessionId: this.options.sessionId,
			seq: nextSeq,
			head: this.prevHash,
			kind,
			ts: record.ts,
		};
		if (this.anchorPath) {
			try {
				writeAnchor(this.anchorPath, head);
			} catch (error) {
				this.failed = true;
				this.options.onError?.(error as Error);
			}
		}
		try {
			this.options.mirror?.(head);
		} catch {
			// The mirror reports its own failures; it never blocks the log.
		}
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
 *
 * The one part of the input it does copy is a shell command, as bash received
 * it (redacted and bounded): `commands` is the tokenizer's reading, which loses
 * quoting and repeats the tokenizer's mistakes, so on its own it can neither be
 * re-run nor re-hashed (#37).
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
		...commandFields(options.action.tool === "bash" ? options.action.input.command : undefined),
		commands: options.action.shell?.commands.map((command) => [command.name, ...command.args].join(" ")) ?? undefined,
		paths: options.action.paths.map((path) => ({ path: path.resolved, writes: path.writes })),
		capability: options.action.capability ?? undefined,
		// Every match, not only the decisive one: a skipReview entry that is
		// being silently overridden is something the user needs to see.
		matches: options.matches.map((match) => ({ list: match.list, pattern: match.pattern, target: match.target })),
		reason: options.reason,
	};
}

function commandFields(command: unknown): Record<string, unknown> {
	const bounded = boundedText(command);
	if (bounded.text === undefined) return {};
	return { command: bounded.text, ...(bounded.truncated ? { commandTruncated: true } : {}) };
}

/** What happened to an allowed call once pi ran it. */
export function executedFields(options: {
	toolCallId: string;
	tool: string;
	hash: string;
	isError: boolean;
	durationMs?: number;
	exitCode?: number | null;
	turnIndex: number;
}): Record<string, unknown> {
	return {
		toolCallId: options.toolCallId,
		tool: options.tool,
		hash: options.hash,
		isError: options.isError,
		...(options.durationMs !== undefined ? { durationMs: Math.round(options.durationMs) } : {}),
		// null is "killed or timed out without an exit code", which is not the
		// same as "not a shell command" (absent).
		...(options.exitCode !== undefined ? { exitCode: options.exitCode } : {}),
		turnIndex: options.turnIndex,
	};
}

/** A `!` command: human input, sandboxed but not gated, and still part of the trail. */
export function userCommandFields(options: {
	command: string;
	cwd: string;
	excludeFromContext: boolean;
	exitCode?: number | null;
	durationMs: number;
	error?: string;
}): Record<string, unknown> {
	return {
		...commandFields(options.command),
		cwd: options.cwd,
		excludeFromContext: options.excludeFromContext,
		...(options.exitCode !== undefined ? { exitCode: options.exitCode } : {}),
		durationMs: Math.round(options.durationMs),
		...(options.error !== undefined ? { error: boundedText(options.error, 1024).text } : {}),
	};
}

/**
 * The reviewer's verdict on one action: what the model said and what the
 * deterministic floor made of it. Enough to tune a small model from the log
 * later (#25, #27) without storing the prompt.
 */
export function reviewerVerdictFields(
	result: ReviewerResult,
	request: { action: CanonicalAction; trigger: string },
): Record<string, unknown> {
	const base = { event: "verdict", hash: request.action.hash, tool: request.action.tool, trigger: request.trigger };
	if (!result.ok) {
		return { ...base, ok: false, failure: result.kind, reason: boundedText(result.reason, 2048).text };
	}
	return {
		...base,
		ok: true,
		decision: result.review.decision,
		risk: result.review.risk,
		modelDecision: result.modelReview.decision,
		modelRisk: result.review.modelRisk,
		minimumRisk: result.review.minimumRisk,
		authorizationCovers: result.review.authorizationCovers,
		reason: boundedText(result.review.reason, 2048).text,
		modelReason: boundedText(result.modelReview.reason, 2048).text,
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
		// Resource limits (#24), so a run that was killed can be read against them.
		limits: profile.sandbox.limits,
		audit: profile.audit,
		rules: {
			deny: profile.rules.deny.length,
			ask: profile.rules.ask.length,
			skipReview: profile.rules.skipReview.length,
		},
	};
}

/** A stable hash of the effective configuration, for the record and for resume. */
export function configHash(profile: EffectiveProfile): string {
	// Keys are sorted so the hash depends on the configuration's content, not on
	// the order the fold happened to build the object in. The action hash in
	// canonical.ts was hardened this way for the same reason; this is stored in
	// every pending record and re-derived at resume, so a key-order change
	// between two versions must not read as a mismatch.
	return `sha256:${createHash("sha256").update(stableStringify(profile)).digest("hex")}`;
}

/** JSON with object keys sorted recursively, so serialization is order-independent. */
function stableStringify(value: unknown): string {
	const sort = (input: unknown): unknown => {
		if (Array.isArray(input)) return input.map(sort);
		if (input && typeof input === "object") {
			return Object.fromEntries(
				Object.entries(input as Record<string, unknown>)
					.sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
					.map(([key, entry]) => [key, sort(entry)]),
			);
		}
		return input;
	};
	return JSON.stringify(sort(value));
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
	/** What the head anchor says, when one was found. */
	anchor?: { seq: number; ts: string; retired?: { ts: string; reason: string } };
	/** Records after the anchor's seq: 1 is a crash between the two writes. */
	anchorBehind?: number;
}

export interface VerifyOptions {
	/** The head anchor to compare the end of the file against. Default: beside the log. */
	anchorPath?: string | false;
}

/**
 * Re-chain a log file and report the first break.
 *
 * A torn final line is reported separately from a broken chain, because they
 * mean different things: the first is a crash mid-write, which is expected and
 * harmless, and the second is an edit.
 *
 * The chain cannot see its own end, so the result is compared with the head
 * anchor: a log shorter than its anchor lost its newest records, and a log
 * whose newest record hashes differently had it replaced.
 */
export function verifyLog(path: string, options: VerifyOptions = {}): VerifyResult {
	const anchorPath = options.anchorPath === false ? undefined : (options.anchorPath ?? anchorPathFor(path));
	const anchor = anchorPath ? readAnchor(anchorPath) : undefined;
	const anchorInfo = anchor
		? { anchor: { seq: anchor.seq, ts: anchor.ts, ...(anchor.retired ? { retired: anchor.retired } : {}) } }
		: {};
	let text: string;
	try {
		text = readFileSync(path, "utf8");
	} catch (error) {
		if (anchor?.retired) {
			return { ok: true, records: 0, ...anchorInfo };
		}
		return { ok: false, records: 0, problem: `cannot read ${path}: ${(error as Error).message}`, ...anchorInfo };
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

	if (anchor && !anchor.retired) {
		const lastSeq = expectedSeq - 1;
		if (anchor.seq > lastSeq) {
			return {
				ok: false,
				records: count,
				brokenAt: lastSeq + 1,
				problem: `the log ends at seq ${lastSeq} but its head anchor recorded seq ${anchor.seq} at ${anchor.ts} -- the newest ${anchor.seq - lastSeq} record(s) were removed`,
				truncatedTail,
				...anchorInfo,
			};
		}
		if (anchor.seq === lastSeq && anchor.head !== expectedPrev) {
			return {
				ok: false,
				records: count,
				brokenAt: lastSeq,
				problem: "the newest record does not match its head anchor -- it was edited or replaced",
				truncatedTail,
				...anchorInfo,
			};
		}
		if (anchor.seq < lastSeq) {
			const behind = lastSeq - anchor.seq;
			// One is a crash between the record and its anchor. More means the
			// anchor stopped following the log: either its writes failed (the
			// session showed AUDIT FAILING) or the records came from elsewhere.
			if (behind === 1) return { ok: true, records: count, truncatedTail, ...anchorInfo, anchorBehind: behind };
			return {
				ok: false,
				records: count,
				brokenAt: anchor.seq + 1,
				problem: `${behind} records follow the head anchor's seq ${anchor.seq} -- they were appended by something other than pi-enclave, or the anchor could not be written`,
				truncatedTail,
				...anchorInfo,
				anchorBehind: behind,
			};
		}
	}

	return { ok: true, records: count, truncatedTail, ...anchorInfo };
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
	if (!result.anchor) {
		lines.push("  no head anchor: removing the newest records would not be detected");
	} else if (result.anchor.retired) {
		lines.push(`  retired by ${result.anchor.retired.reason} at ${result.anchor.retired.ts}`);
	} else if (result.ok) {
		lines.push(`  ends where its head anchor says (seq ${result.anchor.seq}, ${result.anchor.ts})`);
	}
	if (result.anchorBehind === 1) {
		lines.push("  one record after the anchor (a crash between writing the record and the anchor)");
	}
	return lines.join("\n");
}

export { createReadStream };
