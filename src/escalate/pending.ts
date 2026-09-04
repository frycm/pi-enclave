/**
 * Pending-approval records.
 *
 * When an unattended session hits an `ask`, the turn is denied and a record is
 * written so a person can approve the exact action later and resume it. That
 * makes this file the one place where "what a human approved" is persisted,
 * which makes it an attack surface rather than a convenience: an agent that can
 * write one of these can manufacture its own approval.
 *
 * So it is never in the workspace, which the sandboxed agent can write. It
 * lives under pi-enclave's state directory, which is `0700`, in the default
 * `readDeny` list, and which `merge.ts` refuses to let any profile make
 * writable.
 *
 * **The record carries the full canonical action, not a hash.** A hash would
 * force the approver to trust whatever the agent put in the workspace to see
 * what they were approving. The whole point is that they read the action. The
 * hash is included too, and re-derived on resume, so the description and the
 * thing that runs cannot drift apart.
 *
 * **Writes are atomic.** `<nonce>.json.tmp`, fsync, rename. A half-written
 * record must never be observable, because a truncated JSON file that happens
 * to parse is the sort of thing that only fails once.
 */

import { randomBytes } from "node:crypto";
import {
	closeSync,
	fsyncSync,
	mkdirSync,
	openSync,
	readdirSync,
	readFileSync,
	renameSync,
	unlinkSync,
	writeFileSync,
} from "node:fs";
import { join } from "node:path";
import type { EffectiveProfile } from "../config/types.ts";
import {
	approvalSerialize,
	type CanonicalAction,
	type Capability,
	executionSerialize,
	inputFieldPreviews,
} from "../policy/canonical.ts";
import { checkSecureFile, ensureSecureDir } from "../state/dir.ts";

export const PENDING_VERSION = 1;
export const DEFAULT_TTL_MS = 24 * 60 * 60 * 1000;

/** The action, flattened to what survives JSON and is enough to re-derive the rest. */
export interface RecordedAction {
	tool: string;
	input: Record<string, unknown>;
	cwd: string;
	hash: string;
	profileName: string;
	capability?: Capability;
	/** For display. Re-derived on resume rather than trusted. */
	commands?: string[];
	paths?: { path: string; writes: boolean }[];
}

export interface PendingRecord {
	version: typeof PENDING_VERSION;
	nonce: string;
	createdAt: string;
	expiresAt: string;
	sessionId: string;
	sessionFile?: string;
	/** Hash of the effective configuration this was evaluated under. */
	configHash: string;
	/** The profile itself: evidence for the approver, and an upper bound on resume. */
	profileSnapshot: EffectiveProfile;
	/** Pi's independently observed sourceInfo.path for the registered tool. */
	toolSource?: string;
	action: RecordedAction;
	/** Why it needed a person. */
	reason: string;
	/** Set for a host-execution request, which no Phase-2 profile can grant. */
	requiresHuman?: boolean;
}

export type PendingState = "pending" | "approved" | "consumed";

export interface PendingStore {
	/** `<state>/state/<session-id>/`. */
	sessionDir: string;
}

export function pendingDirs(stateRoot: string, sessionId: string) {
	const sessionDir = join(stateRoot, sessionId);
	return {
		sessionDir,
		pending: join(sessionDir, "pending"),
		approved: join(sessionDir, "approved"),
		consumed: join(sessionDir, "consumed"),
	};
}

function dirFor(stateRoot: string, sessionId: string, state: PendingState): string {
	const dirs = pendingDirs(stateRoot, sessionId);
	return state === "pending" ? dirs.pending : state === "approved" ? dirs.approved : dirs.consumed;
}

export interface WriteOptions {
	stateRoot: string;
	sessionId: string;
	sessionFile?: string;
	action: CanonicalAction;
	profile: EffectiveProfile;
	configHash: string;
	reason: string;
	toolSource?: string;
	requiresHuman?: boolean;
	ttlMs?: number;
	now?: () => number;
	nonce?: string;
}

/** Write a record. Returns its path and nonce. */
export function writePending(options: WriteOptions): { path: string; record: PendingRecord } {
	const dirs = pendingDirs(options.stateRoot, options.sessionId);
	ensureSecureDir(dirs.sessionDir);
	ensureSecureDir(dirs.pending);

	const now = options.now?.() ?? Date.now();
	const nonce = options.nonce ?? randomBytes(16).toString("hex");
	const record: PendingRecord = {
		version: PENDING_VERSION,
		nonce,
		createdAt: new Date(now).toISOString(),
		expiresAt: new Date(now + (options.ttlMs ?? DEFAULT_TTL_MS)).toISOString(),
		sessionId: options.sessionId,
		configHash: options.configHash,
		profileSnapshot: options.profile,
		reason: options.reason,
		...(options.toolSource !== undefined ? { toolSource: options.toolSource } : {}),
		action: {
			tool: options.action.tool,
			input: options.action.input as Record<string, unknown>,
			cwd: options.action.cwd,
			hash: options.action.hash,
			profileName: options.action.profileName,
			...(options.action.capability ? { capability: options.action.capability } : {}),
			...(options.action.shell
				? { commands: options.action.shell.commands.map((command) => [command.name, ...command.args].join(" ")) }
				: {}),
			paths: options.action.paths.map((path) => ({ path: path.resolved, writes: path.writes })),
		},
		...(options.sessionFile !== undefined ? { sessionFile: options.sessionFile } : {}),
		...(options.requiresHuman ? { requiresHuman: true } : {}),
	};

	const path = join(dirs.pending, `${nonce}.json`);
	const tmp = `${path}.tmp`;
	// Use the same injective JSON spelling as the action hash. Native
	// JSON.stringify turns -0 into 0, which would make a freshly written record
	// fail its own resume hash check and misdescribe the approved input.
	writeFileSync(tmp, `${executionSerialize(record)}\n`, { mode: 0o600 });
	// fsync before rename: a rename is atomic with respect to *readers*, not
	// with respect to a power cut, and the point of the whole dance is that a
	// crash never leaves a half-written approval.
	const fd = openSync(tmp, "r");
	try {
		fsyncSync(fd);
	} finally {
		closeSync(fd);
	}
	renameSync(tmp, path);
	return { path, record };
}

export type ReadResult = { ok: true; record: PendingRecord; path: string } | { ok: false; reason: string };

export interface ReadOptions {
	stateRoot: string;
	sessionId: string;
	nonce: string;
	state?: PendingState;
	now?: () => number;
	/** Injected by tests. */
	checkFile?: (path: string) => string | undefined;
}

/**
 * Read and validate a record.
 *
 * Every check here is a way the record could have been tampered with, and each
 * failure is refused rather than repaired.
 */
export function readPending(options: ReadOptions): ReadResult {
	const dir = dirFor(options.stateRoot, options.sessionId, options.state ?? "pending");
	// The nonce is used as a filename, so it must not be able to escape the
	// directory. Anything but hex is refused outright rather than sanitized.
	if (!/^[0-9a-f]{32}$/.test(options.nonce)) return { ok: false, reason: "the nonce is not a 128-bit hex value" };
	const path = join(dir, `${options.nonce}.json`);

	const check = options.checkFile ?? ((p: string) => checkSecureFile(p));
	const problem = check(path);
	if (problem) return { ok: false, reason: problem };

	let record: PendingRecord;
	try {
		record = JSON.parse(readFileSync(path, "utf8")) as PendingRecord;
	} catch (error) {
		return { ok: false, reason: `cannot parse ${path}: ${(error as Error).message}` };
	}

	const invalid = validateRecord(record);
	if (invalid) return { ok: false, reason: invalid };

	// The nonce is in the body as well as the filename, so renaming a record
	// does not turn it into a different one.
	if (record.nonce !== options.nonce) {
		return { ok: false, reason: "the nonce inside the record does not match its filename" };
	}
	if (record.sessionId !== options.sessionId) {
		return { ok: false, reason: "the record belongs to a different session" };
	}

	const now = options.now?.() ?? Date.now();
	if (Date.parse(record.expiresAt) <= now) {
		// Deleted rather than left to accumulate: an expired approval request is
		// a decision nobody made, and keeping it invites approving it later
		// without the context that produced it.
		try {
			unlinkSync(path);
		} catch {
			// Best effort. The refusal below is the part that matters.
		}
		return { ok: false, reason: `the record expired at ${record.expiresAt} and has been deleted` };
	}

	return { ok: true, record, path };
}

function validateRecord(record: unknown): string | undefined {
	if (!record || typeof record !== "object") return "the record is not an object";
	const r = record as Partial<PendingRecord>;
	if (r.version !== PENDING_VERSION) return `unsupported record version ${String(r.version)}`;
	if (typeof r.nonce !== "string") return "the record has no nonce";
	if (typeof r.sessionId !== "string") return "the record has no session id";
	if (typeof r.expiresAt !== "string" || Number.isNaN(Date.parse(r.expiresAt))) return "the record has no valid expiry";
	if (typeof r.configHash !== "string") return "the record has no configuration hash";
	if (r.toolSource !== undefined && typeof r.toolSource !== "string") return "the record has an invalid tool source";
	if (!r.profileSnapshot || typeof r.profileSnapshot !== "object") return "the record has no profile snapshot";
	if (!r.action || typeof r.action !== "object") return "the record has no action";
	const action = r.action as Partial<RecordedAction>;
	if (typeof action.tool !== "string" || typeof action.hash !== "string" || typeof action.cwd !== "string") {
		return "the record's action is incomplete";
	}
	if (!action.input || typeof action.input !== "object") return "the record's action has no input";
	return undefined;
}

/**
 * Move a record between states.
 *
 * `pending → approved` happens *before* execution and `approved → consumed`
 * after, so a crash between them leaves visible evidence that something was
 * approved and may or may not have run -- which is the state a person needs to
 * be told about rather than one to resolve automatically.
 */
export function transition(
	stateRoot: string,
	sessionId: string,
	nonce: string,
	from: PendingState,
	to: PendingState,
): string {
	const target = dirFor(stateRoot, sessionId, to);
	mkdirSync(target, { recursive: true, mode: 0o700 });
	const source = join(dirFor(stateRoot, sessionId, from), `${nonce}.json`);
	const destination = join(target, `${nonce}.json`);
	renameSync(source, destination);
	return destination;
}

export interface ListedRecord {
	nonce: string;
	state: PendingState;
	record: PendingRecord;
}

/** Every record for a session, in every state. For `pi-enclave pending`. */
export function listPending(stateRoot: string, sessionId: string, now = Date.now()): ListedRecord[] {
	const out: ListedRecord[] = [];
	for (const state of ["pending", "approved", "consumed"] as PendingState[]) {
		const dir = dirFor(stateRoot, sessionId, state);
		let names: string[];
		try {
			names = readdirSync(dir);
		} catch {
			continue;
		}
		for (const name of names) {
			if (!name.endsWith(".json")) continue;
			const nonce = name.slice(0, -".json".length);
			const result = readPending({ stateRoot, sessionId, nonce, state, now: () => now });
			if (result.ok) out.push({ nonce, state, record: result.record });
		}
	}
	return out;
}

/** Every session that has records. */
export function listSessions(stateRoot: string): string[] {
	try {
		return readdirSync(stateRoot).filter((name) => !name.startsWith("."));
	} catch {
		return [];
	}
}

/** What the approver reads before deciding. The whole action, in full. */
export function describeRecord(record: PendingRecord): string {
	const text = (value: string) => approvalSerialize(value).slice(1, -1);
	const lines = [
		`nonce:    ${text(record.nonce)}`,
		`created:  ${text(record.createdAt)}`,
		`expires:  ${text(record.expiresAt)}`,
		`session:  ${text(record.sessionId)}`,
		`profile:  ${text(record.action.profileName)}`,
		`reason:   ${text(record.reason)}`,
		"",
		`${text(record.action.tool)} in ${text(record.action.cwd)}`,
	];
	for (const command of record.action.commands ?? []) lines.push(`    ${text(command)}`);
	for (const path of record.action.paths ?? [])
		lines.push(`    ${path.writes ? "writes" : "reads"} ${text(path.path)}`);
	for (const [field, preview] of inputFieldPreviews(record.action.input)) {
		lines.push(`    input.${field}: ${preview}`);
	}
	if (record.action.capability) {
		lines.push(`    requests ${record.action.capability.kind} access to ${text(record.action.capability.value)}`);
	}
	if (record.requiresHuman) {
		lines.push("", "This asked for unsandboxed host execution, which no profile in this version can grant.");
	}
	lines.push("", `hash: ${text(record.action.hash)}`);
	return lines.join("\n");
}

/**
 * Full-fidelity, terminal-safe evidence shown at the authorization boundary.
 *
 * The in-session pending list deliberately uses bounded/redacted previews: it
 * is agent-visible diagnostic output. The standalone approval CLI must instead
 * show the complete executor-consumed input before asking a person to run it.
 */
export function describeRecordForApproval(record: PendingRecord): string {
	const lines = [
		`nonce: ${approvalSerialize(record.nonce)}`,
		`created: ${approvalSerialize(record.createdAt)}`,
		`expires: ${approvalSerialize(record.expiresAt)}`,
		`session: ${approvalSerialize(record.sessionId)}`,
		`profile: ${approvalSerialize(record.action.profileName)}`,
		`reason: ${approvalSerialize(record.reason)}`,
		"",
		`tool: ${approvalSerialize(record.action.tool)}`,
		`cwd: ${approvalSerialize(record.action.cwd)}`,
		`input: ${approvalSerialize(record.action.input)}`,
	];
	for (const path of record.action.paths ?? []) {
		lines.push(`${path.writes ? "writes" : "reads"}: ${approvalSerialize(path.path)}`);
	}
	if (record.action.capability) {
		lines.push(`capability: ${approvalSerialize(record.action.capability)}`);
	}
	if (record.requiresHuman) {
		lines.push("", "This asked for unsandboxed host execution, which no profile in this version can grant.");
	}
	lines.push("", `hash: ${record.action.hash}`);
	return lines.join("\n");
}
