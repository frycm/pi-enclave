/**
 * The approval queue (#30): a headless session that hits an `ask` holds the
 * tool call open while a person answers from another terminal, and then runs
 * the call itself, so the agent gets the real result and carries on.
 *
 * The decision travels through the session's record directory, which is in
 * pi-enclave's `0700` state directory and read-denied to the sandbox:
 *
 *     queued/<nonce>.json   written by the waiting session
 *       → approved/         `pi-enclave approve` while the session waits
 *       → declined/         `pi-enclave decline`
 *       → pending/          the session stopped waiting (timeout, abort)
 *     approved/ → consumed/ the session, after the resume checks, before running
 *
 * Every arrow out of `queued/` is one `rename`, so exactly one of them
 * happens: a person's decision and the session giving up cannot both win, and
 * the loser learns it from the rename failing. A record that went back to
 * `pending/` is an ordinary pending record, which `pi-enclave approve` runs out
 * of session as before.
 *
 * Approval here records a decision and nothing else. The session re-runs the
 * same checks `checkResume` applies to an out-of-session approval, against the
 * configuration as it is on disk now, and refuses if that configuration is not
 * the one the session is running under: it cannot run the call under a
 * narrower profile than its own, and nobody approved a wider one.
 */

import { existsSync } from "node:fs";
import { join } from "node:path";
import type { EffectiveProfile } from "../config/types.ts";
import type { CanonicalAction } from "../policy/canonical.ts";
import { configHash } from "../state/audit.ts";
import type { EscalationOutcome } from "./confirm.ts";
import { dirFor, type PendingRecord, readPending, transition, writePending } from "./pending.ts";
import { checkResume } from "./resume.ts";

export type QueueOutcome = "approved" | "declined" | "timeout" | "aborted";

/**
 * Move a queued record out of `queued/`, if it is still there. `false` means
 * another party moved it first, which is how a losing side finds out.
 */
export function claimQueued(
	stateRoot: string,
	sessionId: string,
	nonce: string,
	to: "approved" | "declined" | "pending",
): boolean {
	try {
		transition(stateRoot, sessionId, nonce, "queued", to);
		return true;
	} catch (error) {
		if ((error as NodeJS.ErrnoException).code === "ENOENT") return false;
		throw error;
	}
}

/** True when the process can be signalled, or exists under another user. */
export function processAlive(pid: number): boolean {
	try {
		process.kill(pid, 0);
		return true;
	} catch (error) {
		return (error as NodeJS.ErrnoException).code === "EPERM";
	}
}

/**
 * Whether a queued record's session is still waiting for it. A reused pid can
 * make a dead session look alive; its `until` still bounds how long.
 */
export function waiterAlive(
	record: PendingRecord,
	now = Date.now(),
	alive: (pid: number) => boolean = processAlive,
): boolean {
	if (!record.waiter) return false;
	return Date.parse(record.waiter.until) > now && alive(record.waiter.pid);
}

export interface WaitOptions {
	stateRoot: string;
	sessionId: string;
	nonce: string;
	/** Epoch ms at which the session stops waiting. */
	until: number;
	signal?: AbortSignal;
	pollMs?: number;
	now?: () => number;
}

/**
 * Wait for a person's decision on a queued record.
 *
 * Polls rather than watches: `fs.watch` is unreliable on the network and
 * overlay file systems a state directory can sit on, and a quarter-second
 * poll of two `stat`s costs nothing next to a person typing.
 */
export async function waitForDecision(options: WaitOptions): Promise<QueueOutcome> {
	const now = options.now ?? Date.now;
	const pollMs = options.pollMs ?? 250;
	const at = (state: "approved" | "declined" | "queued") =>
		existsSync(join(dirFor(options.stateRoot, options.sessionId, state), `${options.nonce}.json`));

	for (;;) {
		if (at("approved")) return "approved";
		if (at("declined")) return "declined";
		const aborted = options.signal?.aborted === true;
		if (aborted || now() >= options.until) {
			// Give up by moving the record back to pending, where it can still be
			// approved and run out of session. If that rename loses, a decision
			// landed in the same moment, and the next pass reads it.
			if (claimQueued(options.stateRoot, options.sessionId, options.nonce, "pending")) {
				return aborted ? "aborted" : "timeout";
			}
			if (!at("approved") && !at("declined") && !at("queued")) return "declined";
			// Never spin: whatever state this is, the next pass reads it after a tick.
			await sleep(1);
			continue;
		}
		if (!at("queued")) {
			// Neither decided nor queued: removed, or moved back to pending by
			// someone else. Nothing a person approved, so a refusal.
			if (!at("approved") && !at("declined")) return "declined";
			await sleep(1);
			continue;
		}
		await sleep(Math.min(pollMs, Math.max(1, options.until - now())), options.signal);
	}
}

function sleep(ms: number, signal?: AbortSignal): Promise<void> {
	return new Promise((resolve) => {
		const timer = setTimeout(done, ms);
		function done() {
			clearTimeout(timer);
			signal?.removeEventListener("abort", done);
			resolve();
		}
		signal?.addEventListener("abort", done, { once: true });
	});
}

export interface QueueEscalationDeps {
	stateRoot: () => string;
	sessionId: () => string | undefined;
	sessionFile?: () => string | undefined;
	/** The profile the session runs under. */
	profile: () => EffectiveProfile | undefined;
	/** The configuration as it is on disk now, folded the way session start folds it. */
	reload: () => EffectiveProfile | undefined;
	home: string;
	timeoutMs: () => number;
	/** The current turn's abort signal: an aborted turn stops waiting. */
	signal?: () => AbortSignal | undefined;
	/** Every event here is a `pending` lifecycle record. */
	audit?: (kind: "pending", fields: Record<string, unknown>) => void;
	/** Called once the record is on disk, so a person can be told. */
	onQueued?: (record: PendingRecord, path: string) => void;
	stderr?: (text: string) => void;
	pid?: number;
	pollMs?: number;
	now?: () => number;
}

/**
 * The session side: write the record, hold the call, and on approval check it
 * again before letting the gate run it. Returns the escalation outcome; only
 * `approved` lets the call run.
 */
export function createQueueEscalation(deps: QueueEscalationDeps) {
	const now = deps.now ?? Date.now;
	const stderr = deps.stderr ?? ((text: string) => process.stderr.write(text));
	return async (action: CanonicalAction, reason: string, toolSource?: string): Promise<EscalationOutcome> => {
		const profile = deps.profile();
		const sessionId = deps.sessionId();
		if (!profile || !sessionId) {
			deps.audit?.("pending", { event: "write-skipped", hash: action.hash, reason: "no session" });
			stderr("pi-enclave: an action needed approval but no record could be written (no active session).\n");
			return "unattended";
		}
		const stateRoot = deps.stateRoot();
		const until = now() + deps.timeoutMs();
		let written: ReturnType<typeof writePending>;
		try {
			const sessionFile = deps.sessionFile?.();
			written = writePending({
				stateRoot,
				sessionId,
				...(sessionFile !== undefined ? { sessionFile } : {}),
				action,
				profile,
				configHash: configHash(profile),
				reason,
				...(toolSource !== undefined ? { toolSource } : {}),
				waiter: { pid: deps.pid ?? process.pid, until: new Date(until).toISOString() },
				now,
			});
		} catch (error) {
			deps.audit?.("pending", { event: "write-failed", hash: action.hash, error: (error as Error).message });
			stderr(`pi-enclave: could not write the approval record: ${(error as Error).message}\n`);
			return "unattended";
		}
		const { record, path } = written;
		const nonce = record.nonce;
		deps.audit?.("pending", { event: "queued", nonce, hash: action.hash, path, until: record.waiter?.until });
		stderr(
			`pi-enclave: an action needs approval; this session waits until ${record.waiter?.until} for:\n` +
				`  pi-enclave approve ${nonce}\n  pi-enclave decline ${nonce}\n`,
		);
		deps.onQueued?.(record, path);

		const signal = deps.signal?.();
		const outcome = await waitForDecision({
			stateRoot,
			sessionId,
			nonce,
			until,
			...(signal ? { signal } : {}),
			...(deps.pollMs !== undefined ? { pollMs: deps.pollMs } : {}),
			now,
		});
		deps.audit?.("pending", { event: `queue-${outcome}`, nonce, hash: action.hash });
		if (outcome === "declined") return "declined";
		if (outcome !== "approved") {
			stderr(
				`pi-enclave: no decision on ${nonce} in time; it is pending, and \`pi-enclave approve ${nonce}\` runs it out of session.\n`,
			);
			return "timeout";
		}

		const refusal = resumeInSession(deps, stateRoot, sessionId, nonce, action, profile);
		if (refusal) {
			// Nothing ran. Back to pending, so the record is not read as "may
			// have run", with the reason in the trail and on stderr.
			try {
				transition(stateRoot, sessionId, nonce, "approved", "pending");
			} catch {
				// Already gone; the refusal stands either way.
			}
			deps.audit?.("pending", { event: "resume-refused", nonce, hash: action.hash, reason: refusal });
			stderr(`pi-enclave: approved, but not run: ${refusal}\n`);
			return "declined";
		}
		deps.audit?.("pending", { event: "resumed", nonce, hash: action.hash });
		return "approved";
	};
}

/** The checks between an in-session approval and the run. A reason means no. */
function resumeInSession(
	deps: QueueEscalationDeps,
	stateRoot: string,
	sessionId: string,
	nonce: string,
	action: CanonicalAction,
	profile: EffectiveProfile,
): string | undefined {
	const read = readPending({ stateRoot, sessionId, nonce, state: "approved", ...(deps.now ? { now: deps.now } : {}) });
	if (!read.ok) return read.reason;
	// The record approved is the one this call wrote: same action, same hash.
	if (read.record.action.hash !== action.hash) return "the approved record is not the action this call is holding";
	let current: EffectiveProfile | undefined;
	try {
		current = deps.reload();
	} catch (error) {
		return `the configuration could not be reloaded: ${(error as Error).message}`;
	}
	if (!current) return "the configuration could not be reloaded";
	const check = checkResume({ record: read.record, current, home: deps.home });
	if (!check.ok) return [check.reason, ...(check.detail ?? [])].join("; ");
	if (configHash(current) !== configHash(profile)) {
		return "the configuration changed while this call waited; the session runs under the configuration it started with, so re-run the task";
	}
	try {
		// One decision, one run: out of approved/ before the call is let through.
		transition(stateRoot, sessionId, nonce, "approved", "consumed");
	} catch (error) {
		return `the record could not be consumed: ${(error as Error).message}`;
	}
	return undefined;
}
