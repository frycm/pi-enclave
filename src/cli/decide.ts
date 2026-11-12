/**
 * Answering a queued request (#30): the session that wrote it is still holding
 * the tool call open, so approval records the decision and the session runs
 * the call itself, in session, with the real result going back to the agent.
 *
 * The approver sees the same full action `approve` shows, and the same resume
 * checks run here first, so a request the session would refuse is refused
 * before anyone says yes to it. The session runs them again after the
 * decision; this pass only saves the person a decision that cannot take
 * effect.
 */
import type { EffectiveProfile } from "../config/types.ts";
import { describeRecordForApproval, type PendingRecord, readPending, transition } from "../escalate/pending.ts";
import { claimQueued, waiterAlive } from "../escalate/queue.ts";
import { checkResume, describeNarrowing, formatResumeFailure } from "../escalate/resume.ts";
import { boundedText, configHash } from "../state/audit.ts";
import { type ApproveIO, approverIdentity } from "./approve.ts";

export interface DecideOptions {
	record: PendingRecord;
	stateRoot: string;
	current: EffectiveProfile;
	home: string;
	io: ApproveIO;
	assumeYes?: boolean;
	now?: () => number;
	alive?: (pid: number) => boolean;
	/** An `approval` audit record; `false` means it is not on disk (audit.required). */
	audit?: (fields: Record<string, unknown>) => unknown;
	approver?: () => Record<string, unknown>;
	/** How long to wait for the session to pick the decision up, for the message only. */
	pickupMs?: number;
	pollMs?: number;
}

export type DecideResult =
	| { outcome: "approved"; ran: boolean }
	| { outcome: "declined" }
	| { outcome: "left" }
	| { outcome: "refused"; reason: string }
	/** The session stopped waiting; the record is an ordinary pending one now. */
	| { outcome: "not-waiting" };

function auditBase(options: DecideOptions) {
	const record = options.record;
	const command = record.action.tool === "bash" ? boundedText(record.action.input.command) : {};
	return {
		nonce: record.nonce,
		hash: record.action.hash,
		recordedConfigHash: record.configHash,
		originSession: record.sessionId,
		tool: record.action.tool,
		configHash: configHash(options.current),
		...(command.text !== undefined ? { command: command.text } : {}),
		...(command.truncated ? { commandTruncated: true } : {}),
		...(options.approver ?? approverIdentity)(),
	};
}

/** `pi-enclave approve <nonce>` for a request a live session is waiting on. */
export async function approveQueued(options: DecideOptions): Promise<DecideResult> {
	const { record, io, current } = options;
	const now = options.now ?? Date.now;
	io.out(describeRecordForApproval(record));
	io.out(`\nSession ${record.sessionId} is waiting for this until ${record.waiter?.until}.`);

	const narrowing = describeNarrowing(record, current);
	if (narrowing.length > 0) {
		io.out("\nThe configuration has narrowed since this was recorded:");
		for (const note of narrowing) io.out(`  ${note}`);
		io.out("  The waiting session runs under the configuration it started with, so it will refuse this.");
	}
	const check = checkResume({ record, current, home: options.home });
	if (!check.ok) {
		io.err(`\n${formatResumeFailure(check)}`);
		io.err("  The request stays queued; the session refuses it when it times out.");
		return { outcome: "refused", reason: check.reason };
	}

	if (!options.assumeYes) {
		const yes = await io.ask("\nLet the waiting session run this action now? [y/N] ");
		if (!yes) {
			io.out("Left queued. `pi-enclave decline` refuses it now.");
			return { outcome: "left" };
		}
	}
	// The prompt is unbounded: the session may have stopped waiting meanwhile.
	if (!waiterAlive(record, now(), options.alive)) {
		return notWaiting(io, record);
	}
	if (options.audit && (await options.audit({ ...auditBase(options), event: "queue-approved" })) === false) {
		const reason = "the audit log could not record this approval, and audit.required is set; nothing was decided";
		io.err(`\npi-enclave: ${reason}.`);
		return { outcome: "refused", reason };
	}
	if (!claimQueued(options.stateRoot, record.sessionId, record.nonce, "approved")) {
		return notWaiting(io, record);
	}
	io.out(`Approved. Session ${record.sessionId} runs it and continues.`);
	const ran = await pickedUp(options);
	if (!ran) {
		io.out(
			"The session has not taken it up yet. `pi-enclave pending --all` shows it as consumed once it has; " +
				"if the session refuses it, the record returns to pending and the reason is in its audit log.",
		);
	}
	return { outcome: "approved", ran };
}

function notWaiting(io: ApproveIO, record: PendingRecord): DecideResult {
	io.err(
		`\npi-enclave: session ${record.sessionId} is no longer waiting for this request. Nothing was decided.\n` +
			`  Run \`pi-enclave approve ${record.nonce}\` again to run it out of session.`,
	);
	return { outcome: "not-waiting" };
}

async function pickedUp(options: DecideOptions): Promise<boolean> {
	const limit = options.pickupMs ?? 5_000;
	const poll = options.pollMs ?? 100;
	const started = Date.now();
	for (;;) {
		const consumed = readPending({
			stateRoot: options.stateRoot,
			sessionId: options.record.sessionId,
			nonce: options.record.nonce,
			state: "consumed",
		});
		if (consumed.ok) return true;
		if (Date.now() - started >= limit) return false;
		await new Promise((resolve) => setTimeout(resolve, poll));
	}
}

/**
 * `pi-enclave decline <nonce>`: a person's no. A waiting session gets the same
 * denial an unanswered request gets; a pending record is retired, so it is not
 * approved later by mistake. Either way nothing runs.
 */
export async function decline(
	options: DecideOptions & { state: "queued" | "pending" },
): Promise<{ outcome: "declined" } | { outcome: "not-waiting" } | { outcome: "refused"; reason: string }> {
	const { record, io } = options;
	io.out(describeRecordForApproval(record));
	if (options.audit && (await options.audit({ ...auditBase(options), event: "declined" })) === false) {
		const reason = "the audit log could not record this decision, and audit.required is set; nothing was decided";
		io.err(`\npi-enclave: ${reason}.`);
		return { outcome: "refused", reason };
	}
	if (options.state === "queued") {
		if (!claimQueued(options.stateRoot, record.sessionId, record.nonce, "declined")) {
			io.err(`\npi-enclave: session ${record.sessionId} is no longer waiting for this request.`);
			return { outcome: "not-waiting" };
		}
		io.out(`Declined. Session ${record.sessionId} gets a refusal.`);
		return { outcome: "declined" };
	}
	transition(options.stateRoot, record.sessionId, record.nonce, "pending", "declined");
	io.out("Declined. The record will not be approved later.");
	return { outcome: "declined" };
}
