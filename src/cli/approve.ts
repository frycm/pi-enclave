/**
 * Approving a pending record, out of session.
 *
 * The interesting decision here is what "approve" *is*. It is not a flag on a
 * file that some later session notices: nothing would pick that up, and a
 * record that says "approved" while nothing happens is worse than no feature.
 * It executes the action, once, under the profile that is in force **now**,
 * through the same sandbox a session would have used.
 *
 * Which means this file needs a backend, and that is the whole reason it exists
 * separately from `resume.ts`: the checks are pure and testable on their own,
 * and the execution is the part that needs a compiled profile and a real
 * process.
 *
 * **Known limitation, stated rather than worked around.** Only `bash` and
 * `write` actions can be executed from here. `edit` would mean reimplementing
 * pi's string-replacement semantics outside pi, and an approval that applied a
 * *slightly different* edit from the one that was described would be exactly
 * the failure the canonical hash exists to prevent. An `edit` record is
 * refused with that explanation and left pending, so the user re-runs the task
 * with the rule relaxed instead.
 */
import { isAbsolute, resolve } from "node:path";
import { shellWriteCapabilityIssue, validateWriteCapability } from "../backend/capability.ts";
import { SrtBackend } from "../backend/srt.ts";
import type { SandboxBackend } from "../backend/types.ts";
import { formatViolations } from "../backend/violations.ts";
import { toBackendProfile } from "../config/profile.ts";
import type { EffectiveProfile } from "../config/types.ts";
import { buildChildEnv } from "../env/child-env.ts";
import { describeRecordForApproval, type PendingRecord, transition } from "../escalate/pending.ts";
import { checkResume, describeNarrowing, formatResumeFailure } from "../escalate/resume.ts";

export interface ApproveIO {
	out: (text: string) => void;
	err: (text: string) => void;
	/** Asks in *this* terminal. There is no way to approve by editing the file. */
	ask: (question: string) => Promise<boolean>;
}

export interface ApproveOptions {
	record: PendingRecord;
	stateRoot: string;
	current: EffectiveProfile;
	home: string;
	io: ApproveIO;
	/** Injected by tests. */
	backend?: SandboxBackend;
	/** Skip the interactive question. Only for a caller that already asked. */
	assumeYes?: boolean;
	/** Trusted clock, injected by expiry tests. */
	now?: () => number;
	/** Host platform, injected only by cross-platform refusal tests. */
	platform?: NodeJS.Platform;
}

export type ApproveResult =
	| { outcome: "executed"; exitCode: number | null }
	| { outcome: "declined" }
	| { outcome: "refused"; reason: string }
	| { outcome: "unsupported"; reason: string };

export async function approve(options: ApproveOptions): Promise<ApproveResult> {
	const { record, io, current } = options;
	const expired = () => Date.parse(record.expiresAt) <= (options.now?.() ?? Date.now());
	const expiredResult = (): ApproveResult => ({
		outcome: "refused",
		reason: `the approval record expired at ${record.expiresAt} before execution`,
	});

	io.out(describeRecordForApproval(record));

	const narrowing = describeNarrowing(record, current);
	if (narrowing.length > 0) {
		// Shown before the question, not after: it changes what the person is
		// agreeing to.
		io.out("\nThe configuration has narrowed since this was recorded:");
		for (const note of narrowing) io.out(`  ${note}`);
		io.out("  It will run under the configuration you have now, not the one above.");
	}

	const check = checkResume({ record, current, home: options.home });
	if (!check.ok) {
		io.err(`\n${formatResumeFailure(check)}`);
		io.err("  The record is left pending.");
		return { outcome: "refused", reason: check.reason };
	}

	const { action } = check;
	const tool = action.tool;
	if (tool !== "bash" && tool !== "write") {
		const reason =
			`only bash and write actions can be resumed from the command line; this is a "${tool}".\n` +
			"  Re-running an edit outside pi would risk applying a different edit from the one described above,\n" +
			"  which is exactly what the canonical hash exists to prevent. Re-run the task instead.";
		io.err(`\npi-enclave: ${reason}`);
		return { outcome: "unsupported", reason };
	}
	const capability = action.capability;
	if (capability && capability.kind !== "write") {
		const reason = `${capability.kind} capabilities are Phase 3/4; only a one-shot write can be approved in this version.`;
		io.err(`\npi-enclave: ${reason}`);
		return { outcome: "unsupported", reason };
	}
	const backendProfile = toBackendProfile(current, action.cwd);
	let capabilityTarget: string | undefined;
	if (capability) {
		try {
			const lifetimeIssue = tool === "bash" ? shellWriteCapabilityIssue(options.platform) : undefined;
			if (lifetimeIssue) throw new Error(lifetimeIssue);
			capabilityTarget = validateWriteCapability(backendProfile, action.cwd, capability.value);
		} catch (error) {
			const reason = (error as Error).message;
			io.err(`\n${reason}`);
			io.err("  The record is left pending.");
			return { outcome: "refused", reason };
		}
	}

	if (!options.assumeYes) {
		const yes = await io.ask("\nRun this action now? [y/N] ");
		if (!yes) {
			io.out("Left pending.");
			return { outcome: "declined" };
		}
	}
	// The prompt is intentionally unbounded. Freshness therefore has to be
	// checked after the answer, not only when the record was opened.
	if (expired()) {
		io.err(`\npi-enclave: the approval record expired at ${record.expiresAt}; nothing ran.`);
		return expiredResult();
	}

	// Renamed *before* execution, so a crash mid-run leaves the record in
	// approved/ rather than pending/ -- visible evidence that something was
	// approved and may have run, which is a state a person should be told about
	// rather than one that resolves itself.
	transition(options.stateRoot, record.sessionId, record.nonce, "pending", "approved");

	const backend = options.backend ?? new SrtBackend();
	try {
		// A pending capability request exists because its target is *outside* the
		// current writable roots -- that is why it was escalated. Compiling the
		// unextended profile would reach the same denial, so the approved
		// capability is folded into a one-shot profile here. It is bound to the
		// action hash (which includes the capability), and checkResume above
		// re-derived that hash, so the extension can only be the one approved.
		if (capabilityTarget) {
			backendProfile.writableRoots = [...backendProfile.writableRoots, capabilityTarget];
		}
		const compiled = await backend.compile(backendProfile);
		// Compilation can take long enough to cross the TTL too. An approved/
		// record is retained as crash-safe evidence, but no action executes.
		if (expired()) {
			io.err(`\npi-enclave: the approval record expired at ${record.expiresAt} while preparing; nothing ran.`);
			return expiredResult();
		}

		if (tool === "bash") {
			const command = action.input.command;
			if (typeof command !== "string") return { outcome: "refused", reason: "the record has no command" };
			const result = await backend.run(compiled, {
				command,
				cwd: action.cwd,
				env: buildChildEnv(process.env, {
					passthrough: current.sandbox.env.passthrough,
					envDeny: current.sandbox.env.envDeny,
					readDeny: current.sandbox.readDeny,
					writableRoots: compiled.profile.writableRoots,
				}),
				commandId: `enclave-approve-${record.nonce}`,
				onData: (chunk) => io.out(chunk.toString("utf8")),
			});
			if (result.violations.length > 0) io.err(formatViolations(result.violations));
			transition(options.stateRoot, record.sessionId, record.nonce, "approved", "consumed");
			return { outcome: "executed", exitCode: result.exitCode };
		}

		// All three keys canonicalize accepts, so a record hashed under `file_path`
		// (which pi's write tool uses) is not a dead end at approve time.
		const rawPath = action.input.path ?? action.input.filePath ?? action.input.file_path;
		const content = action.input.content;
		if (typeof rawPath !== "string" || typeof content !== "string") {
			return { outcome: "refused", reason: "the record's write action has no path and content" };
		}
		// Resolved against the *session's* cwd, not this CLI process's. The helper
		// resolves a relative path against its own working directory, so a record
		// of `notes.txt` from /project would otherwise be written wherever the
		// approver happened to run the command -- the approver read "/project/notes.txt".
		const path = isAbsolute(rawPath) ? rawPath : resolve(action.cwd, rawPath);
		const fs = backend.fs(compiled);
		await fs.writeFile(path, content);
		io.out(`wrote ${path}`);
		transition(options.stateRoot, record.sessionId, record.nonce, "approved", "consumed");
		return { outcome: "executed", exitCode: 0 };
	} finally {
		await backend.dispose();
	}
}
