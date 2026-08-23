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
import { SrtBackend } from "../backend/srt.ts";
import type { SandboxBackend } from "../backend/types.ts";
import { formatViolations } from "../backend/violations.ts";
import { toBackendProfile } from "../config/profile.ts";
import type { EffectiveProfile } from "../config/types.ts";
import { buildChildEnv } from "../env/child-env.ts";
import { describeRecord, type PendingRecord, transition } from "../escalate/pending.ts";
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
}

export type ApproveResult =
	| { outcome: "executed"; exitCode: number | null }
	| { outcome: "declined" }
	| { outcome: "refused"; reason: string }
	| { outcome: "unsupported"; reason: string };

export async function approve(options: ApproveOptions): Promise<ApproveResult> {
	const { record, io, current } = options;

	io.out(describeRecord(record));

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

	const tool = record.action.tool;
	if (tool !== "bash" && tool !== "write") {
		const reason =
			`only bash and write actions can be resumed from the command line; this is a "${tool}".\n` +
			"  Re-running an edit outside pi would risk applying a different edit from the one described above,\n" +
			"  which is exactly what the canonical hash exists to prevent. Re-run the task instead.";
		io.err(`\npi-enclave: ${reason}`);
		return { outcome: "unsupported", reason };
	}

	if (!options.assumeYes) {
		const yes = await io.ask("\nRun this action now? [y/N] ");
		if (!yes) {
			io.out("Left pending.");
			return { outcome: "declined" };
		}
	}

	// Renamed *before* execution, so a crash mid-run leaves the record in
	// approved/ rather than pending/ -- visible evidence that something was
	// approved and may have run, which is a state a person should be told about
	// rather than one that resolves itself.
	transition(options.stateRoot, record.sessionId, record.nonce, "pending", "approved");

	const backend = options.backend ?? new SrtBackend();
	try {
		const compiled = await backend.compile(toBackendProfile(current));

		if (tool === "bash") {
			const command = record.action.input.command;
			if (typeof command !== "string") return { outcome: "refused", reason: "the record has no command" };
			const result = await backend.run(compiled, {
				command,
				cwd: record.action.cwd,
				env: buildChildEnv(process.env, {
					passthrough: current.sandbox.env.passthrough,
					envDeny: current.sandbox.env.envDeny,
					readDeny: current.sandbox.readDeny,
				}),
				commandId: `enclave-approve-${record.nonce}`,
				onData: (chunk) => io.out(chunk.toString("utf8")),
			});
			if (result.violations.length > 0) io.err(formatViolations(result.violations));
			transition(options.stateRoot, record.sessionId, record.nonce, "approved", "consumed");
			return { outcome: "executed", exitCode: result.exitCode };
		}

		const path = record.action.input.path ?? record.action.input.filePath;
		const content = record.action.input.content;
		if (typeof path !== "string" || typeof content !== "string") {
			return { outcome: "refused", reason: "the record's write action has no path and content" };
		}
		const fs = backend.fs(compiled);
		await fs.writeFile(path, content);
		io.out(`wrote ${path}`);
		transition(options.stateRoot, record.sessionId, record.nonce, "approved", "consumed");
		return { outcome: "executed", exitCode: 0 };
	} finally {
		await backend.dispose();
	}
}
