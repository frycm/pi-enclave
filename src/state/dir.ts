/**
 * pi-enclave's own directory, and the checks that make it worth trusting.
 *
 * Everything security-relevant that outlives a tool call lives here: the audit
 * log, the pending approval records, and the attendance secret. It is
 * deliberately **not** in the workspace, because the sandboxed agent can write
 * the workspace, and the one thing an agent must not be able to forge is the
 * evidence of its own approval.
 *
 * Three checks on every open, and each one is a real attack rather than
 * defensive habit:
 *
 * - **Mode.** A `0755` state directory is one any local process can write.
 * - **Owner.** A directory owned by someone else is one someone else controls;
 *   inheriting it silently would be the whole game.
 * - **Not a symlink.** A symlinked state directory redirects every subsequent
 *   write, and the redirection is invisible in every path this code prints.
 *
 * The default `readDeny` list also contains this directory, so the sandboxed
 * agent cannot read what it cannot write, and `merge.ts` refuses any profile
 * that would make it writable.
 */
import { chmodSync, existsSync, lstatSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { getAgentDir } from "@earendil-works/pi-coding-agent";
import { enclaveStateDir } from "../config/defaults.ts";

export class StateDirError extends Error {
	constructor(message: string) {
		super(`pi-enclave: ${message}`);
		this.name = "StateDirError";
	}
}

export interface StateDirs {
	root: string;
	audit: string;
	/** Per-session pending approval records live under here. */
	state: string;
	/** Reviewer qualification records, outside every workspace. */
	qualified: string;
	attendSecret: string;
}

export function stateDirs(agentDir = getAgentDir()): StateDirs {
	const root = enclaveStateDir(agentDir);
	return {
		root,
		audit: join(root, "audit"),
		state: join(root, "state"),
		qualified: join(root, "qualified"),
		attendSecret: join(root, "attend.secret"),
	};
}

/**
 * Create a directory `0700` and verify it, or throw.
 *
 * `mkdir` with a mode is not enough on its own: the mode is masked by `umask`,
 * and an existing directory keeps whatever mode it already had. So it is
 * created, then chmodded, then checked -- and the check is what the rest of the
 * code relies on.
 */
export function ensureSecureDir(path: string, uid = process.getuid?.()): void {
	if (!existsSync(path)) {
		mkdirSync(path, { recursive: true, mode: 0o700 });
	}
	// lstat, never stat: the question is what this path *is*, not what it
	// points at.
	const stats = lstatSync(path);

	if (stats.isSymbolicLink()) {
		throw new StateDirError(
			`${path} is a symlink. It holds approval records and the attendance secret, and a symlink redirects every write.`,
		);
	}
	if (!stats.isDirectory()) {
		throw new StateDirError(`${path} exists and is not a directory.`);
	}
	if (uid !== undefined && stats.uid !== uid) {
		throw new StateDirError(`${path} is owned by uid ${stats.uid}, not by you (uid ${uid}).`);
	}

	const mode = stats.mode & 0o777;
	if (mode !== 0o700) {
		// Repair rather than refuse: an over-permissive mode is usually a umask
		// or a restore from a backup, and refusing to start is a worse answer
		// than tightening it. A wrong *owner* is not repairable and is refused.
		chmodSync(path, 0o700);
		const after = lstatSync(path).mode & 0o777;
		if (after !== 0o700) {
			throw new StateDirError(`${path} has mode ${mode.toString(8)} and could not be tightened to 700.`);
		}
	}
}

/** Prepare every directory pi-enclave writes to. Called once at session start. */
export function ensureStateDirs(agentDir = getAgentDir()): StateDirs {
	const dirs = stateDirs(agentDir);
	ensureSecureDir(dirs.root);
	ensureSecureDir(dirs.audit);
	ensureSecureDir(dirs.state);
	ensureSecureDir(dirs.qualified);
	return dirs;
}

/**
 * Verify a file pi-enclave wrote is still one it should read.
 *
 * The same three questions as the directory, plus the mode a secret needs.
 * Returns the reason it is unacceptable, or undefined.
 */
export function checkSecureFile(path: string, expectedMode = 0o600, uid = process.getuid?.()): string | undefined {
	let stats: ReturnType<typeof lstatSync>;
	try {
		stats = lstatSync(path);
	} catch {
		return `${path} does not exist`;
	}
	if (stats.isSymbolicLink()) return `${path} is a symlink`;
	if (!stats.isFile()) return `${path} is not a regular file`;
	if (uid !== undefined && stats.uid !== uid) return `${path} is owned by uid ${stats.uid}, not by you`;
	const mode = stats.mode & 0o777;
	// Refused rather than repaired: unlike a directory, a file with the wrong
	// mode may already have been read by whoever could reach it, so quietly
	// tightening it would hide that.
	if (mode !== expectedMode) return `${path} has mode ${mode.toString(8)}, expected ${expectedMode.toString(8)}`;
	return undefined;
}
