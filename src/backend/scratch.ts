/**
 * The per-session scratch directory the native sandbox points `TMPDIR` at.
 *
 * sandbox-runtime's default is the fixed path `/tmp/claude`, made writable in
 * every profile and created by whoever gets there first (#20). On a shared
 * host another account can pre-create it, as a directory it owns or as a
 * symlink, and read or replace every temp file the agent's commands write. It
 * is also shared by every session and every tool that uses the same default,
 * and nothing ever cleans it.
 *
 * Instead each backend gets its own directory, created by the trusted parent:
 *
 *     <parent>/pi-enclave-<uid>/session-<pid>-<random>
 *
 * `<parent>` is `$XDG_RUNTIME_DIR` when it is set (per-user, `0700`, cleared at
 * logout) and `/tmp` otherwise. The per-user base and the session directory
 * must both be real directories, not symlinks, owned by this uid and mode
 * `0700`; anything else refuses. Only the session directory is ever writable
 * inside the sandbox, so one session cannot reach another's files, and the
 * base cannot be populated by the agent.
 *
 * The directory is removed when the backend is disposed. Directories left by
 * a session that crashed are swept at the next start once their process is
 * gone.
 */
import { chmodSync, lstatSync, mkdirSync, mkdtempSync, readdirSync, realpathSync, rmSync, type Stats } from "node:fs";
import { isAbsolute, join } from "node:path";

export class ScratchDirError extends Error {
	constructor(message: string) {
		super(`pi-enclave: ${message}`);
		this.name = "ScratchDirError";
	}
}

/** The subset of `Stats` the checks read, so tests can inject an `lstat`. */
export type ScratchStat = Pick<Stats, "uid" | "mode" | "mtimeMs" | "isDirectory" | "isSymbolicLink">;
export type LstatFn = (path: string) => ScratchStat;

/** How old a dead session's directory must be before it is swept. */
export const STALE_SCRATCH_MIN_AGE_MS = 60 * 60 * 1000;

const SESSION_PREFIX = "session-";

/**
 * Where the per-user base lives. Derived from the environment and the uid
 * only, never from `TMPDIR`, which may name a broad or repository-chosen
 * directory.
 *
 * `$XDG_RUNTIME_DIR` is used only when it really is this user's private
 * runtime directory. A value inherited across `su` or `sudo` can name another
 * user's directory, or one that no longer exists; that falls back to `/tmp`
 * rather than refusing every session.
 */
export function scratchBase(
	env: Readonly<Record<string, string | undefined>> = process.env,
	uid: number | undefined = process.getuid?.(),
	lstat: LstatFn = lstatSync,
): string {
	const runtime = env.XDG_RUNTIME_DIR;
	const parent = runtime && isAbsolute(runtime) && isPrivateDir(runtime, uid, lstat) ? runtime : "/tmp";
	return join(parent, `pi-enclave-${uid ?? "user"}`);
}

function isPrivateDir(path: string, uid: number | undefined, lstat: LstatFn): boolean {
	try {
		verifyPrivateDir(path, { lstat, uid });
		return true;
	} catch {
		return false;
	}
}

/**
 * Require a real directory, owned by `uid`, mode `0700`.
 *
 * Unlike the state directory, a wrong mode is refused rather than repaired:
 * a scratch directory that was ever group- or world-accessible may already
 * hold someone else's files.
 */
export function verifyPrivateDir(path: string, options: { lstat?: LstatFn; uid?: number | undefined } = {}): void {
	const lstat = options.lstat ?? lstatSync;
	const uid = "uid" in options ? options.uid : process.getuid?.();
	let stats: ScratchStat;
	try {
		stats = lstat(path);
	} catch (error) {
		throw new ScratchDirError(`scratch directory ${path} cannot be inspected: ${(error as Error).message}`);
	}
	if (stats.isSymbolicLink()) {
		throw new ScratchDirError(`scratch directory ${path} is a symlink; refusing to point TMPDIR through it`);
	}
	if (!stats.isDirectory()) throw new ScratchDirError(`scratch directory ${path} exists and is not a directory`);
	if (uid !== undefined && stats.uid !== uid) {
		throw new ScratchDirError(`scratch directory ${path} is owned by uid ${stats.uid}, not by you (uid ${uid})`);
	}
	const mode = stats.mode & 0o777;
	if (mode !== 0o700) {
		throw new ScratchDirError(
			`scratch directory ${path} has mode ${mode.toString(8).padStart(3, "0")}; it must be 700, and is not repaired ` +
				"because files may already be in it. Remove it and start again.",
		);
	}
}

/**
 * Remove a tree the agent could write to, and never throw.
 *
 * `rmSync` alone fails on a directory the agent made unreadable or
 * unwritable (`chmod 000`, `chmod 555`), and a throw here would abort the
 * rest of shutdown. So a failed removal restores owner access on every real
 * directory below the path (never through a symlink, never on one owned by
 * someone else) and tries once more. Returns why the directory is still
 * there, or `undefined` when it is gone.
 *
 * Node has no `lchmod` on Linux, so a directory swapped for a symlink between
 * the `lstat` and the `chmod` would have the owner bits added to the link's
 * target instead. That only ever adds permissions for the user to a directory
 * they own, and the agent's processes are already stopped when this runs.
 */
export function removeTree(path: string, uid: number | undefined = process.getuid?.()): string | undefined {
	try {
		rmSync(path, { recursive: true, force: true });
		return undefined;
	} catch {
		// Fall through: restore access and retry.
	}
	try {
		restoreOwnerAccess(path, uid);
	} catch {
		// Best effort; the retry reports what is left.
	}
	try {
		rmSync(path, { recursive: true, force: true });
		return undefined;
	} catch (error) {
		return `could not remove scratch directory ${path}: ${(error as Error).message}`;
	}
}

function restoreOwnerAccess(root: string, uid: number | undefined): void {
	const stack = [root];
	let budget = 100_000;
	while (stack.length > 0 && budget-- > 0) {
		const path = stack.pop() as string;
		let stats: Stats;
		try {
			stats = lstatSync(path);
		} catch {
			continue;
		}
		if (stats.isSymbolicLink() || !stats.isDirectory()) continue;
		if (uid !== undefined && stats.uid !== uid) continue;
		if ((stats.mode & 0o700) !== 0o700) chmodSync(path, (stats.mode & 0o7777) | 0o700);
		let names: string[];
		try {
			names = readdirSync(path);
		} catch {
			continue;
		}
		for (const name of names) stack.push(join(path, name));
	}
}

/** Create the per-user base if absent, then verify it. */
function ensureBase(base: string, options: { lstat?: LstatFn; uid?: number | undefined }): void {
	try {
		mkdirSync(base, { mode: 0o700 });
		// Created by us just now, so tightening a umask-widened mode is safe.
		chmodSync(base, 0o700);
	} catch (error) {
		const code = (error as NodeJS.ErrnoException).code;
		if (code !== "EEXIST") {
			throw new ScratchDirError(`cannot create scratch directory ${base}: ${(error as Error).message}`);
		}
	}
	verifyPrivateDir(base, options);
}

function processIsAlive(pid: number): boolean {
	try {
		process.kill(pid, 0);
		return true;
	} catch (error) {
		// EPERM: the process exists but belongs to someone else.
		return (error as NodeJS.ErrnoException).code === "EPERM";
	}
}

/**
 * Remove session directories whose process has exited, and that have not
 * been touched for {@link STALE_SCRATCH_MIN_AGE_MS}. The age floor covers a
 * pid that is not visible from here (another PID namespace sharing the same
 * base) without deleting a live session's files at once.
 *
 * Best effort: a directory that cannot be removed is left for the next start.
 */
export function sweepStaleScratch(
	base: string,
	options: { isAlive?: (pid: number) => boolean; now?: number; lstat?: LstatFn } = {},
): string[] {
	const isAlive = options.isAlive ?? processIsAlive;
	const now = options.now ?? Date.now();
	const lstat = options.lstat ?? lstatSync;
	const removed: string[] = [];
	let entries: string[];
	try {
		entries = readdirSync(base);
	} catch {
		return removed;
	}
	for (const name of entries) {
		const match = /^session-(\d+)-/.exec(name);
		if (!match) continue;
		const pid = Number(match[1]);
		if (pid === process.pid || isAlive(pid)) continue;
		const path = join(base, name);
		try {
			const stats = lstat(path);
			if (!stats.isDirectory() || stats.isSymbolicLink()) continue;
			if (now - stats.mtimeMs < STALE_SCRATCH_MIN_AGE_MS) continue;
			if (removeTree(path) === undefined) removed.push(path);
		} catch {
			// Left for the next sweep.
		}
	}
	return removed;
}

/** One backend's scratch directory, from creation to removal. */
export class SessionScratch {
	private disposed = false;

	private constructor(
		/** Canonical path of the session directory. */
		readonly path: string,
		readonly base: string,
	) {}

	static create(
		options: { base?: string; uid?: number | undefined; lstat?: LstatFn; isAlive?: (pid: number) => boolean } = {},
	): SessionScratch {
		const uid = "uid" in options ? options.uid : process.getuid?.();
		const base = options.base ?? scratchBase(process.env, uid);
		const checks = { ...(options.lstat ? { lstat: options.lstat } : {}), uid };
		ensureBase(base, checks);
		sweepStaleScratch(base, {
			...(options.isAlive ? { isAlive: options.isAlive } : {}),
			...(options.lstat ? { lstat: options.lstat } : {}),
		});
		let created: string;
		try {
			created = mkdtempSync(join(base, `${SESSION_PREFIX}${process.pid}-`));
		} catch (error) {
			throw new ScratchDirError(`cannot create a session scratch directory in ${base}: ${(error as Error).message}`);
		}
		verifyPrivateDir(created, checks);
		return new SessionScratch(realpathSync(created), base);
	}

	/**
	 * Check the directory is still there and still private before a command
	 * is wrapped with it, repair its mode if the agent changed it, and
	 * recreate it at the same path if it has gone.
	 *
	 * `$XDG_RUNTIME_DIR` is removed at logout unless lingering is enabled, so a
	 * session left running in tmux can lose it. Recreating at the same path
	 * keeps the compiled profile valid; when the runtime directory itself is
	 * gone that is impossible, and the error says why.
	 */
	ensure(options: { uid?: number | undefined; lstat?: LstatFn } = {}): void {
		if (this.disposed) throw new ScratchDirError(`scratch directory ${this.path} was already removed`);
		const uid = "uid" in options ? options.uid : process.getuid?.();
		const checks = { ...(options.lstat ? { lstat: options.lstat } : {}), uid };
		const lstat = options.lstat ?? lstatSync;
		try {
			const stats = lstat(this.path);
			// The agent owns this directory and may chmod it; that must not stop
			// every later command. The base is still 0700 and still refused when
			// it is not, which is what keeps other users out, so the session
			// directory's own mode is repaired. A symlink, a non-directory or a
			// foreign owner is still refused below. The base is not writable from
			// the sandbox, so the directory cannot be swapped between the lstat
			// and the chmod.
			if (
				stats.isDirectory() &&
				!stats.isSymbolicLink() &&
				(uid === undefined || stats.uid === uid) &&
				(stats.mode & 0o777) !== 0o700
			) {
				chmodSync(this.path, 0o700);
			}
		} catch (error) {
			if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
			try {
				ensureBase(this.base, checks);
				mkdirSync(this.path, { mode: 0o700 });
				chmodSync(this.path, 0o700);
			} catch (cause) {
				throw new ScratchDirError(
					`the session scratch directory ${this.path} no longer exists and cannot be recreated ` +
						`(${(cause as Error).message}). If it was under $XDG_RUNTIME_DIR, that directory is removed at ` +
						"logout unless lingering is enabled (loginctl enable-linger); start a new session.",
				);
			}
		}
		verifyPrivateDir(this.base, checks);
		verifyPrivateDir(this.path, checks);
	}

	/**
	 * Remove the directory and everything the session left in it. Idempotent,
	 * and never throws: returns why removal failed, if it did.
	 */
	dispose(): string | undefined {
		if (this.disposed) return undefined;
		this.disposed = true;
		// rmSync never follows a symlink it finds inside the tree, so whatever
		// the agent left here cannot redirect the removal elsewhere.
		return removeTree(this.path);
	}
}
