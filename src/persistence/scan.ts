/**
 * Bounded, trusted-parent walks of the writable roots.
 *
 * Several things a later, unsandboxed process loads can be created anywhere in
 * a writable root: a nested Git repository whose `config` names an fsmonitor
 * (#33), a nested `.pi` directory (#19). The kernel profile can only protect
 * paths that exist when it is compiled, so the parent has to find them first,
 * and look again afterwards for ones the agent created.
 *
 * Both walks run in the trusted parent, never run anything found in the tree,
 * and never follow a symlink. They are bounded: a tree too large to walk is a
 * refusal, not a partial answer, because a partial answer is exactly what an
 * agent that wants to hide something would arrange.
 */
import {
	accessSync,
	constants,
	type Dirent,
	lstatSync,
	readdirSync,
	readlinkSync,
	realpathSync,
	type Stats,
} from "node:fs";
import { join } from "node:path";
import { isUnder } from "../backend/paths.ts";

/**
 * How many directory entries one walk may visit before it refuses. A warm walk
 * costs about a microsecond per entry, so this is about half a second; a
 * workspace this large should name a narrower writable root.
 */
export const MAX_SCAN_ENTRIES = 500_000;

export class PersistenceScanError extends Error {
	constructor(message: string) {
		super(`pi-enclave: ${message}`);
		this.name = "PersistenceScanError";
	}
}

export type EntryKind = "dir" | "file" | "symlink" | "other";

export interface ScanMatch {
	path: string;
	kind: EntryKind;
}

export interface ScanOptions {
	/** Whether an entry is one the caller is looking for. */
	match(name: string, kind: EntryKind, path: string): boolean;
	/**
	 * Whether a directory is one the caller is looking for, judged by what it
	 * contains. Called once per listed directory, roots included; a match is
	 * still walked.
	 */
	matchListing?(dir: string, entries: readonly Dirent[]): boolean;
	/** Look inside a matched directory too. Off by default. */
	descendIntoMatches?: boolean;
	maxEntries?: number;
	/**
	 * Receives each directory skipped because nobody running as this user can
	 * reach inside it (see {@link isOutOfReach}), so the caller can say so.
	 */
	unscanned?: string[];
}

function kindOf(entry: Dirent | Stats): EntryKind {
	if (entry.isSymbolicLink()) return "symlink";
	if (entry.isDirectory()) return "dir";
	if (entry.isFile()) return "file";
	return "other";
}

/**
 * Canonical, existing, non-overlapping roots: a root inside another is walked
 * as part of the outer one, not twice.
 */
export function walkableRoots(roots: readonly string[]): string[] {
	const resolved: string[] = [];
	for (const root of roots) {
		try {
			resolved.push(realpathSync(root));
		} catch (error) {
			// A writable root that does not exist yet holds nothing to find.
			if ((error as NodeJS.ErrnoException).code === "ENOENT") continue;
			throw new PersistenceScanError(`cannot resolve writable root ${root}: ${(error as Error).message}`);
		}
	}
	const unique = [...new Set(resolved)].sort((a, b) => a.length - b.length);
	return unique.filter((root, index) => !unique.slice(0, index).some((outer) => isUnder(root, outer)));
}

/**
 * Whether a directory that could not be listed holds nothing this user can
 * reach: owned by another account, and without search permission for us.
 *
 * Then neither the sandboxed agent nor Git run later by the user can open,
 * create or run anything inside it, so it cannot hide a persistence path from
 * them either. A database volume (`pgdata/`, owned by the database's uid with
 * mode 0700) is the common case. A directory we own, or one we can search but
 * not list, is the opposite: that is what an agent hiding something would
 * arrange, so the walk still refuses it.
 */
function isOutOfReach(dir: string): boolean {
	let stats: Stats;
	try {
		stats = lstatSync(dir);
	} catch {
		return false;
	}
	if (!stats.isDirectory() || stats.uid === process.getuid?.()) return false;
	try {
		accessSync(dir, constants.X_OK);
		return false;
	} catch (error) {
		const code = (error as NodeJS.ErrnoException).code;
		return code === "EACCES" || code === "EPERM";
	}
}

/**
 * Every entry under `roots` that `match` accepts. Symlinks are reported when
 * they match, and never followed.
 */
export function scanRoots(roots: readonly string[], options: ScanOptions): ScanMatch[] {
	const limit = options.maxEntries ?? MAX_SCAN_ENTRIES;
	const found: ScanMatch[] = [];
	let visited = 0;
	for (const root of walkableRoots(roots)) {
		const stack = [root];
		while (stack.length > 0) {
			const dir = stack.pop() as string;
			let entries: Dirent[];
			try {
				entries = readdirSync(dir, { withFileTypes: true });
			} catch (error) {
				const code = (error as NodeJS.ErrnoException).code;
				// Removed while we walked: nothing left to find there.
				if (code === "ENOENT" || code === "ENOTDIR") continue;
				if ((code === "EACCES" || code === "EPERM") && isOutOfReach(dir)) {
					options.unscanned?.push(dir);
					continue;
				}
				// Anything else is a directory we cannot see into, and so cannot
				// vouch for.
				throw new PersistenceScanError(`cannot inspect ${dir}: ${(error as Error).message}`);
			}
			if (options.matchListing?.(dir, entries)) found.push({ path: dir, kind: "dir" });
			for (const entry of entries) {
				visited++;
				if (visited > limit) {
					throw new PersistenceScanError(
						`the writable roots hold more than ${limit} entries, too many to check for persistence paths; ` +
							"configure a narrower sandbox.writableRoots",
					);
				}
				const path = join(dir, entry.name);
				const kind = kindOf(entry);
				const matched = options.match(entry.name, kind, path);
				if (matched) found.push({ path, kind });
				if (kind === "dir" && (!matched || options.descendIntoMatches)) stack.push(path);
			}
		}
	}
	return found;
}

/** Shared budget for {@link fingerprint}, so one call cannot walk without end. */
export interface FingerprintBudget {
	remaining: number;
}

/**
 * A string that changes whenever the entry at `path` does: its type, inode,
 * size, modification and change times, and for a directory every entry below
 * it. `ctime` cannot be set from user space, so restoring a file's old `mtime`
 * after editing it still changes the fingerprint. `undefined` means absent.
 */
export function fingerprint(path: string, budget: FingerprintBudget = { remaining: 4096 }): string | undefined {
	let stats: Stats;
	try {
		stats = lstatSync(path);
	} catch (error) {
		if ((error as NodeJS.ErrnoException).code === "ENOENT") return undefined;
		throw new PersistenceScanError(`cannot inspect ${path}: ${(error as Error).message}`);
	}
	budget.remaining--;
	if (budget.remaining < 0) throw new PersistenceScanError(`too many entries to fingerprint below ${path}`);
	const kind = kindOf(stats);
	const head = `${kind}:${stats.ino}:${stats.mode}:${stats.ctimeMs}`;
	if (kind === "symlink") return `${head}:${readlinkSync(path)}`;
	if (kind !== "dir") return `${head}:${stats.size}:${stats.mtimeMs}`;
	const children = readdirSync(path).sort();
	return `${head}[${children.map((name) => `${name}=${fingerprint(join(path, name), budget)}`).join(",")}]`;
}
