/**
 * Write-deny for a command nobody judged (#64).
 *
 * Since #18 a bash command L1 cannot read can run without a person: under
 * `rules.onUncertain: "sandbox"` (`sandboxed-uncertain`), or when a reviewer
 * allows it (`review-allow` of an unparsed command). L1 cannot see what such a
 * command writes, so `rules.protectedPaths` never saw it. This finds every
 * existing path under the writable roots that those patterns protect, so the
 * backend can write-deny them for that one call, at L2.
 *
 * What it cannot do, and the README says so:
 *
 * - **A name that does not exist yet** is not denied: bubblewrap and the
 *   container backend bind over an existing path, so denying it would mean
 *   creating a placeholder, as the session profile does for `.pi`, and that
 *   would leave empty `AGENTS.md`, `.envrc` and `Dockerfile` files in the
 *   repository. Creating one is left to the tripwire, which watches every
 *   protected pattern and counts a hit in an unjudged turn.
 * - **Git metadata** is not walked, which `.git/objects` would make too
 *   expensive. The session profile write-denies the config and hooks of every
 *   repository it found when it compiled; for one created since, its
 *   `.git/config` and `.git/hooks` are added here when a pattern names them.
 *   A gitfile (a linked worktree or submodule checkout) is the tripwire's.
 * - **A symlink** is protected through its target when the target is inside
 *   a writable root; a link matched by its own name can still be replaced,
 *   which the tripwire reports. One inside a denied directory cannot.
 *
 * A file with more than one hard link cannot be protected, since another name
 * for it may be writable; a symlink to a target that does not exist yet would
 * create it; and a walk past its bound cannot vouch for what it did not see. Either way the call is not run unjudged: the gate asks a
 * person instead, and at execution time the command is refused.
 */
import { existsSync, lstatSync, readdirSync, readlinkSync } from "node:fs";
import { basename, dirname, join, resolve } from "node:path";
import { canonical, isUnder } from "../backend/paths.ts";
import { PersistenceScanError, scanRoots } from "../persistence/scan.ts";
import { globToRegExp, pathCandidates } from "../policy/paths.ts";

/** Entries walked per call before the walk gives up and the call asks a person. */
export const PROTECTED_WALK_LIMIT = 200_000;

export type ProtectedWrites = { ok: true; paths: string[] } | { ok: false; reason: string };

export interface ProtectedWritesOptions {
	/** The writable roots of the compiled profile. */
	writableRoots: readonly string[];
	/** Where the patterns are anchored, as at L1. */
	workspace: string;
	/** `rules.protectedPaths.deny` and `.ask`, as folded. */
	patterns: readonly string[];
	/** Already write-denied for the session: nothing to add below these. */
	writeDeny?: readonly string[];
	maxEntries?: number;
}

/**
 * A name inside the directory, used to ask whether a pattern covers what the
 * directory holds (`**\/.husky/**`) and not only its name (`**\/.git`). It
 * contains no separator, so `*` matches it and `/` never does.
 */
const CHILD = "\u0001";

/**
 * `matchesPathPattern(patterns, path, workspace) !== undefined`, fast enough
 * to call on every entry of a workspace.
 *
 * A pattern that starts with `**\/` matches some suffix of a path exactly
 * when it matches the whole path, so those are joined into one expression
 * tried once; only the others are tried against every spelling.
 */
export function protectedPathMatcher(patterns: readonly string[], workspace: string): (path: string) => boolean {
	const anywhere = patterns.filter((pattern) => pattern.startsWith("**/"));
	const anchored = patterns.filter((pattern) => !pattern.startsWith("**/")).map(globToRegExp);
	const joined =
		anywhere.length > 0
			? new RegExp(anywhere.map((pattern) => `(?:${globToRegExp(pattern).source})`).join("|"), "i")
			: undefined;
	return (path) => {
		if (joined?.test(path)) return true;
		if (anchored.length === 0) return false;
		const candidates = pathCandidates(path, workspace);
		return anchored.some((regex) => candidates.some((candidate) => regex.test(candidate)));
	};
}

/**
 * Whether a walked entry is one a protected pattern names: a directory when a
 * pattern covers what it holds, anything else by its own path. Shared by the
 * per-call write-deny and the tripwire (#64), so both see the same set.
 */
export function protectedEntryMatcher(
	patterns: readonly string[],
	workspace: string,
): (path: string, kind: "dir" | "file" | "symlink" | "other") => boolean {
	const matches = protectedPathMatcher(patterns, workspace);
	return (path, kind) => (kind === "dir" ? matches(join(path, CHILD)) : matches(path));
}

/**
 * Where a symlink leads, following a chain of links, even when the last
 * target does not exist (`canonical` stops at a dangling link).
 */
function linkTarget(path: string): string {
	let current = path;
	for (let hops = 0; hops < 40; hops++) {
		const next = canonical(resolve(dirname(current), readlinkSync(current)));
		let stats: ReturnType<typeof lstatSync> | undefined;
		try {
			stats = lstatSync(next);
		} catch {
			return next;
		}
		if (!stats.isSymbolicLink()) return next;
		current = next;
	}
	throw new Unprotectable(`${path} is a chain of more than 40 symlinks`);
}

/** Why the walk cannot vouch for the protected paths. */
class Unprotectable extends Error {}

/**
 * Every existing path a protected pattern names, under the writable roots.
 *
 * A read-only bind holds a name, not an inode, so everything a denied path
 * holds is looked at too (as `validateHookTree` does for the session's Git
 * hooks): a file with another name refuses, and a symlink is held through its
 * target. A symlink whose target does not exist yet inside a writable root
 * refuses as well, since writing through it would create that target.
 */
export function protectedWriteTargets(options: ProtectedWritesOptions): ProtectedWrites {
	if (options.patterns.length === 0) return { ok: true, paths: [] };
	const roots = options.writableRoots.map(canonical);
	const denied = (options.writeDeny ?? []).map(canonical);
	const matches = protectedEntryMatcher(options.patterns, options.workspace);
	const limit = options.maxEntries ?? PROTECTED_WALK_LIMIT;
	// One bound for the whole call: the walk for names and the look inside.
	let visited = 0;
	let found: ReturnType<typeof scanRoots>;
	try {
		found = scanRoots(options.writableRoots, {
			match: (name, kind, path) => {
				visited++;
				// Git's own metadata: protected by the session profile, and the
				// tripwire's when new. Matched only so it is not descended into.
				if (name === ".git") return true;
				// A directory whose contents a pattern covers is denied whole;
				// one matched by name only (`**/.git`) is walked instead.
				return matches(path, kind);
			},
			maxEntries: limit,
		});
	} catch (error) {
		if (error instanceof PersistenceScanError) return { ok: false, reason: error.message };
		throw error;
	}

	const held = new Set<string>();
	const seen = new Set<string>();
	const writable = (path: string) =>
		roots.some((root) => isUnder(path, root)) && !denied.some((deny) => isUnder(path, deny));

	const hold = (path: string): void => {
		let stats: ReturnType<typeof lstatSync>;
		try {
			stats = lstatSync(path);
		} catch {
			// Removed since the walk saw it: nothing left to hold.
			return;
		}
		if (stats.isSymbolicLink()) {
			const target = linkTarget(path);
			// Outside every writable root, or already denied: not writable anyway.
			if (!writable(target)) return;
			if (!existsSync(target)) {
				throw new Unprotectable(
					`${path} is a protected symlink to ${target}, which does not exist yet, so writing through it would create it`,
				);
			}
			hold(target);
			return;
		}
		const resolved = canonical(path);
		if (!writable(resolved)) return;
		if (stats.isFile()) {
			if (stats.nlink > 1) {
				throw new Unprotectable(
					`${path} is protected and has ${stats.nlink} hard links, so another name for it could still be written`,
				);
			}
			held.add(resolved);
			return;
		}
		if (!stats.isDirectory() || seen.has(resolved)) return;
		seen.add(resolved);
		held.add(resolved);
		let entries: string[];
		try {
			entries = readdirSync(resolved);
		} catch (error) {
			throw new Unprotectable(`cannot inspect ${resolved}: ${(error as Error).message}`);
		}
		for (const name of entries) {
			visited++;
			if (visited > limit) {
				throw new Unprotectable(
					`the writable roots and their protected paths hold more than ${limit} entries, too many to check; ` +
						"configure a narrower sandbox.writableRoots",
				);
			}
			hold(join(resolved, name));
		}
	};

	try {
		for (const entry of found) {
			if (entry.kind === "other") continue;
			if (basename(entry.path) !== ".git") {
				hold(entry.path);
				continue;
			}
			if (entry.kind !== "dir") continue;
			for (const name of ["config", "hooks"]) {
				const inner = join(entry.path, name);
				if (existsSync(inner) && matches(inner, name === "hooks" ? "dir" : "file")) hold(inner);
			}
		}
	} catch (error) {
		if (error instanceof Unprotectable) return { ok: false, reason: error.message };
		throw error;
	}
	// A path inside another one adds nothing.
	const sorted = [...held].sort((a, b) => a.length - b.length);
	return { ok: true, paths: sorted.filter((path, i) => !sorted.slice(0, i).some((outer) => isUnder(path, outer))) };
}
