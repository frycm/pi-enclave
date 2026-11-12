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
function linkTarget(path: string, replaceable: (link: string) => boolean): string {
	let current = path;
	for (let hops = 0; hops < 40; hops++) {
		const lexical = resolve(dirname(current), readlinkSync(current));
		// A bind holds the final target, not the links on the way to it: one
		// the command could replace would point the protected name elsewhere.
		const link = linkOnTheWay(lexical, replaceable);
		if (link !== undefined) {
			throw new Unprotectable(
				`${path} is a protected symlink that resolves through ${link}, a symlink this command could replace; ` +
					"point the protected link straight at its target",
			);
		}
		const next = canonical(lexical);
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

/**
 * The first symlink met while resolving `path`, as a component or the path
 * itself, that `replaceable` accepts. A link that is not replaceable is
 * followed, so the links its own target passes through are checked too.
 */
function linkOnTheWay(path: string, replaceable: (link: string) => boolean): string | undefined {
	let pending = path.split("/").filter(Boolean);
	// Built from components that are not links, so always canonical.
	let resolved = "/";
	let hops = 0;
	while (pending.length > 0) {
		const part = pending.shift() as string;
		if (part === ".") continue;
		if (part === "..") {
			resolved = dirname(resolved);
			continue;
		}
		const next = join(resolved, part);
		let stats: ReturnType<typeof lstatSync>;
		try {
			stats = lstatSync(next);
		} catch {
			// Missing from here on: nothing below can be a link yet.
			return undefined;
		}
		if (!stats.isSymbolicLink()) {
			resolved = next;
			continue;
		}
		if (replaceable(next)) return next;
		if (++hops > 40) throw new Unprotectable(`${path} passes through more than 40 symlinks`);
		const target = readlinkSync(next);
		if (target.startsWith("/")) resolved = "/";
		pending = [...target.split("/").filter(Boolean), ...pending];
	}
	return undefined;
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
	const heldDirectories = new Set<string>();
	const seen = new Set<string>();
	/** Protected files with another name, by device and inode. */
	const linked = new Map<string, string>();
	const writable = (path: string) =>
		roots.some((root) => isUnder(path, root)) && !denied.some((deny) => isUnder(path, deny));
	const insideHeld = (path: string) => {
		for (let dir = dirname(path); dir !== dirname(dir); dir = dirname(dir)) {
			if (heldDirectories.has(dir)) return true;
		}
		return false;
	};
	// A link inside a directory held for the call cannot be replaced either.
	const replaceable = (link: string) => writable(link) && !insideHeld(link);

	/**
	 * `canonicalParent`: `path` is an entry of a directory already resolved,
	 * so unless it is a symlink it is its own canonical path.
	 */
	const hold = (path: string, canonicalParent = false): void => {
		let stats: ReturnType<typeof lstatSync>;
		try {
			stats = lstatSync(path);
		} catch {
			// Removed since the walk saw it: nothing left to hold.
			return;
		}
		if (stats.isSymbolicLink()) {
			const target = linkTarget(path, replaceable);
			// Outside every writable root, or already denied: not writable anyway.
			if (!writable(target)) return;
			const location = canonicalParent ? path : join(canonical(dirname(path)), basename(path));
			// Back into a directory already held (`.husky/loop -> .`) changes nothing.
			const wider = isUnder(location, target) || roots.some((root) => isUnder(root, target));
			if (wider && !heldDirectories.has(target)) {
				throw new Unprotectable(
					`${path} is a protected symlink to ${target}, which holds ${isUnder(location, target) ? "the link itself" : "a whole writable root"}; ` +
						"holding it would make all of it read-only for this command, so remove the link or point it elsewhere",
				);
			}
			if (!existsSync(target)) {
				throw new Unprotectable(
					`${path} is a protected symlink to ${target}, which does not exist yet, so writing through it would create it`,
				);
			}
			hold(target);
			return;
		}
		const resolved = canonicalParent ? path : canonical(path);
		if (!writable(resolved)) return;
		if (stats.isFile()) {
			// Its other names are found after the walk, and held as well.
			if (stats.nlink > 1) linked.set(`${stats.dev}:${stats.ino}`, resolved);
			held.add(resolved);
			return;
		}
		if (!stats.isDirectory() || seen.has(resolved)) return;
		seen.add(resolved);
		held.add(resolved);
		heldDirectories.add(resolved);
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
			hold(join(resolved, name), true);
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
		if (linked.size > 0) holdOtherNames();
	} catch (error) {
		if (error instanceof Unprotectable) return { ok: false, reason: error.message };
		throw error;
	}

	/**
	 * Every other name of a protected file with more than one, under the
	 * writable roots. A name not found there is outside them, where the
	 * command cannot write anyway; a directory that cannot be read refuses.
	 */
	function holdOtherNames() {
		const unscanned: string[] = [];
		try {
			scanRoots(options.writableRoots, {
				match: (_name, kind, path) => {
					visited++;
					if (kind !== "file") return false;
					const stats = lstatSync(path, { throwIfNoEntry: false });
					if (stats === undefined || stats.nlink < 2) return false;
					if (!linked.has(`${stats.dev}:${stats.ino}`)) return false;
					const name = canonical(path);
					if (writable(name)) held.add(name);
					return false;
				},
				maxEntries: Math.max(0, limit - visited),
				unscanned,
			});
		} catch (error) {
			if (error instanceof PersistenceScanError) {
				throw new Unprotectable(
					`a protected file has more than one name, and the other names cannot all be found: ${error.message}`,
				);
			}
			throw error;
		}
		if (unscanned.length > 0) {
			throw new Unprotectable(
				`a protected file has more than one name, and ${unscanned[0]} cannot be read to look for the others`,
			);
		}
	}
	// A path inside another one adds nothing.
	// By ancestors, not by pairs: a held directory can hold many thousands.
	const sorted = [...held].sort((a, b) => a.length - b.length);
	const kept = new Set<string>();
	const covered = (path: string) => {
		for (let dir = dirname(path); ; dir = dirname(dir)) {
			if (kept.has(dir)) return true;
			if (dir === dirname(dir)) return false;
		}
	};
	for (const path of sorted) if (!covered(path)) kept.add(path);
	return { ok: true, paths: [...kept] };
}
