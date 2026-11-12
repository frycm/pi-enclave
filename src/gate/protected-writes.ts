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
 * - **A name that does not exist yet** cannot be denied: bubblewrap binds
 *   over an existing path, and the container backend mounts one. Creating
 *   `AGENTS.md` or `.github/workflows/x.yml` is left to the tripwire, which
 *   watches every protected pattern and counts a hit in an unjudged turn.
 * - **Git metadata** is not walked, which `.git/objects` would make too
 *   expensive. The session profile write-denies the config and hooks of every
 *   repository it found when it compiled; for one created since, its
 *   `.git/config` and `.git/hooks` are added here when a pattern names them.
 *   A gitfile (a linked worktree or submodule checkout) is the tripwire's.
 * - **A symlink** is protected through its target when the target is inside
 *   a writable root; the link itself can still be replaced, which the
 *   tripwire reports.
 *
 * A file with more than one hard link cannot be protected, since another name
 * for it may be writable, and a walk past its bound cannot vouch for what it
 * did not see. Either way the call is not run unjudged: the gate asks a
 * person instead, and at execution time the command is refused.
 */
import { existsSync, lstatSync } from "node:fs";
import { basename, join } from "node:path";
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

/** Every existing path a protected pattern names, under the writable roots. */
export function protectedWriteTargets(options: ProtectedWritesOptions): ProtectedWrites {
	if (options.patterns.length === 0) return { ok: true, paths: [] };
	const roots = options.writableRoots.map(canonical);
	const denied = (options.writeDeny ?? []).map(canonical);
	const matches = protectedEntryMatcher(options.patterns, options.workspace);
	let found: ReturnType<typeof scanRoots>;
	try {
		found = scanRoots(options.writableRoots, {
			match: (name, kind, path) => {
				// Git's own metadata: protected by the session profile, and the
				// tripwire's when new. Matched only so it is not descended into.
				if (name === ".git") return true;
				// A directory whose contents a pattern covers is denied whole;
				// one matched by name only (`**/.git`) is walked instead.
				return matches(path, kind);
			},
			maxEntries: options.maxEntries ?? PROTECTED_WALK_LIMIT,
		});
	} catch (error) {
		if (error instanceof PersistenceScanError) return { ok: false, reason: error.message };
		throw error;
	}

	const paths = new Set<string>();
	const candidates: typeof found = [];
	for (const entry of found) {
		if (basename(entry.path) !== ".git") {
			candidates.push(entry);
			continue;
		}
		if (entry.kind !== "dir") continue;
		for (const name of ["config", "hooks"]) {
			const inner = join(entry.path, name);
			if (existsSync(inner) && matches(inner, name === "hooks" ? "dir" : "file")) {
				candidates.push({ path: inner, kind: name === "hooks" ? "dir" : "file" });
			}
		}
	}
	for (const entry of candidates) {
		if (entry.kind === "other") continue;
		// A symlink resolves to its target. A dangling one resolves to itself,
		// is neither a file nor a directory below, and is the tripwire's.
		const resolved = canonical(entry.path);
		// Outside every writable root the sandbox cannot write it anyway.
		if (!roots.some((root) => isUnder(resolved, root))) continue;
		if (denied.some((deny) => isUnder(resolved, deny))) continue;
		let stats: ReturnType<typeof lstatSync>;
		try {
			stats = lstatSync(resolved);
		} catch {
			continue;
		}
		if (stats.isFile() && stats.nlink > 1) {
			return {
				ok: false,
				reason: `${entry.path} is protected and has ${stats.nlink} hard links, so another name for it could still be written`,
			};
		}
		if (!stats.isFile() && !stats.isDirectory()) continue;
		paths.add(resolved);
	}
	// A path inside another one adds nothing.
	const sorted = [...paths].sort((a, b) => a.length - b.length);
	return { ok: true, paths: sorted.filter((path, i) => !sorted.slice(0, i).some((outer) => isUnder(path, outer))) };
}
