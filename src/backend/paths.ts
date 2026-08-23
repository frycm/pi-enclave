/**
 * Path containment. Used by the errno classifier to decide whether a path sits
 * inside a denied region, and by `buildChildEnv` to filter PATH.
 *
 * These are *policy* comparisons against an already-compiled profile, never a
 * substitute for the kernel's decision. pi-enclave does not permit or deny
 * anything on the strength of a path check -- the OS does that -- so a
 * mis-comparison here degrades a message, it does not open a hole.
 */
import { realpathSync } from "node:fs";
import { basename, dirname, join, resolve, sep } from "node:path";

/** Resolve to an absolute path with no trailing separator (except for root itself). */
export function normalizePath(path: string): string {
	const resolved = resolve(path);
	if (resolved.length > 1 && resolved.endsWith(sep)) return resolved.slice(0, -1);
	return resolved;
}

/**
 * True when `path` is `root` or sits beneath it.
 *
 * Compares whole segments, so `/foo/bar` is not under `/foo/ba`.
 */
export function isUnder(path: string, root: string): boolean {
	const p = normalizePath(path);
	const r = normalizePath(root);
	if (p === r) return true;
	return p.startsWith(r.endsWith(sep) ? r : r + sep);
}

/**
 * True when `path` is under any of `roots`. An empty list matches nothing.
 *
 * Each root is compared in both its configured and its canonical spelling: the
 * helper reports the path the kernel judged, which on macOS is `/private/var/…`
 * for a root configured as `/var/…`, and on any platform the target of a
 * symlinked home. Resolving the root here is a comparison aid only -- a root
 * that cannot be resolved is simply compared as written.
 */
export function isUnderAny(path: string, roots: readonly string[]): boolean {
	return roots.some((root) => isUnder(path, root) || isUnder(path, canonical(root)));
}

/**
 * The canonical spelling of a path, whether or not all of it exists: the
 * deepest existing ancestor is resolved and the missing remainder re-joined.
 * A path that cannot be resolved at all is returned as written.
 */
export function canonical(path: string): string {
	let current = normalizePath(path);
	let remainder = "";
	for (;;) {
		try {
			const resolved = realpathSync(current);
			return remainder ? join(resolved, remainder) : resolved;
		} catch {
			const parent = dirname(current);
			if (parent === current) return normalizePath(path);
			remainder = remainder ? join(basename(current), remainder) : basename(current);
			current = parent;
		}
	}
}
