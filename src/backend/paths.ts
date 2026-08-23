/**
 * Path containment. Used by the errno classifier to decide whether a path sits
 * inside a denied region, and by `buildChildEnv` to filter PATH.
 *
 * These are *policy* comparisons against an already-compiled profile, never a
 * substitute for the kernel's decision. pi-enclave does not permit or deny
 * anything on the strength of a path check -- the OS does that -- so a
 * mis-comparison here degrades a message, it does not open a hole.
 */
import { resolve, sep } from "node:path";

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

/** True when `path` is under any of `roots`. An empty list matches nothing. */
export function isUnderAny(path: string, roots: readonly string[]): boolean {
	return roots.some((root) => isUnder(path, root));
}
