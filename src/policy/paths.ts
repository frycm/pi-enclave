/**
 * Path resolution and glob matching for the policy layer.
 *
 * A note on what these are for. Nothing here permits anything: the kernel does
 * that, and Phase 1's whole argument is that in-process path checks are not a
 * boundary because they race with the `open`. What these functions decide is
 * whether an action needs a *human*, which is a question the sandbox cannot
 * answer -- writing to `infra/terraform/` is inside a writable root and the
 * kernel will allow it, and the point of `protectedPaths` is to stop and ask
 * anyway.
 *
 * So a miss here does not open a hole in the sandbox; it skips an escalation.
 * That is still worth getting right, which is why the matching is done on both
 * the path as typed and its resolved form, and why an out-of-tree path is
 * matched by every segment suffix rather than only as written.
 */
import { isAbsolute, relative, resolve, sep } from "node:path";
import { canonical, normalizePath } from "../backend/paths.ts";

/**
 * Resolve a path the way policy should see it: absolute, and with symlinks
 * followed as far as they exist.
 *
 * `canonical` resolves the deepest existing ancestor and re-joins the missing
 * tail, so a write target that does not exist yet still resolves -- which is
 * the common case for `write`, and the case a naive `realpath` cannot handle.
 */
export function resolveForPolicy(path: string, cwd: string): { typed: string; resolved: string } {
	const typed = normalizePath(isAbsolute(path) ? path : resolve(cwd, path));
	return { typed, resolved: canonical(typed) };
}

/** Strip the decorations pi's own tools accept, so policy sees the same path they do. */
export function normalizeInputPath(raw: string, home: string): string {
	let path = raw.trim().replace(/^@/, "");
	if (path.startsWith("file://")) path = path.slice("file://".length);
	if (path === "~") path = home;
	else if (path.startsWith("~/")) path = `${home}/${path.slice(2)}`;
	return path;
}

// ---------------------------------------------------------------------------
// Globs
// ---------------------------------------------------------------------------

/**
 * Compile a glob to a regular expression.
 *
 * Supports `**` (any number of segments, including none), `*` (anything but a
 * separator), `?` (one character but a separator), and character classes. Brace
 * expansion is deliberately absent: it multiplies patterns, and every pattern
 * it would save can be written as two entries in a list that is already a list.
 */
export function globToRegExp(pattern: string): RegExp {
	let out = "";
	for (let i = 0; i < pattern.length; i++) {
		const char = pattern[i] as string;
		if (char === "*") {
			if (pattern[i + 1] === "*") {
				// `**/` may match nothing at all, so `**/x` matches a bare `x`.
				if (pattern[i + 2] === "/") {
					out += "(?:[^/]*/)*";
					i += 2;
				} else {
					out += ".*";
					i++;
				}
				continue;
			}
			out += "[^/]*";
			continue;
		}
		if (char === "?") {
			out += "[^/]";
			continue;
		}
		if (char === "[") {
			const close = pattern.indexOf("]", i + 1);
			if (close > i) {
				// A POSIX glob negates a class with a leading `!` (`[!c]`); a regex
				// uses `^`. Copied verbatim, `[!c]` matched a literal `!` or `c`
				// instead of negating, so a `protectedPaths` pattern like
				// `infra/[!c]*` silently failed to escalate.
				let cls = pattern.slice(i, close + 1);
				if (cls.startsWith("[!")) cls = `[^${cls.slice(2)}`;
				out += cls;
				i = close;
				continue;
			}
		}
		out += char.replace(/[.+^${}()|[\]\\]/g, "\\$&");
	}
	// Case-insensitive to match the `deny`/`ask` wildcard matcher, and because
	// on a case-insensitive filesystem (macOS, Windows) `dockerfile` and
	// `Dockerfile` are the same file -- a case-sensitive protected-path glob let
	// a case-variant spelling slip past the escalation. Over-matching a distinct
	// file on a case-sensitive filesystem only costs an extra ask, the direction
	// this layer already errs in.
	return new RegExp(`^${out}$`, "i");
}

const globCache = new Map<string, RegExp>();

function compiled(pattern: string): RegExp {
	let regex = globCache.get(pattern);
	if (!regex) {
		regex = globToRegExp(pattern);
		globCache.set(pattern, regex);
	}
	return regex;
}

/**
 * Does a resolved path match one of the protected-path globs?
 *
 * In-tree paths are matched relative to the workspace, which is how the
 * patterns are written (`infra/**`, not `/home/u/repo/infra/**`). Out-of-tree
 * paths have no meaningful relative form, so every path-segment suffix is
 * tried: `../other/.git/config` still matches `**` + `.git/config`. automode
 * does the same, for the same reason -- a pattern about `.git/config` is about
 * the file, not about where the repository happens to sit.
 */
export function matchesPathPattern(
	patterns: readonly string[],
	resolvedPath: string,
	workspace: string,
): string | undefined {
	const candidates = pathCandidates(resolvedPath, workspace);
	for (const pattern of patterns) {
		const regex = compiled(pattern);
		for (const candidate of candidates) {
			if (regex.test(candidate)) return pattern;
		}
	}
	return undefined;
}

/** Every spelling of a path a pattern might reasonably be written against. */
export function pathCandidates(resolvedPath: string, workspace: string): string[] {
	const out = [resolvedPath];
	const rel = relative(workspace, resolvedPath);
	if (rel !== "" && !rel.startsWith("..") && !isAbsolute(rel)) out.push(rel);

	// Segment suffixes, so a pattern naming a file matches it wherever it sits.
	const segments = resolvedPath.split(sep).filter((segment) => segment !== "");
	for (let i = 1; i < segments.length; i++) out.push(segments.slice(i).join("/"));

	return [...new Set(out)];
}

// ---------------------------------------------------------------------------
// Finding paths in a command line
// ---------------------------------------------------------------------------

/**
 * Does this token look like a path a rule should be matched against?
 *
 * Deliberately generous. A false positive costs an unnecessary
 * `protectedPaths` comparison; a false negative skips an escalation the user
 * asked for. The asymmetry decides every judgement call in here.
 */
export function looksLikePath(token: string): boolean {
	if (token === "" || token.startsWith("-")) return false;
	if (token.startsWith("/") || token.startsWith("./") || token.startsWith("../") || token.startsWith("~")) return true;
	return token.includes("/");
}

/**
 * Path-shaped values in one token, including the `--flag=/path` form.
 *
 * The part after the last `=` is considered as well as the whole token, so
 * `--output=/etc/passwd` contributes `/etc/passwd` rather than nothing.
 */
export function pathCandidatesInToken(token: string): string[] {
	const out: string[] = [];
	if (looksLikePath(token)) out.push(token);
	const eq = token.lastIndexOf("=");
	if (eq > 0) {
		const tail = token.slice(eq + 1).replace(/^["']|["']$/g, "");
		if (looksLikePath(tail)) out.push(tail);
	}
	return out;
}
