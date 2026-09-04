/**
 * Redaction, applied to every audit record before it is written.
 *
 * An audit log is a security control that also creates a risk: it is a
 * plaintext file that records, in detail, everything an agent tried to do --
 * including the arguments. A log that faithfully preserves the API key someone
 * pasted into a command has moved that key from the terminal scrollback into a
 * file with a 30-day retention.
 *
 * So values are replaced by `<redacted:sha256:…>`. The hash is not decoration:
 * it lets an investigator confirm that two records contain the *same* secret,
 * or that a record contains a secret they already hold, without the log ever
 * storing it. That is the property a plain `***` loses.
 *
 * What is redacted, and why each:
 *
 * - **Credential shapes.** Recognizable prefixes and headers, found anywhere in
 *   a string, replaced in place so the rest of the command stays readable.
 * - **Paths under `readDeny`.** Not because the path is secret, but because
 *   these are the paths whose *contents* are, and a command line containing one
 *   often contains the other.
 * - **`write` and `edit` bodies.** Whole file contents have no business in an
 *   audit record at any size, and they are the most likely place for a secret
 *   the pattern list does not recognize.
 */
import { createHash } from "node:crypto";
import { canonical, isUnder } from "../backend/paths.ts";

/** Keys whose values are file contents rather than arguments. */
const BODY_KEYS = new Set([
	"content",
	"edits",
	"newContent",
	"new_string",
	"newString",
	"oldContent",
	"old_string",
	"oldString",
	"text",
]);

/**
 * Credential shapes, as patterns over a string's contents.
 *
 * Kept short and specific. A greedy pattern that redacted anything long and
 * random would redact hashes, ids and diffs, and an audit log where everything
 * is `<redacted>` is one nobody reads -- which is the same as not having one.
 */
const CREDENTIAL_PATTERNS: readonly RegExp[] = [
	/AKIA[0-9A-Z]{16}/g,
	/ASIA[0-9A-Z]{16}/g,
	/gh[pousr]_[A-Za-z0-9]{20,}/g,
	/github_pat_[A-Za-z0-9_]{20,}/g,
	/sk-[A-Za-z0-9]{20,}/g,
	/sk-ant-[A-Za-z0-9-]{20,}/g,
	/xox[abprs]-[A-Za-z0-9-]{10,}/g,
	/glpat-[A-Za-z0-9_-]{16,}/g,
	/AIza[0-9A-Za-z_-]{30,}/g,
	/-----BEGIN[ A-Z]*PRIVATE KEY-----[\s\S]*?-----END[ A-Z]*PRIVATE KEY-----/g,
	/-----BEGIN[ A-Z]*PRIVATE KEY-----/g,
	// Header and assignment forms, where the value is whatever follows.
	/(?<=Authorization:\s*)(?:Bearer\s+|Basic\s+)?[A-Za-z0-9._~+/=-]{8,}/gi,
	/(?<=(?:password|passwd|secret|token|api[_-]?key)\s*[=:]\s*)["']?[^\s"',;]{6,}/gi,
	// A JWT (three base64url segments). Distinctive `eyJ` header, so it can be
	// matched anywhere -- including a non-Authorization header the form above
	// misses.
	/eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}/g,
	// The credential half of a connection string: `scheme://user:PASS@host`.
	// The scheme/user/password up to `@` is replaced; the host and path after it
	// stay readable, which is enough context to tell which DSN it was.
	/[a-z][a-z0-9+.-]*:\/\/[^:@/\s]+:[^@/\s]+(?=@)/gi,
	// `-u user:pass` / `--user user:pass` (curl and friends).
	/(?<=(?:^|\s)(?:-u|--user)[=\s])[^\s:]+:[^\s]+/g,
	// `-pSecret` with no space (mysql/mongo). Six or more trailing characters, so
	// short flags like `-print` (four after `-p`) are left alone; over-matching a
	// long non-secret only costs readability.
	/(?<=(?:^|\s)-p)[^\s]{6,}/g,
];

export function redactedMarker(value: string): string {
	return `<redacted:sha256:${createHash("sha256").update(value).digest("hex").slice(0, 16)}>`;
}

/** Replace every recognized credential inside a string. */
export function redactString(value: string): string {
	let out = value;
	for (const pattern of CREDENTIAL_PATTERNS) {
		out = out.replace(pattern, (match) => redactedMarker(match));
	}
	return out;
}

export interface RedactOptions {
	/** Paths whose mention implies their contents. Usually the profile's readDeny. */
	readDeny?: readonly string[];
}

/**
 * Redact a value of any shape, recursively.
 *
 * Structure is preserved -- an investigator needs to see that there *was* a
 * `content` argument, and how large it was -- while the values that carry
 * secrets are replaced.
 */
export function redact(value: unknown, options: RedactOptions = {}, key?: string): unknown {
	// The denied roots are resolved once here, not per token: `canonical` does a
	// `realpathSync` walk, and doing it for every root for every path-shaped
	// token of every record put a synchronous filesystem probe on the tool-call
	// path (~15 default roots, several nonexistent). Resolving them once and
	// comparing against both spellings keeps the same symlink-awareness with no
	// per-token realpath.
	const denyRoots = resolveDenyRoots(options.readDeny);
	const walk = (input: unknown, k?: string, inheritedBody = false): unknown => {
		const body = inheritedBody || (k !== undefined && BODY_KEYS.has(k));
		if (typeof input === "string") {
			if (body) {
				// The length is kept because it is the one thing about a file body
				// that is useful in an audit record and cannot leak anything.
				return `${redactedMarker(input)} (${input.length} chars)`;
			}
			return redactString(redactDenyPaths(input, denyRoots));
		}
		if (Array.isArray(input)) return input.map((entry) => walk(entry, k, body));
		if (input && typeof input === "object") {
			return Object.fromEntries(Object.entries(input).map(([kk, v]) => [kk, walk(v, kk, body)]));
		}
		return input;
	};
	return walk(value, key);
}

/** Raw roots plus their canonical spellings, de-duplicated, resolved once. */
function resolveDenyRoots(readDeny?: readonly string[]): string[] {
	if (!readDeny || readDeny.length === 0) return [];
	const roots = new Set<string>();
	for (const root of readDeny) {
		roots.add(root);
		roots.add(canonical(root));
	}
	return [...roots];
}

/**
 * Replace mentions of read-denied paths.
 *
 * Whole tokens only. Redacting a substring would turn `/home/u/.sshconfig`
 * into a partially-masked string that is neither readable nor safe, and
 * containment is the same whole-segment comparison the sandbox uses.
 */
function redactDenyPaths(value: string, denyRoots: readonly string[]): string {
	if (denyRoots.length === 0) return value;
	return value
		.split(/(\s+)/)
		.map((token) => {
			const bare = token.replace(/^["'`]|["'`,;:]$/g, "");
			if (bare.length < 2 || !bare.startsWith("/")) return token;
			// `denyRoots` already contains each root's canonical spelling, so a
			// plain containment check keeps the symlink-awareness `isUnderAny`
			// gave without re-resolving anything here.
			return denyRoots.some((root) => isUnder(bare, root)) ? token.replace(bare, redactedMarker(bare)) : token;
		})
		.join("");
}
