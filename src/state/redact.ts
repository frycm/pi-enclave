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
import { isUnderAny } from "../backend/paths.ts";

/** Keys whose values are file contents rather than arguments. */
const BODY_KEYS = new Set([
	"content",
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
	if (typeof value === "string") {
		if (key !== undefined && BODY_KEYS.has(key)) {
			// The length is kept because it is the one thing about a file body
			// that is useful in an audit record and cannot leak anything.
			return `${redactedMarker(value)} (${value.length} chars)`;
		}
		const withPaths = redactDenyPaths(value, options.readDeny);
		return redactString(withPaths);
	}
	if (Array.isArray(value)) return value.map((entry) => redact(entry, options, key));
	if (value && typeof value === "object") {
		return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, redact(v, options, k)]));
	}
	return value;
}

/**
 * Replace mentions of read-denied paths.
 *
 * Whole tokens only. Redacting a substring would turn `/home/u/.sshconfig`
 * into a partially-masked string that is neither readable nor safe, and
 * containment is the same whole-segment comparison the sandbox uses.
 */
function redactDenyPaths(value: string, readDeny?: readonly string[]): string {
	if (!readDeny || readDeny.length === 0) return value;
	return value
		.split(/(\s+)/)
		.map((token) => {
			const bare = token.replace(/^["'`]|["'`,;:]$/g, "");
			if (bare.length < 2 || !bare.startsWith("/")) return token;
			return isUnderAny(bare, readDeny) ? token.replace(bare, redactedMarker(bare)) : token;
		})
		.join("");
}
