/**
 * Turn a failed syscall into a {@link Violation}, or decide it was an ordinary
 * error.
 *
 * This exists because **a denial is not portable**. The same policy, denied on
 * both backends, surfaces differently (docs/step-0-srt-findings.md, finding 9):
 *
 * | Operation                 | Seatbelt | bwrap                              |
 * |---------------------------|----------|------------------------------------|
 * | write outside a root      | EPERM    | EROFS   (`--ro-bind / /`)          |
 * | read a denied path        | EPERM    | ENOENT  (deny-read is a tmpfs)     |
 * | raw TCP connect           | EPERM    | ENETUNREACH (`--unshare-net`)      |
 * | unix socket               | EPERM    | EPERM (at `socket()`, not connect) |
 *
 * Two mistakes are possible and this module exists to avoid both. Checking only
 * for `EPERM` silently misses every Linux write denial. Treating every `ENOENT`
 * as a denial reports a genuinely missing file as a security event -- and on
 * Linux `ENOENT` is exactly what a denied read looks like, so it cannot simply
 * be ignored either. The ambiguity is resolved against the compiled profile:
 * `ENOENT` under a `readDeny` root is a denial, `ENOENT` anywhere else is not.
 */

import { isUnderAny } from "./paths.ts";
import type { BackendName, Profile, Violation, ViolationKind } from "./types.ts";

/** Operations the helper performs, grouped by the kind of access they need. */
export const READ_OPS = ["readFile", "access:read", "stat", "readdir", "exists", "glob", "grep"] as const;
export const WRITE_OPS = ["writeFile", "mkdir", "access:write", "unlink"] as const;

export type FsOp = (typeof READ_OPS)[number] | (typeof WRITE_OPS)[number];

export function kindForOp(op: string): ViolationKind {
	return (WRITE_OPS as readonly string[]).includes(op) ? "write" : "read";
}

/** The Node error shape we get back from a failed `fs` call. */
export interface ErrnoLike {
	code?: string;
	syscall?: string;
	path?: string;
}

export interface ClassifyInput {
	error: ErrnoLike;
	/** The logical operation attempted, e.g. "readFile". */
	op: string;
	/** Absolute path the operation targeted. */
	path: string;
	profile: Profile;
	backend: BackendName;
}

/**
 * Errnos that always mean "the sandbox stopped this", on any backend.
 *
 * `EROFS` is here because pi-enclave never asks the helper to write to a
 * genuinely read-only filesystem in normal operation -- bwrap's `--ro-bind / /`
 * is what makes everything outside the writable roots read-only. A user who
 * points a workspace at a real read-only mount gets a violation instead of a
 * plain error; that is a legible failure, not a dangerous one.
 */
const ALWAYS_DENIAL = new Set(["EPERM", "EACCES", "EROFS"]);

/** Errnos that mean the network was unreachable rather than forbidden. */
const NETWORK_DENIAL = new Set(["ENETUNREACH", "EAFNOSUPPORT", "ENETDOWN"]);

/**
 * Classify a failed filesystem operation.
 *
 * Returns a `Violation` when the sandbox denied it, or `null` when this was an
 * ordinary error the caller should surface as-is (a genuinely missing file, a
 * bad argument, a full disk).
 */
export function classifyErrno(input: ClassifyInput): Violation | null {
	const { error, op, path, profile, backend } = input;
	const code = error.code;
	if (!code) return null;

	const base = {
		source: "errno" as const,
		op,
		path,
		backend,
		raw: `${code}${error.syscall ? ` (${error.syscall})` : ""}`,
	};

	if (ALWAYS_DENIAL.has(code)) {
		return { ...base, kind: kindForOp(op) };
	}

	if (NETWORK_DENIAL.has(code)) {
		return { ...base, kind: "network" };
	}

	// The ambiguous case. On bwrap a denied read region is a tmpfs mounted over
	// the real directory, so its contents are *absent* rather than forbidden: the
	// errno is indistinguishable from a file that was never there. Resolve it
	// against the profile rather than guessing.
	if (code === "ENOENT" && isUnderAny(path, profile.readDeny)) {
		return { ...base, kind: kindForOp(op) };
	}

	return null;
}

/**
 * Would this errno be reported as a denial for this path? Convenience for the
 * conformance suite, which asserts the *classification* rather than merely that
 * a call failed -- a test that only checks "it threw" passes even when we have
 * mislabelled a missing file as a security violation.
 */
export function isDenial(input: ClassifyInput): boolean {
	return classifyErrno(input) !== null;
}
