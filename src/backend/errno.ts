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
 * Errnos a sandbox refusal produces -- and that ordinary Unix permissions
 * produce too.
 *
 * `EPERM` and `EACCES` are what a root-owned file, a `chmod 000` directory, or
 * a macOS TCC-protected folder (`~/Documents` without Full Disk Access) return
 * with no sandbox anywhere near them. `EROFS` is bwrap's `--ro-bind / /`, but
 * also a genuinely read-only mount. So none of these is a verdict on its own;
 * each is resolved against the profile, as `ENOENT` already is: a refused
 * write is a denial only outside every writable root, a refused read only
 * under a deny root. Anything else is the operating system's own "no", passed
 * through as the ordinary error it is, so the agent is not told a permission
 * problem is a policy boundary and the violation counter is not inflated by
 * files the user could not read either.
 */
const PERMISSION_ERRNOS = new Set(["EPERM", "EACCES", "EROFS"]);

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

	if (NETWORK_DENIAL.has(code)) {
		return { ...base, kind: "network" };
	}

	const kind = kindForOp(op);

	if (PERMISSION_ERRNOS.has(code)) {
		if (kind === "write") {
			// Writes are an allow-list: a refusal inside a writable root is not the
			// sandbox's doing.
			return isUnderAny(path, profile.writableRoots) ? null : { ...base, kind };
		}
		// Reads are a deny-list: the sandbox refuses nothing outside readDeny, so
		// a refusal there is the operating system's own.
		return isUnderAny(path, profile.readDeny) ? { ...base, kind } : null;
	}

	// The ambiguous case. On bwrap a denied read region is a tmpfs mounted over
	// the real directory, so its contents are *absent* rather than forbidden: the
	// errno is indistinguishable from a file that was never there. Resolve it
	// against the profile rather than guessing.
	if (code === "ENOENT" && isUnderAny(path, profile.readDeny)) {
		return { ...base, kind };
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
