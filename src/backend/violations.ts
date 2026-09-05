/**
 * Parse backend-native violation lines into {@link Violation}s, and drop the
 * benign ones.
 *
 * Two things make this messier than it looks, both measured in step 0:
 *
 * 1. The two backends share no grammar. Seatbelt emits
 *    `bash(22824) deny(1) file-write-create /private/...` through the unified
 *    log; bwrap's observer emits `deny openat /tmp/...`; the egress proxy emits
 *    `deny network-outbound example.com:443 (host is not on the allow list)`.
 * 2. The stream is noisy, and differently noisy per platform. Nearly every
 *    macOS command denies `sysctl-read kern.iossupportversion`; one Python call
 *    produced 62 `__pycache__` denials on macOS and 30 `/dev/shm/sem.*` denials
 *    on Linux -- while succeeding. A `violations.length > 0` check would call
 *    both of those a security event.
 *
 * So violations are evidence, not the denial signal. The operation's own error
 * is what tells us something was stopped -- which on Linux is the only thing
 * that works at all, since a denied read there produces no event.
 */
import type { BackendName, Violation, ViolationKind } from "./types.ts";

/**
 * Denials that are routine and carry no security meaning. Filtered before
 * anything reaches the status line, the audit log, or phase 2's circuit
 * breaker.
 *
 * Every entry is something observed in the step-0 spike on a successful or
 * otherwise uninteresting command. Adding to this list widens what we ignore,
 * so each entry should say why it is benign.
 */
export const NOISE_PATTERNS: Record<BackendName, RegExp[]> = {
	seatbelt: [
		// Emitted by essentially every process at startup; reveals nothing and is
		// denied by SRT's base profile rather than by our policy.
		/\bsysctl-read\b/,
		// Python writing bytecode into its own (read-only) install directory.
		/__pycache__/,
		// Font and preference lookups from anything linking AppKit.
		/\buser-preference-read\b/,
		/mach-lookup com\.apple\.(FontObjectsServer|fonts)\b/,
		// Every network client queries this before connecting; it is a read-only
		// system-configuration lookup and appears alongside the real network
		// denial, where it adds noise to the one line that matters. Named
		// explicitly rather than ignoring mach-lookup as a class, since other
		// mach services are genuinely powerful.
		/mach-lookup com\.apple\.SystemConfiguration\.configd\b/,
	],
	bwrap: [
		// POSIX semaphores for multiprocessing; the call succeeds via a fallback.
		/\/dev\/shm\/sem\./,
		/__pycache__/,
	],
	docker: [],
};

export function isNoise(line: string, backend: BackendName): boolean {
	return NOISE_PATTERNS[backend].some((pattern) => pattern.test(line));
}

/** Map a backend-native operation name onto a violation kind. */
function kindForNativeOp(op: string): ViolationKind {
	if (op.startsWith("file-write")) return "write";
	if (op.startsWith("file-read")) return "read";
	if (op.startsWith("network")) return "network";
	if (op.startsWith("process-exec") || op === "execve") return "exec";
	// bwrap's observer reports the raw syscall, which does not distinguish
	// intent: a denied write fails at `openat` because the ro-bind is what
	// refuses it, so these are writes rather than reads.
	if (/^(openat|linkat|unlinkat|renameat|mkdirat|creat)$/.test(op)) return "write";
	return "read";
}

/** `bash(22824) deny(1) file-write-create /private/var/...` */
const SEATBELT_LINE = /^\s*(\S+)\((\d+)\)\s+deny\(\d+\)\s+(\S+)\s*(.*)$/;

/** `deny openat /tmp/enclave-home-x/pwned.txt` */
const BWRAP_LINE = /^\s*deny\s+(\S+)\s*(.*)$/;

/** `deny network-outbound example.com:443 (host is not on the allow list)` */
const PROXY_LINE = /^\s*deny\s+network-outbound\s+(\S+?)(?::(\d+))?\s*(?:\(.*\))?\s*$/;

/**
 * Parse one line. Returns null when the line is noise or does not parse -- an
 * unparseable line is never invented into a violation, because a fabricated
 * denial is worse than a missed log line we can still see in the raw audit.
 */
export function parseViolationLine(line: string, backend: BackendName): Violation | null {
	if (!line.trim() || isNoise(line, backend)) return null;

	// The proxy shares the `deny ...` prefix with bwrap's observer, so try the
	// more specific network form first, on both backends.
	const proxy = PROXY_LINE.exec(line);
	if (proxy) {
		const host = proxy[1];
		const port = proxy[2];
		return {
			kind: "network",
			source: "proxy",
			op: "network-outbound",
			...(host ? { host: port ? `${host}:${port}` : host } : {}),
			backend,
			raw: line,
		};
	}

	if (backend === "seatbelt") {
		const match = SEATBELT_LINE.exec(line);
		const op = match?.[3];
		if (!op) return null;
		const target = (match?.[4] ?? "").trim();
		return {
			kind: kindForNativeOp(op),
			source: "kernel-log",
			op,
			...(target.startsWith("/") ? { path: target } : target ? { host: target } : {}),
			backend,
			raw: line,
		};
	}

	const match = BWRAP_LINE.exec(line);
	const op = match?.[1];
	if (!op) return null;
	const target = (match?.[2] ?? "").trim();
	return {
		kind: kindForNativeOp(op),
		source: "kernel-log",
		op,
		...(target ? { path: target } : {}),
		backend,
		raw: line,
	};
}

/** Parse many lines, dropping noise and anything unparseable. */
export function parseViolations(lines: readonly string[], backend: BackendName): Violation[] {
	const out: Violation[] = [];
	for (const line of lines) {
		const violation = parseViolationLine(line, backend);
		if (violation) out.push(violation);
	}
	return out;
}

/**
 * Collapse repeats. One denied write can emit the same line for every retry the
 * calling program makes, and an agent reading its tool output does not benefit
 * from seeing it forty times.
 */
export function dedupeViolations(violations: readonly Violation[]): Violation[] {
	const seen = new Set<string>();
	const out: Violation[] = [];
	for (const violation of violations) {
		const key = `${violation.kind} ${violation.op} ${violation.path ?? violation.host ?? ""}`;
		if (seen.has(key)) continue;
		seen.add(key);
		out.push(violation);
	}
	return out;
}

/**
 * Render violations for the model. The agent needs to learn what boundary it
 * hit so it can change approach, and the wording must be backend-neutral: an
 * agent that learns one platform's vocabulary will not recognise the other's.
 */
export function formatViolations(violations: readonly Violation[]): string {
	if (violations.length === 0) return "";
	const lines = violations.map((v) => {
		const target = v.path ?? v.host ?? "";
		return `  ${v.kind}: ${v.op}${target ? ` ${target}` : ""}`;
	});
	return ["sandbox denied:", ...lines].join("\n");
}
