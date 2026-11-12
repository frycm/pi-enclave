/**
 * Resource limits for sandboxed shell commands (#24).
 *
 * None of this is a security boundary. It is availability: an unattended agent
 * on a server shares the host with the services it manages, and a command that
 * hangs on stdin, prints gigabytes, fills the root filesystem, forks without
 * end or takes the host's memory hurts them without crossing the sandbox, so
 * no other layer reports it. Each backend applies the same pieces:
 *
 * - a wall-clock limit when the model passes none, and a ceiling on the ones
 *   it passes ({@link effectiveTimeout});
 * - a cap on the bytes forwarded to pi, after which the command is killed
 *   ({@link OutputCap}); pi keeps the full output of a long command in a host
 *   temp file, so an unbounded stream is a disk problem outside the sandbox;
 * - kernel resource limits set by the sandboxed shell itself before the
 *   command runs ({@link limitPrefix}), so they apply after the namespaces are
 *   in place and the command cannot raise them;
 * - a free-space floor on the writable roots ({@link freeSpaceIssue}): below
 *   it, a command still runs, but with a file size limit of zero, so it can
 *   delete and inspect and cannot grow anything.
 */
import { statfsSync } from "node:fs";
import type { ResourceLimits } from "./types.ts";

/** The container backend's limits before #24 made them configurable. */
export const DEFAULT_CONTAINER_LIMITS: ResourceLimits["container"] = {
	pids: 256,
	memoryMb: 512,
	cpus: 2,
	shmMb: 32,
	tmpMb: 128,
};

export interface EffectiveTimeout {
	seconds: number;
	/** The model passed no timeout, so the default applied. */
	defaulted: boolean;
	/** The model asked for more than the maximum. */
	clamped: boolean;
}

/** The timeout a command actually gets. Without limits, the request unchanged. */
export function effectiveTimeout(
	requested: number | undefined,
	limits: ResourceLimits | undefined,
): EffectiveTimeout | undefined {
	if (!limits) return requested === undefined ? undefined : { seconds: requested, defaulted: false, clamped: false };
	const max = limits.maxTimeoutSec;
	if (requested === undefined) {
		return { seconds: Math.min(limits.defaultTimeoutSec, max), defaulted: true, clamped: false };
	}
	return requested > max
		? { seconds: max, defaulted: false, clamped: true }
		: { seconds: requested, defaulted: false, clamped: false };
}

/** The line appended to the output when the limit, not the model, ended a command. */
export function timeoutNote(timeout: EffectiveTimeout, limits: ResourceLimits): string | undefined {
	if (timeout.defaulted) {
		return (
			`\npi-enclave: no timeout was given, so the default of ${timeout.seconds}s applied ` +
			`(sandbox.limits.defaultTimeoutSec). Pass a timeout of up to ${limits.maxTimeoutSec}s for a longer command; ` +
			"commands that wait for input or follow a file (tail -f) never finish on their own.\n"
		);
	}
	if (timeout.clamped) {
		return `\npi-enclave: the requested timeout was above the maximum, so ${timeout.seconds}s applied (sandbox.limits.maxTimeoutSec).\n`;
	}
	return undefined;
}

/**
 * Counts what a command printed and says when it has printed too much.
 *
 * `push` forwards a chunk, trimmed to what still fits, and returns false once
 * the cap is reached; the caller then kills the command. Nothing past the cap
 * reaches pi.
 */
export class OutputCap {
	private sent = 0;
	private hit = false;
	private readonly max: number;

	constructor(
		maxMb: number | undefined,
		private readonly forward: ((chunk: Buffer) => void) | undefined,
	) {
		this.max = maxMb === undefined ? Number.POSITIVE_INFINITY : maxMb * 1024 * 1024;
	}

	get exceeded(): boolean {
		return this.hit;
	}

	push(chunk: Buffer): boolean {
		if (this.hit) return false;
		const room = this.max - this.sent;
		if (chunk.length <= room) {
			this.sent += chunk.length;
			this.forward?.(chunk);
			return true;
		}
		if (room > 0) this.forward?.(chunk.subarray(0, room));
		this.sent = this.max;
		this.hit = true;
		return false;
	}

	note(maxMb: number): string {
		return `\npi-enclave: the command printed more than ${maxMb} MB, so the rest was discarded and the command was killed (sandbox.limits.maxOutputMb). Redirect large output to a file and read parts of it.\n`;
	}
}

/** Which limits a platform's shell can set, for the prefix and for `/enclave status`. */
export function enforcedRlimits(platform: NodeJS.Platform): ("fileSize" | "openFiles" | "processes" | "memory")[] {
	// macOS counts RLIMIT_NPROC across every process of the user, not per
	// sandbox, and does not enforce RLIMIT_DATA at all, so neither is set there.
	return platform === "linux" ? ["fileSize", "openFiles", "processes", "memory"] : ["fileSize", "openFiles"];
}

/**
 * The shell text the sandboxed bash runs before the command.
 *
 * Plain `ulimit -X N` sets the soft and the hard limit together, and an
 * unprivileged process cannot raise a hard limit again, so the command cannot
 * undo it. A limit already below the configured value is left alone rather
 * than "raised" (which would fail). If a limit cannot be set the command does
 * not run. RLIMIT_NPROC is set last because the checks before it fork.
 *
 * `fileSizeZero` is the free-space floor: no file may grow at all.
 */
export function limitPrefix(
	limits: ResourceLimits | undefined,
	platform: NodeJS.Platform,
	fileSizeZero = false,
): string {
	if (!limits) return "";
	const enforced = enforcedRlimits(platform);
	const settings: [string, number][] = [];
	if (enforced.includes("fileSize")) settings.push(["-f", fileSizeZero ? 0 : limits.fileSizeMb * 1024]);
	if (enforced.includes("openFiles")) settings.push(["-n", limits.openFiles]);
	if (enforced.includes("memory")) settings.push(["-d", limits.memoryMb * 1024]);
	if (enforced.includes("processes")) settings.push(["-u", limits.processes]);
	if (settings.length === 0) return "";
	const fn = "__pi_enclave_limit";
	return (
		`${fn}() { local h; h=$(ulimit -H "$1") || return 1; ` +
		`if [ "$h" = unlimited ] || [ "$h" -gt "$2" ]; then ulimit "$1" "$2" || return 1; fi; }; ` +
		`${settings.map(([flag, value]) => `${fn} ${flag} ${value}`).join(" && ")} || ` +
		`{ echo "pi-enclave: could not apply resource limits; the command did not run" >&2; exit 125; }; ` +
		`unset -f ${fn}\n`
	);
}

/** Free bytes for an unprivileged user on the filesystem holding `path`, or undefined. */
export type FreeSpaceProbe = (path: string) => number | undefined;

export const statfsFreeBytes: FreeSpaceProbe = (path) => {
	try {
		const stats = statfsSync(path);
		return Number(stats.bavail) * Number(stats.bsize);
	} catch {
		// A root that does not exist yet has no filesystem to fill.
		return undefined;
	}
};

/** The first writable root below the free-space floor, as a message, or undefined. */
export function freeSpaceIssue(
	paths: readonly string[],
	limits: ResourceLimits | undefined,
	probe: FreeSpaceProbe = statfsFreeBytes,
): string | undefined {
	if (!limits || limits.minFreeDiskMb <= 0) return undefined;
	const floor = limits.minFreeDiskMb * 1024 * 1024;
	for (const path of paths) {
		const free = probe(path);
		if (free !== undefined && free < floor) {
			return (
				`pi-enclave: ${path} has ${Math.floor(free / (1024 * 1024))} MB free, below the ${limits.minFreeDiskMb} MB floor ` +
				"(sandbox.limits.minFreeDiskMb), so this command ran with a file size limit of zero: it can delete and inspect files, not grow them."
			);
		}
	}
	return undefined;
}

/** One line for `/enclave status`. */
export function describeLimits(limits: ResourceLimits | undefined, backend: string, platform: NodeJS.Platform): string {
	if (!limits) return "not configured";
	const parts = [
		`timeout ${limits.defaultTimeoutSec}s default, ${limits.maxTimeoutSec}s max`,
		`output ${limits.maxOutputMb} MB`,
		`file ${limits.fileSizeMb} MB`,
		`open files ${limits.openFiles}`,
		`free-space floor ${limits.minFreeDiskMb} MB`,
	];
	if (backend === "docker" || backend === "podman") {
		const c = limits.container;
		parts.push(`cgroup pids ${c.pids}, memory ${c.memoryMb} MB, cpus ${c.cpus}, /tmp ${c.tmpMb} MB, shm ${c.shmMb} MB`);
	} else if (enforcedRlimits(platform).includes("processes")) {
		parts.push(`processes ${limits.processes}`, `memory ${limits.memoryMb} MB (RLIMIT_DATA, per process)`);
	} else {
		parts.push("processes and memory NOT limited on this platform");
	}
	return parts.join("; ");
}
