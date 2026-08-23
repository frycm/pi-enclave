/**
 * The backend contract.
 *
 * A `SandboxBackend` is the only thing in pi-enclave that executes anything.
 * Everything above it -- tools, policy, the reviewer -- reaches the OS through
 * this interface, and the backend-conformance suite (step 3) is the contract
 * every implementation must satisfy. SRT-backed Seatbelt and bwrap are the
 * first two implementations; Docker and a microVM are meant to slot in without
 * the layers above noticing.
 */
import type { BackendName } from "../probe.ts";

export type { BackendName };

// ---------------------------------------------------------------------------
// Profile
// ---------------------------------------------------------------------------

/**
 * What the sandbox permits. Phase 1 ships exactly one mode.
 *
 * Note the asymmetry, which is SRT's model and therefore ours (see
 * docs/step-0-srt-findings.md): **writes are an allow-list** -- only
 * `writableRoots` are writable -- while **reads are a deny-list** -- everything
 * is readable except `readDeny`. There is no way to express "the agent may only
 * read the workspace" on either backend.
 */
export interface Profile {
	mode: "workspace-write";
	/** Absolute paths that may be written. Everything else is read-only. */
	writableRoots: readonly string[];
	/** Absolute paths that may not be read, even though reads are otherwise open. */
	readDeny: readonly string[];
	/**
	 * "off" means no host is allowlisted. It does *not* mean no network stack:
	 * both backends still run an egress proxy the child can reach, which denies
	 * every request. Raw sockets and DNS are denied by the kernel.
	 */
	network: "off";
	/**
	 * PTY allocation. Denied by default on both backends, which breaks `vim`,
	 * `less`, and anything that wants a terminal -- so the dev profile enables it.
	 */
	allowPty: boolean;
}

/**
 * A profile compiled for one backend, ready to execute against. Produced once
 * per session and treated as immutable: widening happens by compiling a
 * *separate* one-shot profile (phase 3's capability retry), never by mutating
 * this.
 */
export interface CompiledProfile {
	backend: BackendName;
	/** The profile this was compiled from. Retained so denials can be classified. */
	profile: Profile;
	/**
	 * Backend-native representation, for `/enclave backend` and for the
	 * conformance suite to assert on: the Seatbelt SBPL or the bwrap argv.
	 */
	describe(): string;
}

// ---------------------------------------------------------------------------
// Violations
// ---------------------------------------------------------------------------

export type ViolationKind = "read" | "write" | "network" | "exec" | "socket";

/**
 * How the denial reached us. The three sources have different reliability, and
 * the distinction is not cosmetic:
 *
 * - `errno`      -- exact and synchronous, from the syscall the helper made.
 * - `kernel-log` -- a parsed log line, asynchronous, backend-specific text.
 * - `proxy`      -- a userspace decision by the egress proxy, not the kernel.
 */
export type ViolationSource = "errno" | "kernel-log" | "proxy";

export interface Violation {
	kind: ViolationKind;
	source: ViolationSource;
	/** The operation that was denied: "openat", "readFile", "connect", … */
	op: string;
	/** Filesystem target, when there is one. */
	path?: string;
	/** Network target, when there is one. */
	host?: string;
	backend: BackendName;
	/** The unparsed evidence, kept for the audit log. */
	raw?: string;
}

// ---------------------------------------------------------------------------
// Execution
// ---------------------------------------------------------------------------

/** A complete environment for the child. Nothing outside this map is inherited. */
export type ChildEnv = Readonly<Record<string, string>>;

export interface RunRequest {
	command: string;
	cwd: string;
	env: ChildEnv;
	/**
	 * Correlation key for violations from this invocation. Use the tool-use id,
	 * never the command text: sandbox-runtime compares only the first 100
	 * characters, so two long commands sharing a prefix cross-attribute.
	 */
	commandId: string;
	onData?: (chunk: Buffer) => void;
	signal?: AbortSignal;
	/** Seconds. */
	timeout?: number;
}

export interface RunResult {
	/** Null when the process was killed by a signal. */
	exitCode: number | null;
	violations: Violation[];
}

export interface SandboxBackend {
	readonly name: BackendName;
	/** Compile a profile for this backend. Called once per session. */
	compile(profile: Profile): Promise<CompiledProfile>;
	/** Execute a shell command under the compiled profile. */
	run(compiled: CompiledProfile, request: RunRequest): Promise<RunResult>;
	/** Start (or reuse) the sandboxed filesystem helper for this profile. */
	fs(compiled: CompiledProfile): FsClient;
	/** Release any long-lived resources: the helper, a container, a log monitor. */
	dispose(): Promise<void>;
}

/**
 * Filesystem operations, all performed inside the sandbox by the helper rather
 * than by the pi process. The names match the pi tool operations they back, so
 * `ReadOperations.readFile` maps to `FsClient.readFile` and so on.
 */
export interface FsClient {
	readFile(path: string): Promise<Buffer>;
	/** The first `bytes` of a file, for type sniffing without a full read. */
	head(path: string, bytes: number): Promise<Buffer>;
	writeFile(path: string, content: string): Promise<void>;
	mkdir(path: string): Promise<void>;
	access(path: string, mode: "read" | "write"): Promise<void>;
	stat(path: string): Promise<{ isDirectory: () => boolean }>;
	readdir(path: string): Promise<string[]>;
	exists(path: string): Promise<boolean>;
	glob(pattern: string, cwd: string, options: { ignore: string[]; limit: number }): Promise<string[]>;
	grep(
		args: readonly string[],
		options?: { limit?: number; signal?: AbortSignal; path?: string },
	): Promise<{ stdout: string; exitCode: number | null; limitReached?: boolean; capped?: boolean }>;
}

/**
 * Thrown by `FsClient` when the kernel denied an operation, as distinct from an
 * ordinary failure. Carries the classified violation so callers report the same
 * thing whatever the backend and whatever errno it used.
 */
export class SandboxDenied extends Error {
	readonly violation: Violation;

	constructor(violation: Violation, message?: string) {
		super(message ?? `sandbox denied ${violation.op}${violation.path ? ` ${violation.path}` : ""}`);
		this.name = "SandboxDenied";
		this.violation = violation;
	}
}
