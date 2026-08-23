/**
 * The sandbox-runtime backend.
 *
 * One implementation serves both `seatbelt` and `bwrap`: SRT abstracts the
 * platform behind `wrapWithSandboxArgv`, and the step-0 spike ran byte-identical
 * code on macOS and Linux. The backends still differ in the two places that
 * matter -- which errno a denial produces and whether it emits a violation event
 * at all -- and those differences live in `errno.ts` and `violations.ts`, keyed
 * by the backend name this class reports.
 *
 * Three things here are not obvious and are load-bearing:
 *
 * 1. **The child environment is ours, not SRT's.** `wrapWithSandboxArgv` returns
 *    `process.env` plus its own additions. Passing that would leak every
 *    credential the pi process holds. SRT's own variables survive anyway because
 *    it injects them as an `env NAME=VALUE` prefix inside the argv.
 * 2. **`SandboxManager` is a process-global singleton.** `initialize()` runs once
 *    per session; per-command divergence is only possible through `customConfig`,
 *    which is exactly what phase 3's capability retry needs and all it gets.
 * 3. **Violations arrive asynchronously**, so they are drained with a bounded
 *    settle rather than read once. They are evidence, not the verdict, so a
 *    missed line degrades reporting and never enforcement.
 */
import { type ChildProcessWithoutNullStreams, spawn } from "node:child_process";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { SandboxManager } from "@anthropic-ai/sandbox-runtime";
import { buildChildEnv } from "../env/child-env.ts";
import { HelperFsClient } from "../fs/client.ts";
import type { BackendName } from "../probe.ts";
import { whichSync } from "../probe-host.ts";
import type { CompiledProfile, FsClient, Profile, RunRequest, RunResult, SandboxBackend, Violation } from "./types.ts";
import { dedupeViolations, parseViolations } from "./violations.ts";

/**
 * Absolute paths for the search tools, for the helper to use instead of a PATH
 * lookup it may not be able to satisfy.
 */
function resolveSearchTools(): Record<string, string> {
	const env: Record<string, string> = {};
	const rg = whichSync("rg");
	const fd = whichSync("fd");
	if (rg) env.PI_ENCLAVE_RG = rg;
	if (fd) env.PI_ENCLAVE_FD = fd;
	return env;
}

/** The helper script, resolved relative to this module so it moves with the package. */
const HELPER_PATH = join(dirname(fileURLToPath(import.meta.url)), "..", "fs", "helper.mjs");

/**
 * Paths sandbox-runtime makes writable by default that pi-enclave does not
 * advertise, and therefore denies.
 *
 * `getDefaultWritePaths()` unions `~/.npm/_logs` and `~/.claude/debug` into
 * every profile. A sandbox that can write those is wider than the one the status
 * line describes, and `~/.claude/debug` in particular sits next to configuration
 * that steers another agent. The device entries in that list (`/dev/null`,
 * `/dev/stdout`, ...) are genuinely required and stay.
 */
export const UNADVERTISED_WRITE_PATHS = [join(homedir(), ".npm", "_logs"), join(homedir(), ".claude", "debug")];

/** How long to keep draining violations after a command exits. */
const VIOLATION_SETTLE_MAX_MS = 750;
/** Poll interval while draining. */
const VIOLATION_SETTLE_STEP_MS = 25;
/** Consecutive stable polls before the drain is considered complete. */
const VIOLATION_SETTLE_STABLE_POLLS = 2;

interface SrtFilesystemConfig {
	denyRead: string[];
	allowWrite: string[];
	denyWrite: string[];
}

interface SrtConfig {
	network: { allowedDomains: string[]; deniedDomains: string[] };
	filesystem: SrtFilesystemConfig;
	allowPty?: boolean;
	enableWeakerNestedSandbox?: boolean;
}

/** Translate a pi-enclave profile into sandbox-runtime's configuration shape. */
export function toSrtConfig(profile: Profile, weakerNested = false): SrtConfig {
	return {
		...(weakerNested ? { enableWeakerNestedSandbox: true } : {}),
		// "off" means no host is allowlisted. SRT still runs an egress proxy the
		// child can reach; it denies every request. Raw sockets and DNS are denied
		// by the kernel.
		network: { allowedDomains: [], deniedDomains: [] },
		filesystem: {
			denyRead: [...profile.readDeny],
			allowWrite: [...profile.writableRoots],
			denyWrite: [...UNADVERTISED_WRITE_PATHS],
		},
		allowPty: profile.allowPty,
	};
}

class SrtCompiledProfile implements CompiledProfile {
	constructor(
		readonly backend: BackendName,
		readonly profile: Profile,
		/**
		 * Which `SandboxManager` configuration this was compiled against.
		 *
		 * The manager is process-global, so a second `compile()` replaces the
		 * configuration every previously compiled profile described. Without this
		 * marker, running an older `CompiledProfile` would silently execute under
		 * the newer configuration -- a wider one, potentially -- and nothing would
		 * report it.
		 */
		readonly generation: number,
		private readonly rendered: string,
	) {}

	describe(): string {
		return this.rendered;
	}
}

export interface SrtBackendOptions {
	/** Overrides the platform-derived name. Tests use this; production does not. */
	name?: BackendName;
	/**
	 * Opt in to sandbox-runtime's weaker nested mode.
	 *
	 * Needed only where the host cannot give bubblewrap and the seccomp helper
	 * capability-bearing user namespaces -- in practice, inside an unprivileged
	 * or nested container. sandbox-runtime's own security notes call this mode
	 * "considerably weaker" and say it should be used only where additional
	 * isolation is otherwise enforced.
	 *
	 * It is off by default and never inferred. A sandbox that silently downgraded
	 * itself when the host looked awkward would be exactly the failure mode this
	 * project exists to avoid: the status line would keep saying "enforced" while
	 * the boundary quietly thinned. Callers that turn it on must say so where the
	 * user can see it -- {@link SrtBackend.weakened} exists for that.
	 */
	weakerNestedSandbox?: boolean;
}

export class SrtBackend implements SandboxBackend {
	readonly name: BackendName;
	/** True when running in sandbox-runtime's weaker nested mode. Surface this to the user. */
	readonly weakened: boolean;
	private initialized = false;
	/** Incremented on every compile; the newest is the one the manager holds. */
	private generation = 0;
	private fsClient: HelperFsClient | undefined;
	/** Which generation `fsClient` was started for. A helper outlives only its own profile. */
	private fsGeneration = 0;
	/** Prepared during compile, because HelperSpawner must be synchronous. */
	private helperArgv: string[] | undefined;
	/** Set by the extension so helper denials reach the same audit trail as shell ones. */
	onFsViolation: ((violation: Violation) => void) | undefined;

	constructor(options: SrtBackendOptions = {}) {
		this.name = options.name ?? (process.platform === "darwin" ? "seatbelt" : "bwrap");
		this.weakened = options.weakerNestedSandbox ?? false;
	}

	async compile(profile: Profile): Promise<CompiledProfile> {
		const config = toSrtConfig(profile, this.weakened);

		// The manager is global to the process, so initialise once and update
		// thereafter. Re-initialising would tear down the proxy and log monitor
		// mid-session.
		if (this.initialized) {
			SandboxManager.updateConfig(config as never);
		} else {
			await SandboxManager.initialize(config as never, undefined, true);
			this.initialized = true;
		}
		await SandboxManager.waitForNetworkInitialization();

		// Render the backend-native form once, for `/enclave backend` and for the
		// conformance suite to assert on.
		const { argv } = await SandboxManager.wrapWithSandboxArgv(":", undefined, undefined, undefined, process.cwd(), {
			commandId: "enclave-describe",
		});
		// Prepared here because the helper spawner must be synchronous, and because
		// a helper wrapped by a stale configuration would be exactly the hazard
		// assertCurrent exists to prevent.
		const helper = await SandboxManager.wrapWithSandboxArgv(
			`exec ${process.execPath} ${HELPER_PATH}`,
			undefined,
			undefined,
			undefined,
			profile.writableRoots[0] ?? process.cwd(),
			{ commandId: "enclave-fs-helper", commandText: "pi-enclave-fs" },
		);
		this.helperArgv = helper.argv;

		return new SrtCompiledProfile(this.name, profile, ++this.generation, argv.join(" "));
	}

	async run(compiled: CompiledProfile, request: RunRequest): Promise<RunResult> {
		this.assertCurrent(compiled);

		const { argv } = await SandboxManager.wrapWithSandboxArgv(
			request.command,
			undefined,
			undefined,
			request.signal,
			request.cwd,
			{ commandId: request.commandId, commandText: request.command },
		);

		const exitCode = await this.spawnSandboxed(argv, request);
		const violations = await this.drainViolations(request.commandId);
		return { exitCode, violations };
	}

	/**
	 * Refuse to execute against a profile the manager no longer holds.
	 *
	 * `wrapWithSandboxArgv` reads the manager's current configuration and ignores
	 * whatever `CompiledProfile` the caller passed, so a stale one would run under
	 * different -- possibly wider -- rules while appearing to honour the profile
	 * in hand. Failing closed here converts that into an error instead of a quiet
	 * privilege change.
	 */
	private assertCurrent(compiled: CompiledProfile): void {
		if (!(compiled instanceof SrtCompiledProfile)) {
			throw new Error("pi-enclave: this backend can only run profiles it compiled itself");
		}
		if (compiled.generation !== this.generation) {
			throw new Error(
				`pi-enclave: refusing to run against a stale profile (generation ${compiled.generation}, ` +
					`current ${this.generation}). sandbox-runtime is process-global, so only the most ` +
					"recently compiled profile is in force.",
			);
		}
	}

	private spawnSandboxed(argv: string[], request: RunRequest): Promise<number | null> {
		const [command, ...args] = argv;
		if (!command) throw new Error("sandbox-runtime returned an empty argv");

		return new Promise((resolve, reject) => {
			const child = spawn(command, args, {
				cwd: request.cwd,
				// Our allowlist, never `process.env` and never the env SRT returns.
				env: request.env,
				// Own process group, so a timeout kills the whole tree rather than
				// leaving the sandboxed grandchildren running.
				detached: true,
				stdio: ["ignore", "pipe", "pipe"],
			});

			child.stdout?.on("data", (chunk: Buffer) => request.onData?.(chunk));
			child.stderr?.on("data", (chunk: Buffer) => request.onData?.(chunk));

			let timedOut = false;
			const killTree = () => {
				if (child.pid === undefined) return;
				try {
					process.kill(-child.pid, "SIGKILL");
				} catch {
					child.kill("SIGKILL");
				}
			};

			const timer =
				request.timeout === undefined || request.timeout <= 0
					? undefined
					: setTimeout(() => {
							timedOut = true;
							killTree();
						}, request.timeout * 1000);

			const onAbort = () => killTree();
			request.signal?.addEventListener("abort", onAbort, { once: true });

			const cleanup = () => {
				if (timer) clearTimeout(timer);
				request.signal?.removeEventListener("abort", onAbort);
			};

			child.on("error", (error) => {
				cleanup();
				reject(error);
			});

			child.on("close", (code) => {
				cleanup();
				if (request.signal?.aborted) reject(new Error("aborted"));
				else if (timedOut) reject(new Error(`timeout:${request.timeout}`));
				else resolve(code);
			});
		});
	}

	/**
	 * Collect this command's violations, waiting for the stream to settle.
	 *
	 * Kernel-log violations are delivered asynchronously through a log monitor,
	 * so reading the store the instant a command exits under-reports. The spike
	 * used a flat sleep; this polls until the count is stable, which is both
	 * faster in the common case (no violations at all) and more complete when a
	 * command produced a burst.
	 *
	 * The bound matters more than the completeness: violations are evidence for
	 * the audit log and the agent's benefit, never the thing that decides whether
	 * an operation was permitted, so waiting longer buys very little.
	 */
	private async drainViolations(commandId: string): Promise<Violation[]> {
		const store = SandboxManager.getSandboxViolationStore();
		const deadline = Date.now() + VIOLATION_SETTLE_MAX_MS;
		let previousCount = -1;
		let stablePolls = 0;

		while (Date.now() < deadline && stablePolls < VIOLATION_SETTLE_STABLE_POLLS) {
			const count = store.getViolationsForCommand(commandId).length;
			stablePolls = count === previousCount ? stablePolls + 1 : 0;
			previousCount = count;
			await new Promise((resolve) => setTimeout(resolve, VIOLATION_SETTLE_STEP_MS));
		}

		const lines = store.getViolationsForCommand(commandId).map((event) => event.line);
		return dedupeViolations(parseViolations(lines, this.name));
	}

	/**
	 * The sandboxed filesystem helper for this profile, started on first use and
	 * reused thereafter.
	 *
	 * One helper per backend, not per call: it costs about 40 ms to start and
	 * well under a tenth of a millisecond per operation, so per-call spawning
	 * would add a hundredfold overhead to every read for no security benefit --
	 * the profile is identical either way.
	 */
	fs(compiled: CompiledProfile): FsClient {
		this.assertCurrent(compiled);

		// A helper is bound to the profile it was started under -- the kernel
		// applied that profile at exec and nothing can change it afterwards. When
		// the profile is recompiled, the running helper is still enforcing the old
		// one: it would refuse writes to the new workspace and, far worse, permit
		// reads the new profile denies. Retire it.
		//
		// The conformance suite found this by leaking a secret through a symlink,
		// because a cached helper was still enforcing an earlier scenario's
		// read-deny list.
		if (this.fsClient && this.fsGeneration !== this.generation) {
			const stale = this.fsClient;
			this.fsClient = undefined;
			void stale.dispose();
		}

		if (!this.fsClient) {
			this.fsGeneration = this.generation;
			this.fsClient = new HelperFsClient({
				compiled,
				spawnHelper: () => this.spawnHelper(compiled),
				...(this.onFsViolation ? { onViolation: this.onFsViolation } : {}),
			});
		}
		return this.fsClient;
	}

	/**
	 * Start the helper inside the sandbox.
	 *
	 * `exec` replaces the shell with node, so the helper is the process the
	 * profile applies to rather than a child of one -- otherwise the shell would
	 * linger as an unsandboxed parent holding the pipes.
	 */
	private spawnHelper(compiled: CompiledProfile): ChildProcessWithoutNullStreams {
		// The argv is prepared during compile(): the spawner contract is
		// synchronous, and wrapping here would also race the configuration that
		// assertCurrent exists to pin down.
		const argv = this.helperArgv;
		if (!argv) throw new Error("pi-enclave: the helper argv was not prepared; compile() must run first");

		const [bin, ...args] = argv;
		if (!bin) throw new Error("pi-enclave: sandbox-runtime returned an empty argv for the helper");

		return spawn(bin, args, {
			cwd: compiled.profile.writableRoots[0] ?? process.cwd(),
			// The same allowlist the shell gets -- the helper reads files on the
			// agent's behalf, so a credential in its environment is exactly as
			// disclosable as one in bash's -- plus the resolved search-tool paths.
			//
			// Resolving them here rather than inside the sandbox is the point: the
			// helper has no network and cannot fetch a missing tool, so the lookup
			// has to happen on this side while it still can.
			env: {
				...buildChildEnv(process.env, { readDeny: compiled.profile.readDeny }),
				...resolveSearchTools(),
			},
			stdio: ["pipe", "pipe", "pipe"],
		}) as ChildProcessWithoutNullStreams;
	}

	async dispose(): Promise<void> {
		await this.fsClient?.dispose();
		this.fsClient = undefined;
		if (!this.initialized) return;
		await SandboxManager.reset();
		this.initialized = false;
	}
}
