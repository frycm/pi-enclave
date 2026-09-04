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
import { closeSync, lstatSync, mkdirSync, openSync } from "node:fs";
import { dirname, isAbsolute, join } from "node:path";
import { fileURLToPath } from "node:url";
import { getDefaultWritePaths, SandboxManager } from "@anthropic-ai/sandbox-runtime";
import { buildChildEnv } from "../env/child-env.ts";
import { HelperFsClient } from "../fs/client.ts";
import type { BackendName } from "../probe.ts";
import { hostRuntimeSafety, whichSync } from "../probe-host.ts";
import { shellCapabilityIssue, validateReadCapability, validateWriteCapability } from "./capability.ts";
import { canonical, isUnder } from "./paths.ts";
import {
	type CompiledProfile,
	type FsClient,
	type FsClientLease,
	type Profile,
	type RunRequest,
	type RunResult,
	SANDBOX_TMPDIR,
	type SandboxBackend,
	type Violation,
} from "./types.ts";
import { dedupeViolations, parseViolations } from "./violations.ts";

/**
 * Absolute paths for the search tools, for the helper to use instead of a PATH
 * lookup it may not be able to satisfy.
 */
function resolveSearchTools(rg?: string, fd?: string): Record<string, string> {
	const env: Record<string, string> = {};
	if (rg) env.PI_ENCLAVE_RG = rg;
	if (fd) env.PI_ENCLAVE_FD = fd;
	return env;
}

/** Single-quote a string for a POSIX shell; the only safe quoting for arbitrary paths. */
export function shellQuote(value: string): string {
	return `'${value.replace(/'/g, `'\\''`)}'`;
}

/**
 * Deny entries in the spelling each backend needs.
 *
 * Neither backend denies a path as written when a symlink sits anywhere in it.
 * Seatbelt matches `subpath` rules on the canonical path the kernel sees, and
 * sandbox-runtime keeps the link spelling -- so on macOS a `readDeny` entry
 * that is a symlink, *or sits under one*, denied nothing (F13 found the first,
 * F14 the second: `<agent-link>/auth.json` is exactly the credential path
 * shape). bwrap, given a link, tries to mount a tmpfs on it and aborts at
 * startup.
 *
 * Every component is resolved, with the missing tail of an absent path
 * re-joined onto its deepest existing ancestor. On macOS the canonical form is
 * denied *as well* (the rule only widens); on Linux it is denied *instead*.
 * Recomputed on every translation, so a retargeted link is re-denied at its
 * new target by the re-wrap.
 */
function withResolvedTargets(readDeny: readonly string[], platform: NodeJS.Platform = process.platform): string[] {
	const out: string[] = [];
	for (const path of readDeny) {
		const resolved = canonical(path);
		if (resolved === path || platform === "darwin") out.push(path);
		if (resolved !== path && !out.includes(resolved)) out.push(resolved);
	}
	return out;
}

/**
 * What the deny roots resolve to right now, as one comparable string.
 *
 * Existence alone is not enough: sandbox-runtime masks the *target* of a deny
 * entry that is a symlink, so a link retargeted from one existing directory to
 * another keeps the old mask while reads follow the new target. The snapshot
 * therefore carries the canonical path and, for a link, the link's own
 * identity (inode and mtime), so a retarget or a replacement changes it.
 */
function denySnapshot(profile: Profile): string {
	return [
		...profile.readDeny.map((path) => ({ kind: "r", path })),
		...(profile.writeDeny ?? []).map((path) => ({ kind: "w", path })),
	]
		.map(({ kind, path }) => {
			let link = "";
			try {
				const own = lstatSync(path);
				if (own.isSymbolicLink()) link = `@${own.ino}:${own.mtimeMs}`;
			} catch {
				return `${kind}:0${path}`;
			}
			return `${kind}:1${path}>${canonical(path)}${link}`;
		})
		.join("\n");
}

/** The helper script, resolved relative to this module so it moves with the package. */
const HELPER_PATH = join(dirname(fileURLToPath(import.meta.url)), "..", "fs", "helper.mjs");

/**
 * The temporary directory sandbox-runtime gives every child.
 *
 * SRT injects `TMPDIR=<this>` into the child's argv prefix and makes the path
 * writable in every profile, so temp-file writers land somewhere the sandbox
 * allows. It is therefore part of the boundary whether pi-enclave mentions it
 * or not; the honest move is to advertise it as a writable root rather than
 * leave the status line describing a narrower sandbox than the one in force.
 * Mirrors SRT's own resolution, including its two environment overrides.
 */
export function srtTmpDir(env: NodeJS.ProcessEnv = process.env): string {
	return env.CLAUDE_CODE_TMPDIR || env.CLAUDE_TMPDIR || SANDBOX_TMPDIR;
}

/**
 * Compare two paths, treating `/private/tmp` and `/tmp` as the same place on
 * macOS -- where they are aliases -- and as two places everywhere else. On
 * Linux `/private/tmp/claude` is a distinct directory that SRT would make
 * writable if it existed, so it must not be folded into the advertised root.
 */
function samePath(a: string, b: string, platform: NodeJS.Platform = process.platform): boolean {
	if (platform !== "darwin") return a === b;
	const strip = (p: string) => p.replace(/^\/private(?=\/)/, "");
	return strip(a) === strip(b);
}

/**
 * Writable bind mounts that pin every movable ancestor of a Linux write deny.
 *
 * A read-only bind on `workspace/.git/hooks` protects the directory's inode,
 * but Linux still permits renaming its writable `.git` parent and creating a
 * replacement tree at the old pathname. Making each ancestor below the nearest
 * writable root a mount point makes those renames fail with `EBUSY`, while the
 * ancestors themselves remain writable for ordinary Git metadata updates.
 *
 * The roots are already mount points. Returning pins shallow-first is
 * load-bearing: a later bind of an ancestor would otherwise cover an earlier
 * nested mount and remove the pin.
 */
export function linuxWriteMountPins(
	writableRoots: readonly string[],
	writeDeny: readonly string[],
	platform: NodeJS.Platform = process.platform,
): string[] {
	if (platform !== "linux") return [];
	const roots = [...new Set(writableRoots.map(canonical))].sort((a, b) => b.length - a.length);
	const pins = new Set<string>();
	for (const denied of writeDeny) {
		const target = canonical(denied);
		const root = roots.find((candidate) => isUnder(target, candidate));
		if (!root) continue;
		for (let parent = dirname(target); parent !== root && isUnder(parent, root); parent = dirname(parent)) {
			pins.add(parent);
		}
	}
	return [...pins].sort((a, b) => {
		const depth = a.split("/").length - b.split("/").length;
		return depth || a.localeCompare(b);
	});
}

/**
 * Every path sandbox-runtime makes writable by default, partitioned against
 * the profile: advertised roots are left alone, the device entries (`/dev/null`,
 * `/dev/stdout`, ...) are genuinely required and stay, and everything else is
 * denied.
 *
 * This is computed from `getDefaultWritePaths()` rather than from a hand-kept
 * list, so a future SRT default cannot silently widen the sandbox: it is either
 * in the profile or it is denied. `~/.npm/_logs` and `~/.claude/debug` fall in
 * the denied set -- the latter sits next to configuration that steers another
 * agent.
 */
export function partitionSrtDefaults(
	writableRoots: readonly string[],
	platform: NodeJS.Platform = process.platform,
): {
	advertised: string[];
	devices: string[];
	denied: string[];
} {
	const advertised: string[] = [];
	const devices: string[] = [];
	const denied: string[] = [];
	for (const path of getDefaultWritePaths()) {
		if (path.startsWith("/dev/")) devices.push(path);
		else if (writableRoots.some((root) => samePath(root, path, platform))) advertised.push(path);
		else denied.push(path);
	}
	return { advertised, devices, denied };
}

/**
 * The profile as it is actually in force under sandbox-runtime: the caller's
 * roots plus the SRT temp directory the child is pointed at.
 */
export function effectiveProfile(
	profile: Profile,
	platform: NodeJS.Platform = process.platform,
	env: NodeJS.ProcessEnv = process.env,
): Profile {
	const tmp = srtTmpDir(env);
	const hasAmbientOverride = Boolean(env.CLAUDE_CODE_TMPDIR || env.CLAUDE_TMPDIR);
	const tmpContained =
		isAbsolute(tmp) && profile.writableRoots.some((root) => isUnder(canonical(tmp), canonical(root)));
	if (hasAmbientOverride && tmp !== SANDBOX_TMPDIR && !tmpContained) {
		throw new Error(
			`pi-enclave: refusing ambient sandbox TMPDIR ${tmp}; ` +
				"CLAUDE_CODE_TMPDIR/CLAUDE_TMPDIR may only select a path already inside a configured writable root",
		);
	}
	const roots = profile.writableRoots.some(
		(root) => samePath(root, tmp, platform) || isUnder(canonical(tmp), canonical(root)),
	)
		? profile.writableRoots
		: [...profile.writableRoots, tmp];
	// sandbox-runtime's allowPty is macOS-only: bubblewrap never restricts
	// pseudo-terminals. The compiled profile says what is in force, so on Linux
	// it says PTYs are allowed whatever was asked -- a status line reading "pty
	// off" there would be describing a restriction that does not exist.
	const allowPty = platform === "linux" ? true : profile.allowPty;
	return { ...profile, writableRoots: roots, tmpDir: tmp, allowPty };
}

/**
 * Materialize trusted deny mount points before bwrap compiles its bind mounts.
 * Read-deny credential paths are deliberately never created as a side effect.
 */
export function materializeWriteDenyAnchors(profile: Profile): void {
	const writableRoots = profile.writableRoots.map(canonical);
	const assertContained = (path: string) => {
		const resolved = canonical(path);
		if (!writableRoots.some((root) => isUnder(resolved, root))) {
			throw new Error(
				`pi-enclave: refusing to materialize write-deny anchor outside writable roots: ${path} -> ${resolved}`,
			);
		}
	};
	for (const path of profile.materializeWriteDeny ?? []) {
		assertContained(path);
		try {
			const stat = lstatSync(path);
			if (!stat.isDirectory() || stat.isSymbolicLink()) {
				throw new Error(`pi-enclave: protected write-deny anchor is not a real directory: ${path}`);
			}
		} catch (error) {
			if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
			try {
				const parent = lstatSync(dirname(path));
				if (!parent.isDirectory() || parent.isSymbolicLink()) {
					throw new Error(`pi-enclave: protected write-deny parent is not a real directory: ${dirname(path)}`);
				}
			} catch (parentError) {
				if ((parentError as NodeJS.ErrnoException).code === "ENOENT") {
					throw new Error(`pi-enclave: protected write-deny parent does not exist: ${dirname(path)}`);
				}
				throw parentError;
			}
			mkdirSync(path, { recursive: false, mode: 0o700 });
		}
	}
	for (const path of profile.materializeWriteDenyFiles ?? []) {
		assertContained(path);
		try {
			const stat = lstatSync(path);
			if (!stat.isFile() || stat.isSymbolicLink()) {
				throw new Error(`pi-enclave: protected write-deny anchor is not a real file: ${path}`);
			}
		} catch (error) {
			if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
			try {
				const parent = lstatSync(dirname(path));
				if (!parent.isDirectory() || parent.isSymbolicLink()) {
					throw new Error(`pi-enclave: protected write-deny parent is not a real directory: ${dirname(path)}`);
				}
			} catch (parentError) {
				if ((parentError as NodeJS.ErrnoException).code === "ENOENT") {
					throw new Error(`pi-enclave: protected write-deny parent does not exist: ${dirname(path)}`);
				}
				throw parentError;
			}
			const fd = openSync(path, "wx", 0o600);
			closeSync(fd);
		}
	}
}

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
	ripgrep?: { command: string };
	bwrapPath?: string;
	socatPath?: string;
}

interface HostToolPaths {
	rg?: string;
	fd?: string;
	bwrap?: string;
	socat?: string;
}

/**
 * Translate a pi-enclave profile into sandbox-runtime's configuration shape.
 *
 * Expects the {@link effectiveProfile}; the SRT defaults it does not advertise
 * are denied explicitly.
 */
export function toSrtConfig(
	profile: Profile,
	weakerNested = false,
	platform: NodeJS.Platform = process.platform,
	hostTools: HostToolPaths = {},
): SrtConfig {
	const { denied } = partitionSrtDefaults(profile.writableRoots, platform);
	const denyWrite = [...new Set([...denied, ...withResolvedTargets(profile.writeDeny ?? [], platform)])];
	const mountPins = linuxWriteMountPins(profile.writableRoots, denyWrite, platform);
	const allowWrite =
		platform === "linux"
			? [...new Set([...profile.writableRoots, ...mountPins])]
					.map((path, index) => ({ path, index }))
					.sort((a, b) => a.path.split("/").length - b.path.split("/").length || a.index - b.index)
					.map(({ path }) => path)
			: [...profile.writableRoots];
	return {
		...(weakerNested ? { enableWeakerNestedSandbox: true } : {}),
		...(hostTools.rg ? { ripgrep: { command: hostTools.rg } } : {}),
		...(platform === "linux" && hostTools.bwrap ? { bwrapPath: hostTools.bwrap } : {}),
		...(platform === "linux" && hostTools.socat ? { socatPath: hostTools.socat } : {}),
		// "off" means no host is allowlisted. SRT still runs an egress proxy the
		// child can reach; it denies every request. Raw sockets and DNS are denied
		// by the kernel.
		network: { allowedDomains: [], deniedDomains: [] },
		filesystem: {
			denyRead: withResolvedTargets(profile.readDeny, platform),
			allowWrite,
			denyWrite,
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
	private helperDenySnapshot = "";
	private hostTools: HostToolPaths = {};
	/** Set by the extension so helper denials reach the same audit trail as shell ones. */
	onFsViolation: ((violation: Violation) => void) | undefined;

	constructor(options: SrtBackendOptions = {}) {
		this.name = options.name ?? (process.platform === "darwin" ? "seatbelt" : "bwrap");
		this.weakened = options.weakerNestedSandbox ?? false;
	}

	async compile(requested: Profile): Promise<CompiledProfile> {
		const profile = effectiveProfile(requested);
		const pathSafety = hostRuntimeSafety(profile.writableRoots);
		if (!pathSafety.ok) {
			throw new Error(`pi-enclave: refusing unsafe host executable lookup. ${pathSafety.detail}`);
		}
		const rg = whichSync("rg");
		const fd = whichSync("fd");
		const bwrap = process.platform === "linux" ? whichSync("bwrap") : null;
		const socat = process.platform === "linux" ? whichSync("socat") : null;
		this.hostTools = {
			...(rg ? { rg } : {}),
			...(fd ? { fd } : {}),
			...(bwrap ? { bwrap } : {}),
			...(socat ? { socat } : {}),
		};
		materializeWriteDenyAnchors(profile);
		const config = toSrtConfig(profile, this.weakened, process.platform, this.hostTools);

		// SRT points the child's TMPDIR here but never creates it. On macOS a
		// child can mkdir it itself (the profile allows the path); on Linux bwrap
		// skips an absent bind, leaving TMPDIR pointing nowhere and `mktemp`
		// failing. Creating it makes both platforms behave the same.
		try {
			mkdirSync(profile.tmpDir ?? SANDBOX_TMPDIR, { recursive: true, mode: 0o700 });
		} catch {
			// A temp directory that cannot be created is the child's problem to
			// report, not a reason to refuse to compile.
		}

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
		const { argv } = await SandboxManager.wrapWithSandboxArgv(":", "/bin/bash", undefined, undefined, process.cwd(), {
			commandId: "enclave-describe",
		});
		// Prepared here because the helper spawner must be synchronous, and because
		// a helper wrapped by a stale configuration would be exactly the hazard
		// assertCurrent exists to prevent.
		await this.wrapHelper(profile);

		return new SrtCompiledProfile(this.name, profile, ++this.generation, argv.join(" "));
	}

	/**
	 * Wrap the helper launch under the manager's current configuration, and
	 * remember which deny roots existed when it was done.
	 *
	 * bwrap can only mask a directory that is there: sandbox-runtime stats each
	 * `denyRead` entry at wrap time and skips the absent ones. A shell command is
	 * wrapped per invocation, so it always sees the filesystem as it is. The
	 * helper is wrapped once and lives for the session -- so a `~/.aws` created
	 * after startup would be readable through it until this snapshot notices.
	 */
	private async wrapHelper(profile: Profile): Promise<void> {
		// The command is a shell string that /bin/bash -c will parse, so both
		// paths are quoted: a checkout under "Application Support" or a node
		// under a directory with a space would otherwise split into arguments.
		const helper = await SandboxManager.wrapWithSandboxArgv(
			`exec ${shellQuote(process.execPath)} ${shellQuote(HELPER_PATH)}`,
			"/bin/bash",
			undefined,
			undefined,
			profile.writableRoots[0] ?? process.cwd(),
			{ commandId: "enclave-fs-helper", commandText: "pi-enclave-fs" },
		);
		this.helperArgv = helper.argv;
		this.helperDenySnapshot = denySnapshot(profile);
	}

	/**
	 * Re-apply the configuration and re-wrap the helper if a deny root has
	 * appeared, vanished or been retargeted since the last wrap. Called before
	 * every helper operation and every shell command; the cost is an lstat and
	 * a realpath per deny root, microseconds against a round trip.
	 */
	private async refreshHelperIfStale(compiled: CompiledProfile): Promise<void> {
		if (denySnapshot(compiled.profile) === this.helperDenySnapshot) return;
		materializeWriteDenyAnchors(compiled.profile);
		// Re-apply the configuration before re-wrapping: the manager resolves
		// deny targets when it takes the configuration, not per wrap, so a wrap
		// alone would mask the same stale target again.
		SandboxManager.updateConfig(
			toSrtConfig(compiled.profile, this.weakened, process.platform, this.hostTools) as never,
		);
		await this.wrapHelper(compiled.profile);
		this.fsClient?.retire();
	}

	async run(compiled: CompiledProfile, request: RunRequest): Promise<RunResult> {
		this.assertCurrent(compiled);
		if (request.writeCapability && request.readCapability) {
			throw new Error("pi-enclave: one invocation cannot carry both read and write capabilities");
		}
		const capabilityKind = request.writeCapability ? "write" : request.readCapability ? "read" : undefined;
		if (capabilityKind) {
			const lifetimeIssue = shellCapabilityIssue(capabilityKind);
			if (lifetimeIssue) throw new Error(lifetimeIssue);
		}
		// Shell commands are wrapped per call, but the manager resolves deny
		// targets when it takes the configuration, so a retargeted deny link
		// needs the configuration re-applied here too.
		await this.refreshHelperIfStale(compiled);

		const writeTarget = request.writeCapability
			? validateWriteCapability(compiled.profile, request.cwd, request.writeCapability)
			: undefined;
		const readTarget = request.readCapability
			? validateReadCapability(compiled.profile, request.cwd, request.readCapability)
			: undefined;
		const customProfile = writeTarget
			? effectiveProfile({
					...compiled.profile,
					writableRoots: [...compiled.profile.writableRoots, writeTarget],
				})
			: readTarget
				? {
						...compiled.profile,
						readDeny: compiled.profile.readDeny.filter((entry) => canonical(entry) !== readTarget),
					}
				: undefined;
		const customConfig = customProfile
			? toSrtConfig(customProfile, this.weakened, process.platform, this.hostTools)
			: undefined;

		const { argv } = await SandboxManager.wrapWithSandboxArgv(
			request.command,
			"/bin/bash",
			customConfig as never,
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
				killTree();
				cleanup();
				reject(error);
			});

			// `close` waits for stdio. A background descendant that inherited a pipe
			// can keep it from firing, so reap the process group as soon as its leader
			// exits. On macOS this is the lifecycle boundary Seatbelt itself does not
			// provide; on Linux it is harmless defense in depth around bwrap's PID
			// namespace and --die-with-parent behavior.
			child.on("exit", killTree);

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
				beforeCall: () => this.refreshHelperIfStale(compiled),
				...(this.onFsViolation ? { onViolation: this.onFsViolation } : {}),
			});
		}
		return this.fsClient;
	}

	/**
	 * Start a helper under a one-call profile with one exact read denial lifted.
	 *
	 * This helper is never cached and the process-global SRT configuration is
	 * never updated. Its caller owns the lease and must dispose it after the tool
	 * call, which keeps concurrent ordinary helpers on the base profile.
	 */
	async fsWithReadCapability(
		compiled: CompiledProfile,
		value: string,
		actionHash: string,
		cwd = compiled.profile.writableRoots[0] ?? process.cwd(),
	): Promise<FsClientLease> {
		this.assertCurrent(compiled);
		await this.refreshHelperIfStale(compiled);
		const target = validateReadCapability(compiled.profile, cwd, value);
		const customProfile: Profile = {
			...compiled.profile,
			readDeny: compiled.profile.readDeny.filter((entry) => canonical(entry) !== target),
		};
		const customConfig = toSrtConfig(customProfile, this.weakened, process.platform, this.hostTools);
		const { argv } = await SandboxManager.wrapWithSandboxArgv(
			`exec ${shellQuote(process.execPath)} ${shellQuote(HELPER_PATH)}`,
			"/bin/bash",
			customConfig as never,
			undefined,
			customProfile.writableRoots[0] ?? process.cwd(),
			{ commandId: `enclave-fs-cap-${actionHash.slice(0, 24)}`, commandText: "pi-enclave-fs-read-capability" },
		);
		const capabilityCompiled: CompiledProfile = {
			backend: compiled.backend,
			profile: customProfile,
			describe: () => compiled.describe(),
		};
		const client = new HelperFsClient({
			compiled: capabilityCompiled,
			spawnHelper: () => this.spawnPreparedHelper(argv, customProfile),
			...(this.onFsViolation ? { onViolation: this.onFsViolation } : {}),
		});
		return { client, dispose: () => client.dispose() };
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

		return this.spawnPreparedHelper(argv, compiled.profile);
	}

	/** Spawn a helper from an already wrapped argv under the matching profile. */
	private spawnPreparedHelper(argv: string[], profile: Profile): ChildProcessWithoutNullStreams {
		const [bin, ...args] = argv;
		if (!bin) throw new Error("pi-enclave: sandbox-runtime returned an empty argv for the helper");

		return spawn(bin, args, {
			cwd: profile.writableRoots[0] ?? process.cwd(),
			// The same allowlist the shell gets -- the helper reads files on the
			// agent's behalf, so a credential in its environment is exactly as
			// disclosable as one in bash's -- plus the resolved search-tool paths.
			//
			// Resolving them here rather than inside the sandbox is the point: the
			// helper has no network and cannot fetch a missing tool, so the lookup
			// has to happen on this side while it still can.
			env: {
				...buildChildEnv(process.env, {
					readDeny: profile.readDeny,
					writableRoots: profile.writableRoots,
					...(profile.tmpDir ? { tmpdir: profile.tmpDir } : {}),
					// The helper reads files on the agent's behalf, so it must honour
					// the same configured passthrough/envDeny the shell does; without
					// these a user's custom envDeny protected bash but not the file
					// helper, which reads through /proc/self/environ just as readily.
					...(profile.envPassthrough ? { passthrough: profile.envPassthrough } : {}),
					...(profile.envDeny ? { envDeny: profile.envDeny } : {}),
				}),
				...resolveSearchTools(this.hostTools.rg, this.hostTools.fd),
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
