/**
 * Experimental Phase 4a runner. Explicitly invoked by the Docker/Podman test harnesses;
 * production selection remains native until the remaining roadmap gates pass.
 */
import { type ChildProcessWithoutNullStreams, execFile, spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { chmodSync, copyFileSync, mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import { buildChildEnv } from "../env/child-env.ts";
import { HelperFsClient } from "../fs/client.ts";
import { validateBashTimeout } from "../tools/bash.ts";
import { compileDockerPlan, type DockerPlan, dockerPath, mountArguments, mountSnapshot } from "./docker/plan.ts";
import { offlineSeccomp } from "./docker/seccomp.ts";
import { isUnder } from "./paths.ts";
import { PodmanDriver } from "./podman/driver.ts";
import type { ChildEnv, CompiledProfile, FsClient, Profile, RunRequest, RunResult, SandboxBackend } from "./types.ts";

const execFileAsync = promisify(execFile);
const IMAGE = /^(?:sha256:[a-f0-9]{64}|[a-z0-9][a-z0-9./:_-]*@sha256:[a-f0-9]{64})$/;
const CONTAINER_PATH = "/usr/local/bin:/usr/bin:/bin";

export interface ContainerBackendOptions {
	engine: "docker" | "podman";
	/** macOS only: explicit, already running Podman machine. */
	machine?: string;
	/** Already present and explicitly trusted; a tag alone is never accepted. */
	image: string;
	/** Absolute trusted CLI, never resolved through a repository-controlled PATH. */
	binary?: string;
	/** A local Linux daemon socket. Remote contexts and ambient DOCKER_HOST are ignored. */
	socket?: string;
}

interface OwnedContainer {
	name: string;
	child?: ChildProcessWithoutNullStreams;
	removal?: Promise<void>;
}

class ContainerCompiled implements CompiledProfile {
	constructor(
		readonly backend: "docker" | "podman",
		readonly plan: DockerPlan,
		readonly image: string,
	) {}
	get profile(): Profile {
		return this.plan.profile;
	}
	describe(): string {
		return JSON.stringify(
			{
				backend: this.backend,
				image: this.image,
				network: "none",
				socketCreation: "denied",
				readonlyRootfs: true,
				privateTmp: ["/tmp", "/dev/shm"],
				mounts: this.plan.mounts,
			},
			null,
			2,
		);
	}
}

export class ContainerBackend implements SandboxBackend {
	readonly name: "docker" | "podman";
	private readonly options: { image: string; binary: string; socket: string };
	private readonly podman: PodmanDriver | undefined;
	private readonly privateDir: string;
	private readonly containers = new Set<OwnedContainer>();
	private readonly helpers = new Map<ContainerCompiled, HelperFsClient>();
	private readonly profiles = new Set<ContainerCompiled>();
	private disposed = false;
	private cleanupFailure: Error | undefined;
	private ready: Promise<string> | undefined;
	private readonly pendingCreates = new Set<Promise<OwnedContainer>>();

	constructor(options: ContainerBackendOptions) {
		this.name = options.engine;
		if (!IMAGE.test(options.image))
			throw new Error(`pi-enclave: ${this.name} image must be an immutable sha256 ID or repository@sha256 digest`);
		if (this.name === "docker" && process.platform !== "linux")
			throw new Error("pi-enclave: experimental Docker runner currently requires a Linux host");
		this.podman = this.name === "podman" ? new PodmanDriver(options) : undefined;
		const binary = dockerPath(options.binary ?? this.podman?.binary ?? "/usr/bin/docker");
		const socket = dockerPath(options.socket ?? "/var/run/docker.sock");
		this.options = { image: options.image, binary, socket };
		this.privateDir = mkdtempSync(join(this.podman?.privateBase ?? realpathSync(tmpdir()), `pi-enclave-${this.name}-`));
		chmodSync(this.privateDir, 0o700);
		try {
			this.podman?.configure(this.privateDir);
			// Empty read-only masks match bwrap: recursive searches can cross them
			// without EACCES, while HelperFsClient classifies direct masked success
			// as SandboxDenied. No host secret bytes are present in these mounts.
			mkdirSync(join(this.privateDir, "empty-dir"), 0o755);
			writeFileSync(join(this.privateDir, "empty-file"), "", { mode: 0o444 });
			writeFileSync(join(this.privateDir, "config.json"), "{}", { mode: 0o600 });
			writeFileSync(join(this.privateDir, "seccomp.json"), offlineSeccomp(), { mode: 0o600 });
			copyFileSync(new URL("../fs/helper.mjs", import.meta.url), join(this.privateDir, "helper.mjs"));
			chmodSync(join(this.privateDir, "helper.mjs"), 0o444);
		} catch (error) {
			rmSync(this.privateDir, { recursive: true, force: true });
			throw error;
		}
	}

	private cliArgs(args: readonly string[]): string[] {
		if (this.podman) return this.podman.args(args);
		return ["--config", this.privateDir, "--host", `unix://${this.options.socket}`, ...args];
	}

	private cliEnv(): NodeJS.ProcessEnv {
		return this.podman?.env() ?? { PATH: "/usr/bin:/bin", HOME: this.privateDir, LANG: "C.UTF-8" };
	}

	private async control(args: readonly string[]): Promise<string> {
		try {
			const result = await execFileAsync(this.options.binary, this.cliArgs(args), {
				env: this.cliEnv(),
				cwd: this.privateDir,
				timeout: 30_000,
				maxBuffer: 1024 * 1024,
			});
			return result.stdout.trim();
		} catch (error) {
			throw new Error(
				`pi-enclave: ${this.name} ${args[0]} failed: ${error instanceof Error ? error.message : String(error)}`,
			);
		}
	}

	private assertActive(): void {
		if (this.disposed) throw new Error(`pi-enclave: ${this.name} backend was disposed`);
		if (this.cleanupFailure) throw this.cleanupFailure;
	}

	private preflight(): Promise<string> {
		this.ready ??= (async () => {
			if (this.podman) {
				await this.podman.initialize();
				this.podman.checkInfo(JSON.parse(await this.control(["info", "--format", "json"])));
			} else {
				const info = JSON.parse(await this.control(["info", "--format", "{{json .}}"])) as {
					OSType?: string;
					SecurityOptions?: string[];
				};
				if (
					info.OSType !== "linux" ||
					!info.SecurityOptions?.some((s) => s.startsWith("name=seccomp")) ||
					info.SecurityOptions.some((s) => /rootless|userns/.test(s))
				) {
					throw new Error(
						`pi-enclave: ${this.name} requires a Linux daemon with seccomp and unmapped host UID support; rootless/userns mapping is not qualified yet`,
					);
				}
			}
			const images = JSON.parse(await this.control(["image", "inspect", this.options.image])) as {
				Id: string;
				Os: string;
				Config?: { Volumes?: Record<string, unknown> };
			}[];
			const image = images[0];
			// Podman reports bare hex IDs; normalize without resolving a mutable tag.
			if (this.podman && image && /^[a-f0-9]{64}$/.test(image.Id)) image.Id = `sha256:${image.Id}`;
			if (
				images.length !== 1 ||
				!image ||
				!/^sha256:[a-f0-9]{64}$/.test(image.Id) ||
				image.Os !== "linux" ||
				Object.keys(image.Config?.Volumes ?? {}).length > 0
			) {
				throw new Error(`pi-enclave: ${this.name} requires one Linux image without implicit VOLUME mounts`);
			}
			return image.Id;
		})();
		return this.ready;
	}

	async compile(profile: Profile): Promise<CompiledProfile> {
		this.assertActive();
		const plan = compileDockerPlan(profile, this.privateDir, this.options.binary, this.options.socket);
		const image = await this.preflight();
		this.podman?.checkRoots(plan);
		const compiled = Object.freeze(new ContainerCompiled(this.name, plan, image));
		this.assertActive();
		this.profiles.add(compiled);
		try {
			if (this.podman?.machine) await this.podman.verifyShares(plan);
			return compiled;
		} catch (error) {
			this.profiles.delete(compiled);
			throw error;
		}
	}

	private checked(compiled: CompiledProfile): ContainerCompiled {
		this.assertActive();
		if (!(compiled instanceof ContainerCompiled) || !this.profiles.has(compiled))
			throw new Error(`pi-enclave: foreign ${this.name} profile`);
		this.podman?.checkRoots(compiled.plan);
		if (mountSnapshot(compiled.plan.observedPaths) !== compiled.plan.snapshot)
			throw new Error(`pi-enclave: ${this.name} mount topology changed; recompile before executing`);
		return compiled;
	}

	private environment(compiled: ContainerCompiled, parent: ChildEnv): ChildEnv {
		return buildChildEnv(
			{ ...parent, PATH: CONTAINER_PATH, SHELL: "/bin/bash" },
			{
				passthrough: compiled.profile.envPassthrough ?? [],
				envDeny: compiled.profile.envDeny ?? [],
				home: "/tmp",
				tmpdir: "/tmp",
				writableRoots: compiled.profile.writableRoots,
				readDeny: compiled.profile.readDeny,
			},
		);
	}

	private async create(
		compiled: ContainerCompiled,
		cwd: string,
		command: readonly string[],
		env: ChildEnv,
		helper = false,
	): Promise<OwnedContainer> {
		this.checked(compiled);
		await this.podman?.verifyShares(compiled.plan);
		this.checked(compiled);
		dockerPath(cwd);
		for (const [key, value] of Object.entries(env)) {
			if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(key) || value.includes("\0"))
				throw new Error("pi-enclave: invalid Docker child environment entry");
		}
		if (
			![...compiled.profile.writableRoots, ...(compiled.profile.readableRoots ?? [])].some((root) => isUnder(cwd, root))
		)
			throw new Error(`pi-enclave: ${this.name} cwd must be inside an explicit host root`);
		const uid = process.getuid?.();
		const gid = process.getgid?.();
		if (!uid || gid === undefined || gid === 0)
			throw new Error(`pi-enclave: ${this.name} runner requires a non-root host UID/GID`);
		const owned: OwnedContainer = { name: `pi-enclave-${randomUUID()}` };
		this.containers.add(owned);
		const create = (async () => {
			try {
				await this.control([
					"create",
					"--name",
					owned.name,
					"--pull=never",
					"--interactive",
					"--network",
					"none",
					"--cap-drop",
					"ALL",
					"--security-opt",
					"no-new-privileges",
					"--security-opt",
					`seccomp=${this.privateDir}/seccomp.json`,
					"--read-only",
					...(this.podman?.createArgs(uid, gid) ?? []),
					"--pids-limit",
					"256",
					"--memory",
					"1g",
					"--memory-swap",
					"1g",
					"--cpus",
					"2",
					"--user",
					`${uid}:${gid}`,
					"--ipc",
					"private",
					"--cgroupns",
					"private",
					"--no-healthcheck",
					"--log-driver",
					"none",
					"--tmpfs",
					"/tmp:rw,nosuid,nodev,size=256m,mode=1777",
					"--shm-size",
					"16m",
					"--workdir",
					cwd,
					"--entrypoint",
					"/usr/bin/env",
					...mountArguments(compiled.plan, this.privateDir, this.name),
					...(helper
						? [
								"--mount",
								`type=bind,source=${this.privateDir}/helper.mjs,target=/opt/pi-enclave/helper.mjs,readonly,${this.name === "podman" ? "bind-nonrecursive" : "bind-recursive=disabled"}`,
							]
						: []),
					compiled.image,
					"-i",
					...Object.entries(env).map(([key, value]) => `${key}=${value}`),
					...command,
				]);
				this.checked(compiled);
				return owned;
			} catch (error) {
				await this.remove(owned);
				throw error;
			}
		})();
		this.pendingCreates.add(create);
		try {
			return await create;
		} finally {
			this.pendingCreates.delete(create);
		}
	}

	private attach(owned: OwnedContainer): ChildProcessWithoutNullStreams {
		this.assertActive();
		const child = spawn(this.options.binary, this.cliArgs(["start", "--attach", "--interactive", owned.name]), {
			cwd: this.privateDir,
			env: this.cliEnv(),
			stdio: "pipe",
		});
		owned.child = child;
		// An unexpected CLI exit must not leave a detached container running.
		child.once("close", () => {
			void this.remove(owned).catch(() => {});
		});
		return child;
	}

	private remove(owned: OwnedContainer): Promise<void> {
		owned.removal ??= (async () => {
			try {
				// Podman's --force alone still honors its stop grace period. An
				// aborted invocation must not retain authority during those seconds.
				await this.control(["rm", "--force", ...(this.podman ? ["--time", "0"] : []), "--volumes", owned.name]);
			} catch (error) {
				// A failed create may never have allocated the container. Verify absence;
				// a dead daemon or any other removal error is a session-stopping failure.
				const remaining = await this.control([
					"container",
					"ls",
					"--all",
					"--filter",
					`name=^${this.podman ? "" : "/"}${owned.name}$`,
					"--format",
					"{{.Names}}",
				]);
				if (remaining) throw error;
			}
			owned.child?.kill("SIGKILL");
			this.containers.delete(owned);
		})().catch((error: unknown) => {
			const failure = new Error(
				`pi-enclave: ${this.name} container cleanup could not be verified (${owned.name}): ${String(error)}`,
			);
			this.cleanupFailure = failure;
			throw failure;
		});
		return owned.removal;
	}

	async run(profile: CompiledProfile, request: RunRequest): Promise<RunResult> {
		const compiled = this.checked(profile);
		if (request.readCapability || request.writeCapability)
			throw new Error(`pi-enclave: ${this.name} capability profiles are not enabled in this experimental slice`);
		const timeout = validateBashTimeout(request.timeout);
		if (request.signal?.aborted) throw new Error("Operation aborted");
		const owned = await this.create(
			compiled,
			request.cwd,
			["/bin/bash", "--noprofile", "--norc", "-c", request.command],
			this.environment(compiled, request.env),
		);
		try {
			if (request.signal?.aborted) throw new Error("Operation aborted");
			const child = this.attach(owned);
			const result = await new Promise<number | null>((resolve, reject) => {
				let stopped = false;
				const stop = () => {
					stopped = true;
					void this.remove(owned).catch(reject);
				};
				const timer = timeout === undefined ? undefined : setTimeout(stop, timeout * 1000);
				request.signal?.addEventListener("abort", stop, { once: true });
				if (request.signal?.aborted) stop();
				child.stdout.on("data", (data: Buffer) => request.onData?.(data));
				child.stderr.on("data", (data: Buffer) => request.onData?.(data));
				child.stdin.on("error", () => {});
				child.stdin.end();
				const clear = () => {
					clearTimeout(timer);
					request.signal?.removeEventListener("abort", stop);
				};
				child.once("error", (error) => {
					clear();
					reject(error);
				});
				child.once("close", (code) => {
					clear();
					resolve(stopped ? null : code);
				});
			});
			return { exitCode: result, violations: [] };
		} finally {
			await this.remove(owned);
		}
	}

	fs(profile: CompiledProfile): FsClient {
		const compiled = this.checked(profile);
		const existing = this.helpers.get(compiled);
		if (existing) return existing;
		let prepared: Promise<OwnedContainer> | undefined;
		let owned: OwnedContainer | undefined;
		const client = new HelperFsClient({
			compiled,
			beforeCall: async () => {
				this.checked(compiled);
				prepared ??= this.create(
					compiled,
					compiled.profile.writableRoots[0] ?? "/",
					["/usr/local/bin/node", "/opt/pi-enclave/helper.mjs"],
					this.environment(compiled, process.env as ChildEnv),
					true,
				);
				try {
					owned = await prepared;
				} catch (error) {
					prepared = undefined;
					throw error;
				}
			},
			spawnHelper: () => {
				if (!owned) throw new Error(`pi-enclave: ${this.name} helper container was not prepared`);
				const child = this.attach(owned);
				child.once("close", () => {
					prepared = undefined;
					owned = undefined;
				});
				return child;
			},
		});
		this.helpers.set(compiled, client);
		return client;
	}

	async dispose(): Promise<void> {
		this.disposed = true;
		await Promise.allSettled([...this.pendingCreates]);
		await Promise.all([...this.helpers.values()].map((helper) => helper.dispose()));
		this.helpers.clear();
		await Promise.all([...this.containers].map((owned) => this.remove(owned)));
		this.profiles.clear();
		chmodSync(join(this.privateDir, "empty-dir"), 0o700);
		rmSync(this.privateDir, { recursive: true, force: true });
	}
}
