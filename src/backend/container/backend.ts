import { type ChildProcessWithoutNullStreams, execFile, spawn } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import {
	chmodSync,
	copyFileSync,
	lstatSync,
	mkdirSync,
	mkdtempSync,
	readFileSync,
	realpathSync,
	rmSync,
	writeFileSync,
} from "node:fs";
import { arch, homedir, hostname, release, userInfo } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { VERSION as PI_VERSION } from "@earendil-works/pi-coding-agent";
import type { BackendSettings } from "../../config/types.ts";
import { buildChildEnv } from "../../env/child-env.ts";
import { HelperFsClient } from "../../fs/client.ts";
import { hostExecutableSafety } from "../../probe-host.ts";
import { ensureSecureDir } from "../../state/dir.ts";
import { validateBashTimeout } from "../../tools/bash.ts";
import { validateReadCapability, validateWriteCapability } from "../capability.ts";
import { canonical, isUnder } from "../paths.ts";
import { materializeWriteDenyAnchors } from "../srt.ts";
import type {
	CompiledProfile,
	FsClient,
	FsClientLease,
	Profile,
	RunRequest,
	RunResult,
	SandboxBackend,
	Violation,
} from "../types.ts";
import { assertMounts, compileMounts, containerPath, type MountPlan } from "./mounts.ts";
import { CONTAINER_SECCOMP } from "./seccomp.ts";

const exec = promisify(execFile);
const sourceDir = dirname(fileURLToPath(import.meta.url));
const helperSource = fileURLToPath(new URL("../../fs/helper.mjs", import.meta.url));
type Prepared = { mounts: MountPlan; profile: Profile };

export class ContainerBackend implements SandboxBackend {
	readonly name: "docker" | "podman";
	readonly weakened = false;
	onFsViolation?: (violation: Violation) => void;
	private readonly compiled = new WeakMap<CompiledProfile, Prepared>();
	private readonly children = new Map<ChildProcessWithoutNullStreams, Promise<number | null>>();
	private readonly clients = new Set<HelperFsClient>();
	private readonly baseClients = new WeakMap<CompiledProfile, HelperFsClient>();
	private root?: string;
	private imageId?: string;
	private engineIdentity?: unknown;
	private engineEnv: NodeJS.ProcessEnv = {};
	private prefix: string[] = [];
	private failure?: Error;
	private disposed = false;
	private initialization?: Promise<void>;
	constructor(
		readonly settings: BackendSettings,
		private readonly controlRoot: string,
	) {
		this.name = settings.kind === "auto" ? settings.fallback : settings.kind === "docker" ? "docker" : "podman";
		if (!/^(sha256:[a-f0-9]{64}|[^\s@]+@sha256:[a-f0-9]{64})$/.test(settings.image))
			throw new Error("pi-enclave: an immutable, already-local container image is required");
	}

	async initialize(): Promise<void> {
		this.assertAlive();
		this.initialization ??= this.initializeOnce().catch((error: Error) => {
			this.failure = error;
			throw error;
		});
		await this.initialization;
	}

	private async initializeOnce(): Promise<void> {
		if (process.platform !== "linux" || arch() !== "x64")
			throw new Error("pi-enclave: container backend is qualified only on Linux/x86-64; other hosts refuse");
		containerPath(this.settings.binary);
		if (realpathSync(this.settings.binary) !== this.settings.binary || !lstatSync(this.settings.binary).isFile())
			throw new Error("pi-enclave: engine executable must be a canonical regular file");
		ensureSecureDir(this.controlRoot);
		this.root = mkdtempSync(join(this.controlRoot, "container-"));
		chmodSync(this.root, 0o700);
		mkdirSync(join(this.root, "empty"), { mode: 0o755 });
		writeFileSync(join(this.root, "empty-file"), "", { mode: 0o644 });
		writeFileSync(join(this.root, "seccomp.json"), JSON.stringify(CONTAINER_SECCOMP), { mode: 0o600 });
		copyFileSync(helperSource, join(this.root, "helper.mjs"));
		copyFileSync(join(sourceDir, "supervisor.mjs"), join(this.root, "supervisor.mjs"));
		this.engineEnv = {
			PATH: "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
			HOME: homedir(),
			LANG: "C",
			XDG_RUNTIME_DIR: `/run/user/${userInfo().uid}`,
		};
		if (this.name === "docker") {
			containerPath(this.settings.socket);
			if (!lstatSync(this.settings.socket).isSocket())
				throw new Error("pi-enclave: Docker requires an explicit local Unix socket");
			mkdirSync(join(this.root, "docker"));
			this.prefix = ["--config", join(this.root, "docker"), "--host", `unix://${this.settings.socket}`];
			const info = JSON.parse(await this.cli(["info", "--format", "{{json .}}"]));
			if (
				info.OSType !== "linux" ||
				info.Architecture !== "x86_64" ||
				!info.SecurityOptions?.some((v: string) => v.includes("seccomp")) ||
				info.SecurityOptions.some((v: string) => /userns|rootless/.test(v))
			)
				throw new Error("pi-enclave: Docker needs a local Linux seccomp daemon without UID remapping");
			this.engineIdentity = {
				version: info.ServerVersion,
				kernel: info.KernelVersion,
				driver: info.Driver,
				security: info.SecurityOptions,
				root: info.DockerRootDir,
			};
		} else {
			writeFileSync(
				join(this.root, "containers.conf"),
				"[containers]\nvolumes=[]\nenv=[]\ndefault_sysctls=[]\n[engine]\nhooks_dir=[]\n",
				{ mode: 0o600 },
			);
			this.engineEnv.CONTAINERS_CONF = join(this.root, "containers.conf");
			this.prefix = ["--remote=false"];
			const info = JSON.parse(await this.cli(["info", "--format", "json"]));
			if (
				!info.host.security.rootless ||
				!info.host.security.seccompEnabled ||
				info.host.cgroupVersion !== "v2" ||
				!["cpu", "memory", "pids"].every((v) => info.host.cgroupControllers.includes(v))
			)
				throw new Error(
					"pi-enclave: Podman needs rootless seccomp with delegated cgroup v2 CPU/memory/PID controllers",
				);
			this.engineIdentity = {
				version: info.version.Version,
				kernel: info.host.kernel,
				runtime: info.host.ociRuntime,
				conmon: info.host.conmon,
				store: info.store.graphRoot,
				runRoot: info.store.runRoot,
			};
		}
		const [image] = JSON.parse(await this.cli(["image", "inspect", this.settings.image]));
		if (image.Config?.Volumes && Object.keys(image.Config.Volumes).length)
			throw new Error("pi-enclave: trusted images must not declare implicit volumes");
		const imageId = image.Id ?? image.ID;
		this.imageId = imageId.startsWith("sha256:") ? imageId : `sha256:${imageId}`;
		if (!/^sha256:[a-f0-9]{64}$/.test(this.imageId ?? ""))
			throw new Error("pi-enclave: engine returned an invalid image ID");
	}

	async identity(): Promise<string> {
		await this.initialize();
		const sources = ["backend.ts", "mounts.ts", "seccomp.ts", "supervisor.mjs", "qualification.ts"].map((name) =>
			readFileSync(join(sourceDir, name)),
		);
		const sharedSources = [
			"../capability.ts",
			"../paths.ts",
			"../srt.ts",
			"../../fs/client.ts",
			"../../env/child-env.ts",
			"../../config/profile.ts",
			"../select.ts",
			"../../state/dir.ts",
			"../../probe-host.ts",
		].map((path) => readFileSync(join(sourceDir, path)));
		return createHash("sha256")
			.update(
				JSON.stringify({
					schema: 1,
					platform: process.platform,
					arch: arch(),
					kernel: release(),
					hostname: hostname(),
					uid: userInfo().uid,
					gid: userInfo().gid,
					node: process.version,
					pi: PI_VERSION,
					settings: this.settings,
					image: this.imageId,
					engine: this.engineIdentity,
				}),
			)
			.update(Buffer.concat([...sources, ...sharedSources, readFileSync(helperSource)]))
			.digest("hex");
	}

	private async cli(args: string[]): Promise<string> {
		const { stdout } = await exec(this.settings.binary, [...this.prefix, ...args], {
			env: this.engineEnv,
			timeout: 30_000,
			maxBuffer: 2 * 1024 * 1024,
		});
		return stdout;
	}

	async compile(input: Profile): Promise<CompiledProfile> {
		await this.initialize();
		this.assertAlive();
		if (input.network !== "off") throw new Error("pi-enclave: containers support network off only");
		const profile = structuredClone(input);
		profile.readableRoots = [...(input.readableRoots ?? this.settings.readableRoots)];
		profile.tmpDir = "/tmp/claude";
		// Linux devpts permits allocation, as on bwrap. Report the effective setting.
		profile.allowPty = true;
		profile.writableRoots = [...new Set([...input.writableRoots, "/tmp/claude"])];
		const roots = [...profile.writableRoots, ...profile.readableRoots];
		const safety = hostExecutableSafety(profile.writableRoots, [this.settings.binary, process.execPath]);
		if (!safety.ok) throw new Error(safety.detail);
		if (roots.some((root) => isUnder(this.root as string, root) || isUnder(root, this.root as string)))
			throw new Error("pi-enclave: container control state must be outside exposed roots");
		const engine = this.engineIdentity as {
			store?: string;
			runRoot?: string;
			root?: string;
			runtime?: { path?: string };
			conmon?: { path?: string };
		};
		if (
			[engine.store, engine.runRoot, engine.root, this.settings.socket]
				.filter(Boolean)
				.some((path) => roots.some((root) => isUnder(path as string, root)))
		)
			throw new Error("pi-enclave: engine storage and sockets cannot be exposed to the child");
		const runtimeSafety = hostExecutableSafety(
			profile.writableRoots,
			[engine.runtime?.path, engine.conmon?.path].filter((p): p is string => !!p),
		);
		if (!runtimeSafety.ok) throw new Error(runtimeSafety.detail);
		materializeWriteDenyAnchors(profile);
		// The default project credential file may not exist. Mask its entire .pi
		// parent rather than permit a future file to appear inside an unmasked bind.
		for (const root of input.writableRoots) {
			const file = join(root, ".pi", "mcp.json");
			if (!profile.readDeny.includes(file)) continue;
			try {
				lstatSync(file);
			} catch (error) {
				if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
				materializeWriteDenyAnchors({
					...profile,
					materializeWriteDeny: [dirname(file)],
					materializeWriteDenyFiles: [],
				});
				profile.readDeny = [...profile.readDeny, dirname(file)];
			}
		}
		const mounts = compileMounts(profile, join(this.root as string, "empty"), join(this.root as string, "empty-file"));
		// Retain a private snapshot; callers cannot mutate what the execution path uses.
		const compiled: CompiledProfile = {
			backend: this.name,
			profile: structuredClone(profile),
			describe: () =>
				JSON.stringify({ image: this.imageId, network: "none", uid: userInfo().uid, mounts: mounts.mounts }, null, 2),
		};
		this.compiled.set(compiled, { mounts, profile });
		return compiled;
	}

	private assertAlive(): void {
		if (this.failure) throw this.failure;
		if (this.disposed) throw new Error("pi-enclave: container backend was disposed");
	}
	private prepared(compiled: CompiledProfile): Prepared {
		this.assertAlive();
		const prepared = this.compiled.get(compiled);
		if (!prepared) throw new Error("pi-enclave: this backend can only execute profiles it compiled");
		if (JSON.stringify(compiled.profile) !== JSON.stringify(prepared.profile))
			throw new Error("pi-enclave: compiled profile was mutated");
		assertMounts(prepared.mounts);
		return prepared;
	}

	private start(
		prepared: Prepared,
		cwd: string,
		command: string[],
		inputEnv: NodeJS.ProcessEnv,
	): ChildProcessWithoutNullStreams {
		this.assertAlive();
		assertMounts(prepared.mounts);
		containerPath(cwd);
		if (!prepared.mounts.mounts.some((mount) => !mount.mask && isUnder(cwd, mount.target)))
			throw new Error(`pi-enclave: cwd is not exposed to the container: ${cwd}`);
		const name = `pi-enclave-${randomUUID()}`;
		const profile = prepared.profile;
		const env = {
			...buildChildEnv(inputEnv, {
				passthrough: profile.envPassthrough ?? [],
				envDeny: profile.envDeny ?? [],
				writableRoots: profile.writableRoots,
				readDeny: profile.readDeny,
				tmpdir: "/tmp/claude",
			}),
		};
		// Runtime binaries come from the image, never a workspace-provided host PATH.
		env.PATH = "/usr/local/bin:/usr/bin:/bin";
		const create = [
			"create",
			"--name",
			name,
			"--rm",
			"--interactive",
			"--pull=never",
			"--network=none",
			"--cap-drop=ALL",
			"--security-opt=no-new-privileges",
			`--security-opt=seccomp=${join(this.root as string, "seccomp.json")}`,
			"--read-only",
			"--ipc=private",
			"--pid=private",
			"--cgroupns=private",
			"--pids-limit=256",
			"--memory=512m",
			"--cpus=2",
			"--shm-size=32m",
			"--no-healthcheck",
			"--log-driver=none",
			"--user",
			`${userInfo().uid}:${userInfo().gid}`,
			"--workdir",
			cwd,
			"--entrypoint=/usr/bin/env",
			"--tmpfs=/tmp:rw,nosuid,nodev,size=128m,mode=1777",
		];
		if (this.name === "podman")
			create.push(
				"--userns=keep-id",
				"--read-only-tmpfs=false",
				"--unsetenv-all",
				"--http-proxy=false",
				"--hooks-dir",
				join(this.root as string, "empty"),
			);
		for (const mount of prepared.mounts.mounts)
			create.push(
				"--mount",
				`type=bind,src=${mount.source},dst=${mount.target},${this.name === "docker" ? "bind-recursive=disabled" : "bind-nonrecursive"}${mount.readonly ? ",ro=true" : ""}`,
			);
		create.push("--mount", `type=bind,src=${join(this.root as string, "helper.mjs")},dst=/enclave/helper.mjs,ro=true`);
		create.push(
			this.imageId as string,
			"-i",
			...Object.entries(env).map(([key, value]) => `${key}=${value}`),
			...command,
		);
		const planPath = join(this.root as string, `${name}.json`);
		writeFileSync(
			planPath,
			JSON.stringify({
				engine: this.name,
				name,
				binary: this.settings.binary,
				prefix: this.prefix,
				engineEnv: this.engineEnv,
				create,
			}),
			{ mode: 0o600, flag: "wx" },
		);
		const child = spawn(process.execPath, [join(this.root as string, "supervisor.mjs"), planPath], {
			env: this.engineEnv,
			detached: true,
			stdio: ["pipe", "pipe", "pipe", "pipe"],
		}) as ChildProcessWithoutNullStreams;
		// HelperFsClient's protocol/ready failures request SIGKILL. The supervisor must first reap the container.
		const kill = child.kill.bind(child);
		child.kill = (signal) => kill(signal === "SIGKILL" ? "SIGTERM" : signal);
		const completion = new Promise<number | null>((resolve, reject) => {
			child.once("error", reject);
			child.once("close", (code) => {
				if (code === 125)
					this.failure = new Error("pi-enclave: container supervisor failed; refusing further execution");
				resolve(code);
			});
		});
		this.children.set(child, completion);
		void completion.finally(() => this.children.delete(child)).catch(() => {});
		return child;
	}

	async run(compiled: CompiledProfile, request: RunRequest): Promise<RunResult> {
		validateBashTimeout(request.timeout);
		let prepared = this.prepared(compiled);
		if (request.writeCapability && request.readCapability)
			throw new Error("pi-enclave: only one capability is allowed per invocation");
		if (request.signal?.aborted) return { exitCode: null, violations: [] };
		if (request.writeCapability || request.readCapability) {
			const profile = structuredClone(prepared.profile);
			if (request.writeCapability)
				profile.writableRoots = [
					...profile.writableRoots,
					validateWriteCapability(profile, request.cwd, request.writeCapability),
				];
			if (request.readCapability) {
				const target = validateReadCapability(profile, request.cwd, request.readCapability);
				profile.readDeny = profile.readDeny.filter((path) => canonical(path) !== target);
				profile.readableRoots = [...(profile.readableRoots ?? []), target];
			}
			prepared = this.prepared(await this.compile(profile));
		}
		const child = this.start(
			prepared,
			request.cwd,
			["/bin/bash", "--noprofile", "--norc", "-c", `mkdir -p /tmp/claude; ${request.command}`],
			request.env,
		);
		let cancelled = false;
		const cancel = () => {
			cancelled = true;
			child.kill("SIGTERM");
		};
		request.signal?.addEventListener("abort", cancel, { once: true });
		if (request.signal?.aborted) cancel();
		const timer = request.timeout === undefined ? undefined : setTimeout(cancel, request.timeout * 1000);
		child.stdout.on("data", (chunk: Buffer) => request.onData?.(chunk));
		child.stderr.on("data", (chunk: Buffer) => request.onData?.(chunk));
		try {
			const exitCode = await this.children.get(child);
			if (this.failure) throw this.failure;
			return { exitCode: cancelled ? null : (exitCode ?? null), violations: [] };
		} finally {
			clearTimeout(timer);
			request.signal?.removeEventListener("abort", cancel);
		}
	}

	private helper(
		compiled: CompiledProfile,
		cwd: string,
	): { client: HelperFsClient; children: Set<ChildProcessWithoutNullStreams> } {
		const spawned = new Set<ChildProcessWithoutNullStreams>();
		const client = new HelperFsClient({
			compiled,
			beforeCall: async () => {
				this.prepared(compiled);
			},
			spawnHelper: () => {
				const child = this.start(this.prepared(compiled), cwd, ["node", "/enclave/helper.mjs"], process.env);
				spawned.add(child);
				return child;
			},
			onViolation: (violation) => this.onFsViolation?.(violation),
		});
		this.clients.add(client);
		return { client, children: spawned };
	}
	fs(compiled: CompiledProfile): FsClient {
		this.prepared(compiled);
		let client = this.baseClients.get(compiled);
		if (!client) {
			client = this.helper(compiled, compiled.profile.writableRoots[0] as string).client;
			this.baseClients.set(compiled, client);
		}
		return client;
	}
	async fsWithReadCapability(
		compiled: CompiledProfile,
		value: string,
		_actionHash: string,
		cwd: string,
	): Promise<FsClientLease> {
		const profile = structuredClone(this.prepared(compiled).profile);
		const target = validateReadCapability(profile, cwd, value);
		profile.readDeny = profile.readDeny.filter((path) => canonical(path) !== target);
		profile.readableRoots = [...(profile.readableRoots ?? []), target];
		const widened = await this.compile(profile);
		const lease = this.helper(widened, cwd);
		return {
			client: lease.client,
			dispose: async () => {
				await lease.client.dispose();
				await Promise.all([...lease.children].map((child) => this.children.get(child)));
				this.clients.delete(lease.client);
				if (this.failure) throw this.failure;
			},
		};
	}
	async dispose(): Promise<void> {
		this.disposed = true;
		await Promise.all([...this.clients].map((client) => client.dispose()));
		for (const child of this.children.keys()) child.kill("SIGTERM");
		await Promise.all([...this.children.values()]);
		if (this.root) rmSync(this.root, { recursive: true, force: true });
		if (this.failure) throw this.failure;
	}
}
