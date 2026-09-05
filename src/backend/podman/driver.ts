/** Podman's native rootless CLI, locally or inside an explicitly named Mac VM. */
import { execFile } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { existsSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir, userInfo } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import { type DockerPlan, dockerPath } from "../docker/plan.ts";
import { canonical, isUnder } from "../paths.ts";

const execFileAsync = promisify(execFile);
const quote = (value: string) => `'${value.replaceAll("'", "'\\''")}'`;

export interface PodmanInfo {
	host?: {
		os?: string;
		cgroupVersion?: string;
		cgroupControllers?: string[];
		security?: { rootless?: boolean; seccompEnabled?: boolean };
	};
	store?: { graphRoot?: string; runRoot?: string; volumePath?: string };
}

export function validatePodmanInfo(info: PodmanInfo): void {
	if (
		info.host?.os !== "linux" ||
		info.host.security?.rootless !== true ||
		info.host.security.seccompEnabled !== true ||
		info.host.cgroupVersion !== "v2" ||
		!["cpu", "memory", "pids"].every((name) => info.host?.cgroupControllers?.includes(name))
	) {
		throw new Error(
			"pi-enclave: Podman requires rootless Linux, seccomp and delegated cgroup v2 cpu/memory/pids controllers",
		);
	}
}

export class PodmanDriver {
	readonly binary: string;
	readonly machine: string | undefined;
	readonly privateBase: string;
	private readonly hostHome = realpathSync(userInfo().homedir);
	private readonly protectedPaths: string[];
	private privateDir = "";
	private engineHome: string;
	private engineUid: number;

	constructor(options: { binary?: string; machine?: string }) {
		if (!["linux", "darwin"].includes(process.platform))
			throw new Error("pi-enclave: Podman supports Linux and macOS hosts only");
		if (process.platform === "linux" && options.machine)
			throw new Error("pi-enclave: Linux Podman uses the local rootless engine, not a remote machine");
		this.machine = process.platform === "darwin" ? (options.machine ?? "podman-machine-default") : undefined;
		if (this.machine && !/^[a-zA-Z0-9][a-zA-Z0-9_.-]*$/.test(this.machine))
			throw new Error("pi-enclave: invalid Podman machine name");
		this.binary = dockerPath(
			options.binary ??
				(process.platform === "darwin"
					? (["/opt/homebrew/bin/podman", "/usr/local/bin/podman", "/opt/podman/bin/podman"].find(existsSync) ??
						"/opt/homebrew/bin/podman")
					: "/usr/bin/podman"),
		);
		// macOS /var/folders temporary directories are not normally shared with the VM.
		this.privateBase = this.machine ? this.hostHome : realpathSync(tmpdir());
		this.engineHome = this.hostHome;
		this.engineUid = userInfo().uid;
		this.protectedPaths = [
			join(this.hostHome, ".config", "containers"),
			join(this.hostHome, ".local", "share", "containers"),
			join(this.hostHome, "Library", "Application Support", "containers"),
			`/run/user/${this.engineUid}`,
		];
	}

	configure(privateDir: string): void {
		this.privateDir = privateDir;
		writeFileSync(join(privateDir, "mounts.conf"), "", { mode: 0o600 });
		// Replace ambient containers.conf, including default mounts, hooks and env.
		// Keep the normal image store; XDG_CONFIG_HOME excludes user config/modules.
		writeFileSync(
			join(privateDir, "containers.conf"),
			`[containers]\ndefault_mounts_file = ${JSON.stringify(join(privateDir, "mounts.conf"))}\n[engine]\nhooks_dir = []\n`,
			{ mode: 0o600 },
		);
	}

	private engineEnv(): Record<string, string> {
		return {
			PATH: "/usr/bin:/bin",
			HOME: this.engineHome,
			LANG: "C.UTF-8",
			XDG_CONFIG_HOME: this.privateDir,
			XDG_DATA_HOME: join(this.engineHome, ".local", "share"),
			XDG_RUNTIME_DIR: `/run/user/${this.engineUid}`,
			DBUS_SESSION_BUS_ADDRESS: `unix:path=/run/user/${this.engineUid}/bus`,
			CONTAINERS_CONF: join(this.privateDir, "containers.conf"),
		};
	}

	env(): Record<string, string> {
		// machine ssh needs the user's existing VM configuration, but no agent,
		// remote context or environment-selected connections are inherited.
		return this.machine
			? { PATH: "/usr/bin:/bin:/usr/sbin:/sbin", HOME: this.hostHome, LANG: "C.UTF-8" }
			: this.engineEnv();
	}

	args(args: readonly string[]): string[] {
		if (!this.machine) return ["--remote=false", ...args];
		const command = [
			"/usr/bin/env",
			"-i",
			...Object.entries(this.engineEnv()).map(([key, value]) => `${key}=${value}`),
			"/usr/bin/podman",
			"--remote=false",
			...args,
		];
		// machine ssh invokes a remote shell: quote each argument, including paths
		// and literal Bash commands. The sandboxed command is never interpolated.
		return ["machine", "ssh", this.machine, command.map(quote).join(" ")];
	}

	private async hostControl(args: string[]): Promise<string> {
		const { stdout } = await execFileAsync(this.binary, args, {
			env: this.env(),
			cwd: this.privateDir,
			timeout: 30_000,
			maxBuffer: 1024 * 1024,
		});
		return stdout;
	}

	async initialize(): Promise<void> {
		if (!this.machine) return;
		const machines = JSON.parse(await this.hostControl(["machine", "inspect", this.machine])) as {
			State?: string;
			Rootful?: boolean;
		}[];
		if (machines.length !== 1 || machines[0]?.State !== "running" || machines[0].Rootful !== false)
			throw new Error("pi-enclave: start the selected Podman machine in rootless mode before testing");
		const result = await this.hostControl(["machine", "ssh", this.machine, "printf '%s\\n' \"$HOME\"; /usr/bin/id -u"]);
		const lines = result.trim().split("\n");
		const home = lines[0];
		const uid = Number(lines[1]);
		if (lines.length !== 2 || !home || !Number.isSafeInteger(uid) || uid <= 0)
			throw new Error("pi-enclave: Podman machine must have a non-root SSH user");
		this.engineHome = dockerPath(home);
		this.engineUid = uid;
	}

	checkInfo(info: PodmanInfo): void {
		validatePodmanInfo(info);
		// Image storage or runtime state must never be exposed via a host root.
		if (!this.machine) {
			for (const path of [info.store?.graphRoot, info.store?.runRoot, info.store?.volumePath]) {
				if (!path) throw new Error("pi-enclave: Podman did not report its storage paths");
				this.protectedPaths.push(dockerPath(path));
			}
		}
	}

	checkRoots(plan: DockerPlan): void {
		const protectedPaths = this.protectedPaths.flatMap((path) => [path, canonical(path)]);
		for (const root of [...plan.profile.writableRoots, ...(plan.profile.readableRoots ?? [])]) {
			if (this.machine && !isUnder(root, this.hostHome))
				throw new Error("pi-enclave: macOS Podman roots must be canonical paths inside the shared home directory");
			if (protectedPaths.some((path) => isUnder(path, root) || isUnder(root, path)))
				throw new Error(`pi-enclave: Podman host root overlaps engine configuration/storage: ${root}`);
		}
	}

	createArgs(uid: number, gid: number): string[] {
		return [
			`--userns=keep-id:uid=${uid},gid=${gid}`,
			"--read-only-tmpfs=false",
			"--systemd=false",
			"--http-proxy=false",
			"--pid=private",
			"--uts=private",
			// Explicit bounded shm is needed after disabling Podman's extra tmpfses.
			"--tmpfs",
			"/dev/shm:rw,nosuid,nodev,noexec,size=16m,mode=1777",
		];
	}

	/** Fail closed if the VM sees a different tree at an otherwise identical path. */
	async verifyShares(plan: DockerPlan): Promise<void> {
		if (!this.machine) return;
		const temporary: string[] = [];
		try {
			const sources = plan.mounts.filter((mount) => mount.kind === "bind").map((mount) => mount.source);
			const { statSync } = await import("node:fs");
			const files: string[] = [];
			for (const source of [this.privateDir, ...new Set(sources)]) {
				if (!statSync(source).isDirectory()) {
					files.push(source);
					continue;
				}
				// These host-only canaries also prove each nested bind. Read-only roots
				// must permit this temporary host write for the experimental VM runner.
				const path = join(source, `.pi-enclave-share-${randomUUID()}`);
				writeFileSync(path, randomUUID(), { flag: "wx", mode: 0o600 });
				temporary.push(path);
				files.push(path);
			}
			const expected = files
				.map((path) => `${createHash("sha256").update(readFileSync(path)).digest("hex")}  ${path}\0`)
				.join("");
			const actual = await this.hostControl([
				"machine",
				"ssh",
				this.machine,
				["/usr/bin/sha256sum", "--zero", "--", ...files].map(quote).join(" "),
			]);
			if (actual !== expected) throw new Error("pi-enclave: Podman machine does not see the same host bind sources");
		} finally {
			for (const path of temporary) rmSync(path, { force: true });
		}
	}
}
