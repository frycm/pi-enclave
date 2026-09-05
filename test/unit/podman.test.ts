import { execFileSync, spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { mountArguments } from "../../src/backend/docker/plan.ts";
import { PodmanDriver, type PodmanInfo, validatePodmanInfo } from "../../src/backend/podman/driver.ts";

const supported: PodmanInfo = {
	host: {
		os: "linux",
		cgroupVersion: "v2",
		cgroupControllers: ["cpu", "memory", "pids"],
		security: { rootless: true, seccompEnabled: true },
	},
};

afterEach(() => vi.unstubAllGlobals());

describe("Podman admission", () => {
	it("accepts rootless Linux with seccomp and delegated resource controllers", () => {
		expect(() => validatePodmanInfo(supported)).not.toThrow();
	});
	it.each([
		{},
		{ ...supported.host, os: "darwin" },
		{ ...supported.host, security: { rootless: false, seccompEnabled: true } },
		{ ...supported.host, security: { rootless: true, seccompEnabled: false } },
		{ ...supported.host, cgroupVersion: "v1" },
		{ ...supported.host, cgroupControllers: ["memory", "pids"] },
	])("refuses an unsupported engine rather than dropping protections (%j)", (host) => {
		expect(() => validatePodmanInfo({ host })).toThrow(/rootless Linux/);
	});

	it("uses Podman's nonrecursive bind spelling for host roots and masks", () => {
		const args = mountArguments(
			{
				profile: { mode: "workspace-write", writableRoots: [], readDeny: [], network: "off", allowPty: true },
				mounts: [{ source: "/secret", target: "/secret", readonly: true, kind: "mask-file" }],
				observedPaths: [],
				snapshot: "",
			},
			"/private-state",
			"podman",
		);
		expect(args).toEqual([
			"--mount",
			"type=bind,source=/private-state/empty-file,target=/secret,bind-nonrecursive,readonly",
		]);
	});

	it("isolates native CLI configuration and keeps rootless ownership without ambient authority", () => {
		vi.stubGlobal("process", {
			...process,
			platform: "linux",
			env: { CONTAINER_HOST: "tcp://untrusted", PODMAN_USERNS: "host", CONTAINERS_CONF: "/untrusted" },
		});
		const driver = new PodmanDriver({});
		const state = mkdtempSync(join(tmpdir(), "enclave-podman-driver-"));
		try {
			driver.configure(state);
			expect(driver.args(["info"])).toEqual(["--remote=false", "info"]);
			expect(driver.env().CONTAINER_HOST).toBeUndefined();
			expect(driver.env().PODMAN_USERNS).toBeUndefined();
			expect(driver.env().CONTAINERS_CONF).toBe(join(state, "containers.conf"));
			expect(readFileSync(join(state, "containers.conf"), "utf8")).toContain("hooks_dir = []");
			expect(driver.createArgs(501, 20)).toContain("--userns=keep-id:uid=501,gid=20");
			expect(driver.createArgs(501, 20)).toContain("--read-only-tmpfs=false");
		} finally {
			rmSync(state, { recursive: true, force: true });
		}
	});

	it("round-trips literal arguments through the machine SSH shell without expansion", () => {
		vi.stubGlobal("process", { ...process, platform: "darwin" });
		const driver = new PodmanDriver({ binary: "/trusted/podman", machine: "enclave" });
		const words = ["create", "space ' quote", "$(printf INJECTED)", "`printf INJECTED`", "line\nbreak", "semi;colon"];
		const args = driver.args(words);
		expect(args.slice(0, 3)).toEqual(["machine", "ssh", "enclave"]);
		// Execute the real POSIX shell quoting using a harmless argv recorder.
		const script = (args[3] ?? "").replace("'/usr/bin/podman'", "'/usr/bin/printf' '%s\\0'");
		const output = execFileSync("/bin/sh", ["-c", script]).toString();
		expect(output.split("\0")).toEqual(["--remote=false", ...words, ""]);
	});

	it("starts machine SSH without user or system SSH configuration", () => {
		vi.stubGlobal("process", { ...process, platform: "darwin" });
		const driver = new PodmanDriver({ machine: "enclave" });
		const state = mkdtempSync(join(realpathSync(tmpdir()), "enclave-podman-ssh-"));
		try {
			driver.configure(state);
			// OpenSSH -G resolves configuration locally without opening a connection.
			// -F is reported as the effective config source, proving the PATH shim
			// executes the real client with an empty config.
			const result = spawnSync("/bin/sh", ["-c", "ssh -G -v example.invalid"], {
				env: driver.env(),
				encoding: "utf8",
				stdio: ["ignore", "pipe", "pipe"],
			});
			expect(result.status, result.stderr).toBe(0);
			expect(result.stdout).toMatch(/hostname example\.invalid/);
			expect(result.stdout).toMatch(/permitlocalcommand no/);
			expect(result.stderr).toContain("Reading configuration data /dev/null");
			expect(result.stderr).not.toMatch(/Reading configuration data .*\/ssh(?:_config|\/config)/);
		} finally {
			rmSync(state, { recursive: true, force: true });
		}
	});

	it("rejects machine names that could become CLI flags or shell fragments", () => {
		vi.stubGlobal("process", { ...process, platform: "darwin" });
		for (const machine of ["--rootful", "a;b", "a b", "$(id)"])
			expect(() => new PodmanDriver({ machine })).toThrow(/machine name/);
	});

	it("keeps symlinked and retargeted engine storage outside exposed roots", () => {
		vi.stubGlobal("process", { ...process, platform: "linux" });
		const driver = new PodmanDriver({});
		const state = mkdtempSync(join(realpathSync(tmpdir()), "enclave-podman-storage-"));
		try {
			const link = join(state, "store");
			const first = join(state, "first");
			const second = join(state, "second");
			mkdirSync(first);
			mkdirSync(second);
			symlinkSync(first, link);
			driver.checkInfo({
				...supported,
				store: { graphRoot: link, runRoot: "/run/user/1234", volumePath: `${link}/volumes` },
			});
			const check = (root: string) =>
				driver.checkRoots({
					profile: { mode: "workspace-write", writableRoots: [root], readDeny: [], network: "off", allowPty: true },
					mounts: [],
					observedPaths: [],
					snapshot: "",
				});
			expect(() => check(first)).toThrow(/configuration\/storage/);
			rmSync(link);
			symlinkSync(second, link);
			expect(() => check(second)).toThrow(/configuration\/storage/);
		} finally {
			rmSync(state, { recursive: true, force: true });
		}
	});
});
