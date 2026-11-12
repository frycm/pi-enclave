/**
 * `sandbox.readMode: "allowlist"` (#23): the roots it lets back in, how the
 * SRT configuration expresses it, how a refused read is classified, and the
 * configuration rules that keep it from being loosened.
 */
import { describe, expect, it } from "vitest";
import { classifyErrno } from "../../src/backend/errno.ts";
import {
	allowlistReadRoots,
	LINUX_SYSTEM_READ_ROOTS,
	outsideReadAllowlist,
	withAllowlistGitConfig,
	withReadCapability,
} from "../../src/backend/read-allowlist.ts";
import { toSrtConfig } from "../../src/backend/srt.ts";
import type { Profile } from "../../src/backend/types.ts";
import { defaultProfile } from "../../src/config/defaults.ts";
import { fold } from "../../src/config/merge.ts";
import { toBackendProfile } from "../../src/config/profile.ts";
import { parseDocument } from "../../src/config/schema.ts";

const HOME = "/home/u";
const OPTIONS = { cwd: "/home/u/work/app", home: HOME, tmp: "/tmp", agentDir: "/home/u/.pi/agent" };

const roots = (overrides: Partial<Parameters<typeof allowlistReadRoots>[0]> = {}) =>
	allowlistReadRoots({
		profile: { writableRoots: ["/home/u/work/app", "/run/user/1000/pi-enclave-u/s1"], readAllow: [], readDeny: [] },
		platform: "linux",
		path: "/home/u/.cargo/bin:/usr/local/bin:/usr/bin:/home/u/bin:relative/bin:/home/u/.local/bin",
		execPath: "/home/u/.nvm/versions/node/v24.1.0/bin/node",
		helperPath: "/home/u/.pi/agent/npm/pi-enclave/src/fs/helper.mjs",
		hostTools: ["/home/u/.pi/agent/npm/pi-enclave/node_modules/@vscode/ripgrep/bin/rg"],
		home: HOME,
		exists: () => true,
		resolve: (path) => path,
		...overrides,
	});

describe("the read allowlist", () => {
	it("lets back the system, the writable roots, the toolchain and pi-enclave's helper", () => {
		const out = roots();
		for (const system of LINUX_SYSTEM_READ_ROOTS) expect(out).toContain(system);
		expect(out).toContain("/home/u/work/app");
		expect(out).toContain("/run/user/1000/pi-enclave-u/s1");
		// The Node install root, where npm and its libraries live.
		expect(out).toContain("/home/u/.nvm/versions/node/v24.1.0/bin");
		expect(out).toContain("/home/u/.nvm/versions/node/v24.1.0");
		expect(out).toContain("/home/u/.pi/agent/npm/pi-enclave/src/fs");
		expect(out).toContain("/home/u/.cargo");
		expect(out).toContain("/home/u/bin");
	});

	it("never lets back the home directory, its parent or /", () => {
		const out = roots({
			path: "/:/home/u:/home:/home/u/bin",
			profile: { writableRoots: ["/home/u/work/app"], readAllow: ["/home", "/"], readDeny: [] },
		});
		expect(out).not.toContain("/");
		expect(out).not.toContain(HOME);
		expect(out).not.toContain("/home");
		// ~/bin's install root would be ~ itself.
		expect(out).toContain("/home/u/bin");
	});

	it("does not open ~/.local for a ~/.local/bin entry", () => {
		const out = roots();
		expect(out).toContain("/home/u/.local/bin");
		expect(out).not.toContain("/home/u/.local");
	});

	it("does not open a sibling project", () => {
		const out = roots();
		expect(
			outsideReadAllowlist("/home/u/work/other/.env", { readMode: "allowlist", readAllow: out, writableRoots: [] }),
		).toBe(true);
		expect(
			outsideReadAllowlist("/home/u/.bash_history", { readMode: "allowlist", readAllow: out, writableRoots: [] }),
		).toBe(true);
	});

	it("adds the configured readable roots and the canonical spelling of a link", () => {
		const out = roots({
			profile: { writableRoots: ["/home/u/work/app"], readAllow: ["/srv/data"], readDeny: [] },
			resolve: (path) => (path === "/srv/data" ? "/mnt/disk/data" : path),
		});
		expect(out).toContain("/srv/data");
		expect(out).toContain("/mnt/disk/data");
	});

	it("leaves out a root at or below a deny entry, which would otherwise lift it", () => {
		const out = roots({
			profile: {
				writableRoots: ["/home/u/work/app"],
				readAllow: ["/home/u/.ssh", "/home/u/.aws/sub", "/srv/data"],
				readDeny: ["/home/u/.ssh", "/home/u/.aws", "/srv/data/secret"],
			},
		});
		expect(out).not.toContain("/home/u/.ssh");
		expect(out).not.toContain("/home/u/.aws/sub");
		// Above a deny is fine: the deeper deny still applies inside it.
		expect(out).toContain("/srv/data");
	});

	describe("judges every exclusion on the canonical location (review of #55)", () => {
		// /home/u is a link to /data/home/u, as with a home on a data disk, an
		// automounted home or /home -> var/home.
		const linked = (path: string) => path.replace(/^\/home\/u(?=\/|$)/, "/data/home/u");
		const base = { writableRoots: ["/srv/work/app"], readAllow: [] as string[], readDeny: [] as string[] };

		it("does not open a home reached through a link because rg sits in ~/bin", () => {
			const out = roots({
				profile: base,
				path: "/usr/bin",
				hostTools: ["/home/u/bin/rg"],
				resolve: linked,
			});
			expect(out).toContain("/data/home/u/bin");
			expect(out).not.toContain("/data/home/u");
			expect(out).not.toContain("/home/u");
		});

		it("does not open ~/.local through the link for fd in ~/.local/bin", () => {
			const out = roots({ profile: base, path: "/usr/bin", hostTools: ["/home/u/.local/bin/fd"], resolve: linked });
			expect(out).not.toContain("/data/home/u/.local");
			expect(out).not.toContain("/home/u/.local");
		});

		it("does not open the home for a PATH entry spelled through the link when home is canonical", () => {
			const out = roots({ profile: base, home: "/data/home/u", path: "/home/u/bin", resolve: linked });
			expect(out).not.toContain("/home/u");
			expect(out).not.toContain("/data/home/u");
			expect(out).toContain("/data/home/u/bin");
		});

		it("does not let a PATH entry spelled through a link lift a deny entry", () => {
			const out = roots({
				profile: { ...base, readDeny: ["/data/home/u/.docker"] },
				home: "/data/home/u",
				path: "/home/u/.docker/bin",
				resolve: linked,
			});
			expect(out.filter((root) => root.includes(".docker"))).toEqual([]);
		});

		it("does not climb from a shallow bin into a shared store or a top-level directory", () => {
			const out = roots({
				profile: base,
				path: "/home/u/.config/bin:/home/u/Library/bin:/opt/bin:/var/bin:/home/u/.cache/bin",
				resolve: (path) => path,
			});
			for (const root of ["/home/u/.config", "/home/u/Library", "/opt", "/var", "/home/u/.cache"]) {
				expect(out).not.toContain(root);
			}
			expect(out).toContain("/home/u/.config/bin");
			expect(out).toContain("/opt/bin");
		});

		it("does not climb into a custom XDG directory either", () => {
			const out = roots({
				profile: base,
				path: "/srv/xdg/config/bin",
				env: { XDG_CONFIG_HOME: "/srv/xdg/config" },
				resolve: (path) => path,
			});
			expect(out).not.toContain("/srv/xdg/config");
			expect(out).toContain("/srv/xdg/config/bin");
		});
	});

	it("leaves out paths that do not exist", () => {
		const out = roots({ exists: (path) => path !== "/nix" && path !== "/run/current-system" });
		expect(out).not.toContain("/nix");
		expect(out).toContain("/usr");
	});

	it("uses the macOS system roots on darwin", () => {
		const out = roots({ platform: "darwin", home: "/Users/u", path: "/usr/bin" });
		expect(out).toContain("/System");
		expect(out).toContain("/Library");
		expect(out).not.toContain("/lib64");
	});

	it("lets the /var and /tmp links be followed on macOS without opening what is behind them", () => {
		const out = roots({
			platform: "darwin",
			home: "/Users/u",
			path: "/usr/bin",
			resolve: (path) => (path === "/var" || path === "/tmp" ? `/private${path}` : path),
		});
		expect(out).toContain("/var");
		expect(out).toContain("/tmp");
		expect(out).not.toContain("/private/var");
		expect(out).not.toContain("/private/tmp");
		expect(roots()).not.toContain("/var");
		// The link name does not count as a readable root when a refusal is classified.
		expect(
			outsideReadAllowlist("/var/folders/x/T/outside/secret", {
				readMode: "allowlist",
				readAllow: ["/usr", "/var", "/tmp"],
				writableRoots: [],
			}),
		).toBe(true);
	});
});

describe("git in allowlist mode", () => {
	const profile = { readMode: "allowlist" as const, readAllow: ["/usr"], writableRoots: ["/home/u/work/app"] };

	it("tells git there is no user configuration it cannot read", () => {
		expect(withAllowlistGitConfig(profile, { PATH: "/usr/bin" }, HOME)).toEqual({
			PATH: "/usr/bin",
			GIT_CONFIG_GLOBAL: "/dev/null",
		});
	});

	it("leaves git alone when its configuration is readable, already chosen, or in open mode", () => {
		const readable = { ...profile, readAllow: ["/usr", "/home/u/.gitconfig"] };
		expect(withAllowlistGitConfig(readable, {}, HOME)).toEqual({});
		const xdg = { ...profile, readAllow: ["/home/u/.config/git"] };
		expect(withAllowlistGitConfig(xdg, {}, HOME)).toEqual({});
		expect(withAllowlistGitConfig(profile, { GIT_CONFIG_GLOBAL: "/etc/gitconfig.ci" }, HOME)).toEqual({
			GIT_CONFIG_GLOBAL: "/etc/gitconfig.ci",
		});
		expect(withAllowlistGitConfig({ ...profile, readMode: "open" }, {}, HOME)).toEqual({});
	});
});

describe("the SRT configuration in allowlist mode", () => {
	// No link on the way to the deny entry, so its canonical spelling is the
	// same on Linux and on macOS (where /home and /tmp are links).
	const secret = "/pi-enclave-test-root/u/.ssh";
	const base: Profile = {
		mode: "workspace-write",
		writableRoots: ["/tmp/ws"],
		readDeny: [secret],
		network: "off",
		allowPty: true,
	};

	it("denies / and lets the allowlist back in, with the deny list still applied", () => {
		const config = toSrtConfig({ ...base, readMode: "allowlist", readAllow: ["/usr", "/tmp/ws"] }, false, "linux");
		expect(config.filesystem.denyRead[0]).toBe("/");
		expect(config.filesystem.denyRead).toContain(secret);
		expect(config.filesystem.allowRead).toEqual(["/usr", "/tmp/ws"]);
	});

	it("is unchanged in open mode", () => {
		const config = toSrtConfig(base, false, "linux");
		expect(config.filesystem.denyRead).not.toContain("/");
		expect(config.filesystem.allowRead).toBeUndefined();
	});

	it("adds a read capability's target to the allowlist as well as lifting its deny", () => {
		const granted = withReadCapability({ ...base, readMode: "allowlist", readAllow: ["/usr"] }, secret);
		expect(granted.readDeny).toEqual([]);
		expect(granted.readAllow).toEqual(["/usr", secret]);
		const open = withReadCapability(base, secret);
		expect(open.readAllow).toBeUndefined();
	});
});

describe("classifying a refused read in allowlist mode", () => {
	const profile: Profile = {
		mode: "workspace-write",
		writableRoots: ["/tmp/ws"],
		readDeny: [],
		readMode: "allowlist",
		readAllow: ["/usr"],
		network: "off",
		allowPty: true,
	};
	const classify = (path: string, code: string, p: Profile = profile) =>
		classifyErrno({ error: { code }, op: "readFile", path, profile: p, backend: "bwrap" });

	it("reports a read outside the allowlist as a denial", () => {
		expect(classify("/home/u/notes.txt", "ENOENT")?.kind).toBe("read");
		expect(classify("/home/u/notes.txt", "EPERM")?.kind).toBe("read");
	});

	it("passes through a missing file inside an allowed root", () => {
		expect(classify("/usr/share/missing", "ENOENT")).toBeNull();
		expect(classify("/tmp/ws/missing", "ENOENT")).toBeNull();
	});

	it("is unchanged in open mode", () => {
		expect(classify("/home/u/notes.txt", "ENOENT", { ...profile, readMode: "open" })).toBeNull();
	});

	it("passes through a missing file under /proc, /sys or /dev, which the sandbox always mounts", () => {
		expect(classify("/proc/12345/status", "ENOENT")).toBeNull();
		expect(classify("/sys/class/missing", "ENOENT")).toBeNull();
		expect(classify("/dev/missing", "ENOENT")).toBeNull();
	});
});

describe("configuring the read mode", () => {
	const parse = (raw: unknown, source: "user_global" | "project_shared" = "user_global") =>
		parseDocument(
			raw,
			source,
			source === "user_global" ? "/home/u/.pi/agent/enclave.json" : "/home/u/work/app/.pi/enclave.json",
			OPTIONS,
		);
	const errorKeys = (result: ReturnType<typeof parse>) => (result.ok ? [] : result.errors.map((error) => error.key));
	const folded = (raw: unknown) => {
		const parsed = parse(raw);
		if (!parsed.ok) throw new Error(errorKeys(parsed).join());
		return fold([{ source: "builtin" }, parsed.document], OPTIONS);
	};

	it("defaults to open, and allowlist reaches the backend profile with the readable roots", () => {
		expect(defaultProfile(OPTIONS).sandbox.readMode).toBe("open");
		const result = folded({ sandbox: { readMode: "allowlist", readableRoots: ["/srv/data"] } });
		if (!result.ok) throw new Error(result.errors.map((e) => e.message).join());
		const backend = toBackendProfile(result.profile, OPTIONS.cwd, OPTIONS.agentDir);
		expect(backend.readMode).toBe("allowlist");
		expect(backend.readAllow).toEqual(["/srv/data"]);
	});

	it("rejects an unknown read mode", () => {
		expect(errorKeys(parse({ sandbox: { readMode: "closed" } }))).toEqual(["sandbox.readMode"]);
	});

	it("lets a project narrow to allowlist but not reopen it", () => {
		const user = parse({ sandbox: { readMode: "allowlist" } });
		const reopen = parse({ sandbox: { readMode: "open" } }, "project_shared");
		const narrow = parse({ sandbox: { readMode: "allowlist" } }, "project_shared");
		if (!user.ok || !reopen.ok || !narrow.ok) throw new Error("parse");
		expect(fold([{ source: "builtin" }, user.document, reopen.document], OPTIONS).ok).toBe(false);
		const narrowed = fold([{ source: "builtin" }, narrow.document], OPTIONS);
		expect(narrowed.ok && narrowed.profile.sandbox.readMode).toBe("allowlist");
	});

	it("refuses / as a readable root", () => {
		expect(folded({ sandbox: { readMode: "allowlist", readableRoots: ["/"] } }).ok).toBe(false);
	});

	it("refuses the home directory or its parent as a readable root, which the backend would drop", () => {
		for (const root of ["~", "/home/u", "/home"]) {
			const result = folded({ sandbox: { readMode: "allowlist", readableRoots: [root] } });
			expect(result.ok).toBe(false);
			if (result.ok) continue;
			expect(result.errors.map((error) => error.message).join()).toContain("home directory");
		}
		expect(folded({ sandbox: { readMode: "allowlist", readableRoots: ["/home/u/data"] } }).ok).toBe(true);
	});

	it("refuses a readable root on or below a read-deny path", () => {
		const result = folded({ sandbox: { readMode: "allowlist", readableRoots: ["~/.ssh/keys"] } });
		expect(result.ok).toBe(false);
		if (result.ok) return;
		expect(result.errors.map((error) => error.message).join()).toContain("cannot expose a denied path");
	});

	it("does not let a project file add readable roots or open the read mode", () => {
		expect(errorKeys(parse({ sandbox: { readableRoots: ["/home/u/work/other"] } }, "project_shared"))).toEqual([
			"sandbox.readableRoots",
		]);
	});
});

describe("the read mode in /enclave status", () => {
	const base: Profile = { mode: "workspace-write", writableRoots: [], readDeny: [], network: "off", allowPty: true };

	it("says OPEN for a deny-list, the root count for an allowlist, and allowlist for a container", async () => {
		const { describeReadMode } = await import("../../src/commands/enclave.ts");
		expect(describeReadMode(base, "bwrap")).toMatch(/^OPEN/);
		expect(describeReadMode({ ...base, readMode: "allowlist", readAllow: ["/usr", "/etc"] }, "seatbelt")).toContain(
			"allowlist: 2 root(s)",
		);
		expect(describeReadMode(base, "podman")).toMatch(/^allowlist \(container/);
	});
});
