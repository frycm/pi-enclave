/**
 * Resource limits (#24): the pure pieces every backend shares. The behaviour
 * on a real kernel is the L rows of the conformance suite.
 */
import { spawnSync } from "node:child_process";
import { describe, expect, it } from "vitest";
import {
	describeLimits,
	effectiveTimeout,
	enforcedRlimits,
	freeSpaceIssue,
	limitPrefix,
	OutputCap,
	timeoutNote,
} from "../../src/backend/limits.ts";
import type { CompiledProfile, Profile, RunRequest, SandboxBackend } from "../../src/backend/types.ts";
import { defaultLimits, defaultProfile } from "../../src/config/defaults.ts";
import { fold, narrowerOrEqual } from "../../src/config/merge.ts";
import { toBackendProfile } from "../../src/config/profile.ts";
import { parseDocument } from "../../src/config/schema.ts";
import type { ConfigDocument, EffectiveProfile } from "../../src/config/types.ts";
import { createEnclaveBashOperations } from "../../src/tools/bash.ts";

const LIMITS = { ...defaultLimits(), defaultTimeoutSec: 120, maxTimeoutSec: 1800 };
const OPTIONS = { cwd: "/work", home: "/home/u", tmp: "/tmp", agentDir: "/home/u/.pi/agent", env: {} };

describe("the effective timeout", () => {
	it("applies the default when the model passes none", () => {
		expect(effectiveTimeout(undefined, LIMITS)).toEqual({ seconds: 120, defaulted: true, clamped: false });
	});

	it("clamps a larger request to the maximum and keeps a smaller one", () => {
		expect(effectiveTimeout(99_999, LIMITS)).toEqual({ seconds: 1800, defaulted: false, clamped: true });
		expect(effectiveTimeout(30, LIMITS)).toEqual({ seconds: 30, defaulted: false, clamped: false });
	});

	it("never lets the default exceed the maximum", () => {
		expect(effectiveTimeout(undefined, { ...LIMITS, defaultTimeoutSec: 5000 })?.seconds).toBe(1800);
	});

	it("leaves a hand-built profile without limits unchanged", () => {
		expect(effectiveTimeout(undefined, undefined)).toBeUndefined();
	});

	it("tells the agent why a command ended and how to run longer", () => {
		const note = timeoutNote({ seconds: 120, defaulted: true, clamped: false }, LIMITS);
		expect(note).toContain("default of 120s");
		expect(note).toContain("up to 1800s");
		expect(timeoutNote({ seconds: 30, defaulted: false, clamped: false }, LIMITS)).toBeUndefined();
	});
});

describe("the output cap", () => {
	it("forwards up to the cap, trims the chunk that crosses it, then refuses", () => {
		const seen: Buffer[] = [];
		const cap = new OutputCap(1, (chunk) => seen.push(chunk));
		expect(cap.push(Buffer.alloc(1024 * 1024 - 10))).toBe(true);
		expect(cap.push(Buffer.alloc(100))).toBe(false);
		expect(cap.push(Buffer.alloc(100))).toBe(false);
		expect(cap.exceeded).toBe(true);
		expect(Buffer.concat(seen).length).toBe(1024 * 1024);
	});
});

describe("the rlimit prefix", () => {
	it("sets file size, open files, memory and processes on Linux, processes last", () => {
		const prefix = limitPrefix(LIMITS, "linux");
		expect(prefix).toContain(`-f ${LIMITS.fileSizeMb * 1024}`);
		expect(prefix).toContain(`-n ${LIMITS.openFiles}`);
		expect(prefix).toContain(`-d ${LIMITS.memoryMb * 1024}`);
		expect(prefix.indexOf("-u ")).toBeGreaterThan(prefix.indexOf("-d "));
	});

	it("sets only what macOS enforces per sandbox", () => {
		const prefix = limitPrefix(LIMITS, "darwin");
		expect(prefix).toContain("-f ");
		expect(prefix).not.toContain(" -u ");
		expect(prefix).not.toContain(" -d ");
		expect(enforcedRlimits("darwin")).toEqual(["fileSize", "openFiles"]);
	});

	it("is a file size limit of zero below the free-space floor", () => {
		expect(limitPrefix(LIMITS, "linux", true)).toContain("__pi_enclave_limit -f 0 ");
	});

	it("applies in a real bash, sets the hard limit, and leaves a lower limit alone", () => {
		const run = (script: string) =>
			spawnSync(
				"/bin/bash",
				["-c", `${limitPrefix({ ...LIMITS, fileSizeMb: 1, openFiles: 100 }, "darwin")}${script}`],
				{
					encoding: "utf8",
				},
			);
		const r = run('echo "$(ulimit -Hf) $(ulimit -Sf) $(ulimit -Hn)"; ulimit -f 4096 2>/dev/null && echo raised');
		expect(r.stdout.trim()).toBe("1024 1024 100");
		const lower = spawnSync("/bin/bash", ["-c", `ulimit -n 50; ${limitPrefix(LIMITS, "darwin")}ulimit -Hn`], {
			encoding: "utf8",
		});
		expect(lower.stdout.trim()).toBe("50");
	});

	it("does not run the command when a limit cannot be set", () => {
		const prefix = limitPrefix(LIMITS, "darwin").replace("-n 8192", "-Z 8192");
		const r = spawnSync("/bin/bash", ["-c", `${prefix}echo ran`], { encoding: "utf8" });
		expect(r.stdout).not.toContain("ran");
		expect(r.status).toBe(125);
	});
});

describe("the free-space floor", () => {
	it("reports the first writable root below the floor", () => {
		const free = new Map([
			["/work", 5 * 1024 ** 3],
			["/scratch", 100 * 1024 ** 2],
		]);
		const issue = freeSpaceIssue(["/work", "/scratch"], LIMITS, (path) => free.get(path));
		expect(issue).toContain("/scratch has 100 MB free");
		expect(issue).toContain("file size limit of zero");
		expect(freeSpaceIssue(["/work"], LIMITS, (path) => free.get(path))).toBeUndefined();
		expect(freeSpaceIssue(["/scratch"], { ...LIMITS, minFreeDiskMb: 0 }, (path) => free.get(path))).toBeUndefined();
	});
});

describe("limits in the configuration", () => {
	const doc = (source: ConfigDocument["source"], patch: object): ConfigDocument =>
		({ source, patch, path: `/${source}.json` }) as ConfigDocument;

	it("has defaults and reaches the backend profile", () => {
		const profile = defaultProfile(OPTIONS);
		expect(profile.sandbox.limits.defaultTimeoutSec).toBe(120);
		expect(toBackendProfile(profile, "/work", OPTIONS.agentDir).limits).toEqual(profile.sandbox.limits);
	});

	it("parses a partial limits object, including container limits", () => {
		const parsed = parseDocument(
			{ sandbox: { limits: { defaultTimeoutSec: 60, container: { memoryMb: 2048 } } } },
			"user_global",
			"/home/u/.pi/agent/enclave.json",
			OPTIONS,
		);
		if (!parsed.ok) throw new Error(JSON.stringify(parsed.errors));
		const result = fold([{ source: "builtin" }, parsed.document], OPTIONS);
		if (!result.ok) throw new Error(JSON.stringify(result.errors));
		expect(result.profile.sandbox.limits.defaultTimeoutSec).toBe(60);
		expect(result.profile.sandbox.limits.maxTimeoutSec).toBe(1800);
		expect(result.profile.sandbox.limits.container.memoryMb).toBe(2048);
		expect(result.profile.sandbox.limits.container.pids).toBe(256);
	});

	it.each([
		{ limits: { defaultTimeoutSec: 0 } },
		{ limits: { maxOutputMb: "big" } },
		{ limits: { unknown: 1 } },
		{ limits: { container: { gpus: 1 } } },
	])("rejects %j", (sandbox) => {
		expect(parseDocument({ sandbox }, "user_global", "/home/u/.pi/agent/enclave.json", OPTIONS).ok).toBe(false);
	});

	it("lets a project lower a limit and not raise one", () => {
		const lowered = fold(
			[{ source: "builtin" }, doc("project_local", { sandbox: { limits: { maxTimeoutSec: 600 } } })],
			OPTIONS,
		);
		expect(lowered.ok).toBe(true);
		const raised = fold(
			[{ source: "builtin" }, doc("project_local", { sandbox: { limits: { memoryMb: 65536 } } })],
			OPTIONS,
		);
		expect(raised.ok).toBe(false);
		if (!raised.ok) expect(raised.errors.map((error) => error.field)).toContain("sandbox.limits.memoryMb");
	});

	it("treats the free-space floor as a floor and container limits as ceilings", () => {
		const base = defaultProfile(OPTIONS);
		const edit = (change: (p: EffectiveProfile) => void) => {
			const p = defaultProfile(OPTIONS);
			change(p);
			return narrowerOrEqual(p, base).map((violation) => violation.field);
		};
		expect(edit((p) => (p.sandbox.limits.minFreeDiskMb = 0))).toEqual(["sandbox.limits.minFreeDiskMb"]);
		expect(edit((p) => (p.sandbox.limits.minFreeDiskMb = 4096))).toEqual([]);
		expect(edit((p) => (p.sandbox.limits.container.pids = 4096))).toEqual(["sandbox.limits.container.pids"]);
		expect(edit((p) => (p.sandbox.limits.container.cpus = 1))).toEqual([]);
	});

	it("is described for /enclave status per backend", () => {
		expect(describeLimits(LIMITS, "bwrap", "linux")).toContain("processes 1024");
		expect(describeLimits(LIMITS, "seatbelt", "darwin")).toContain("NOT limited on this platform");
		expect(describeLimits(LIMITS, "docker", "linux")).toContain("cgroup pids 256, memory 512 MB");
	});
});

describe("a command a person typed", () => {
	it("gets the maximum timeout rather than the default", async () => {
		const profile: Profile = {
			mode: "workspace-write",
			writableRoots: ["/work"],
			readDeny: [],
			network: "off",
			allowPty: true,
			limits: LIMITS,
		};
		const compiled: CompiledProfile = { backend: "seatbelt", profile, describe: () => "" };
		const calls: RunRequest[] = [];
		const backend: SandboxBackend = {
			name: "seatbelt",
			compile: async () => compiled,
			run: async (_c, request) => {
				calls.push(request);
				return { exitCode: 0, violations: [] };
			},
			fs: () => {
				throw new Error("unused");
			},
			dispose: async () => {},
		};
		const onData = () => {};
		await createEnclaveBashOperations({ backend, getCompiled: () => compiled, userCommand: true }).exec(
			"true",
			"/work",
			{
				onData,
			},
		);
		await createEnclaveBashOperations({ backend, getCompiled: () => compiled }).exec("true", "/work", { onData });
		expect(calls[0]?.timeout).toBe(1800);
		expect(calls[1]?.timeout).toBeUndefined();
	});
});
