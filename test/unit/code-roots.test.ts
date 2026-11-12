/**
 * Loaded code below a writable root (#36): refused by default, write-denied
 * with the user-global opt-in.
 */
import { mkdirSync, mkdtempSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import type { ExtensionAPI, ExtensionContext } from "@earendil-works/pi-coding-agent";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { toSrtConfig } from "../../src/backend/srt.ts";
import type { CompiledProfile, Profile } from "../../src/backend/types.ts";
import { defaultProfile, OWNED_TOOLS } from "../../src/config/defaults.ts";
import { toBackendProfile } from "../../src/config/profile.ts";
import type { EffectiveProfile } from "../../src/config/types.ts";
import {
	applySelfHosting,
	type CodeSources,
	checkCodeRoots,
	collectCodeRoots,
	extensionArguments,
	formatCodeRootProblems,
	packageRootOf,
	resolveDependencyEntries,
} from "../../src/gate/code-roots.ts";
import { hostExecutableSafety, hostRuntimeSafety } from "../../src/probe-host.ts";

const mocks = vi.hoisted(() => ({
	loadConfig: vi.fn(),
	compile: vi.fn(),
}));

vi.mock("../../src/probe-host.ts", async (original) => ({
	...(await original<typeof import("../../src/probe-host.ts")>()),
	probeHost: () => ({ ok: true, platform: "linux", backend: "bwrap", piVersion: "1.5.2", checks: [] }),
}));
vi.mock("../../src/config/sources.ts", () => ({ loadConfig: mocks.loadConfig }));
vi.mock("../../src/backend/select.ts", () => ({
	selectBackend: async () => ({
		backend: { name: "fake", compile: mocks.compile, dispose: async () => {} },
		report: { ok: true, platform: "linux", backend: "bwrap", piVersion: "1.5.2", checks: [] },
	}),
}));

let root: string;
let ws: string;
let outside: string;

beforeEach(() => {
	root = realpathSync(mkdtempSync(join(tmpdir(), "enclave-code-")));
	ws = join(root, "ws");
	outside = join(root, "outside");
	// An extension checked out inside the workspace, the dogfooding layout.
	mkdirSync(join(ws, "ext", "src"), { recursive: true });
	writeFileSync(join(ws, "ext", "package.json"), "{}\n");
	writeFileSync(join(ws, "ext", "src", "index.ts"), "export default () => {};\n");
	mkdirSync(join(outside, "node", "bin"), { recursive: true });
	writeFileSync(join(outside, "node", "bin", "node"), "");
	mkdirSync(join(outside, "pi", "dist"), { recursive: true });
	writeFileSync(join(outside, "pi", "package.json"), "{}\n");
	writeFileSync(join(outside, "pi", "dist", "cli.js"), "");
});
afterEach(() => rmSync(root, { recursive: true, force: true }));

const sources = (overrides: Partial<CodeSources> = {}): CodeSources => ({
	ownSource: join(outside, "pi", "dist", "cli.js"),
	dependencyEntries: [],
	piEntry: join(outside, "pi", "dist", "cli.js"),
	extensionPaths: [{ path: join(ws, "ext", "src", "index.ts"), from: "extension" }],
	execPath: join(outside, "node", "bin", "node"),
	seccompHelper: null,
	cwd: ws,
	home: join(root, "home"),
	...overrides,
});

const check = (s: CodeSources, writable = [ws]) => checkCodeRoots(collectCodeRoots(s, writable), writable);

describe("loaded code roots (#36)", () => {
	it("finds the package root of a loaded file", () => {
		expect(packageRootOf(join(ws, "ext", "src", "index.ts"), join(root, "home"))).toBe(join(ws, "ext"));
	});

	it("does not take a package.json in the home directory for a package root", () => {
		const home = join(root, "home");
		mkdirSync(join(home, ".pi", "agent", "extensions"), { recursive: true });
		writeFileSync(join(home, "package.json"), "{}\n");
		const file = join(home, ".pi", "agent", "extensions", "x.ts");
		writeFileSync(file, "");
		expect(packageRootOf(file, home)).toBe(join(home, ".pi", "agent", "extensions"));
	});

	it("refuses auto mode by default for an extension under cwd", () => {
		const result = check(sources());
		expect(result.exposed.map((r) => r.path)).toEqual([join(ws, "ext")]);
		const message = formatCodeRootProblems(result, false);
		expect(message).toMatch(/refusing to start auto mode/);
		expect(message).toContain(join(ws, "ext"));
		expect(message).toMatch(/sandbox\.allowSelfHosting/);
	});

	it("accepts nothing outside the writable roots", () => {
		const result = check(sources({ extensionPaths: [] }));
		expect(result).toEqual({ exposed: [], refused: [], missing: [] });
		expect(formatCodeRootProblems(result, false)).toBeUndefined();
	});

	it("with the opt-in, write-denies the code roots instead", () => {
		const result = check(sources());
		expect(formatCodeRootProblems(result, true)).toBeUndefined();
		const profile = applySelfHosting(toBackendProfile(defaultProfile({ cwd: ws }), ws), result);
		expect(profile.writeDeny).toContain(join(ws, "ext"));
		// The node_modules a later start would search above it, created read-only.
		expect(profile.selfHosted).toEqual([join(ws, "ext"), join(ws, "node_modules")]);
		expect(profile.materializeWriteDeny).toContain(join(ws, "node_modules"));
		expect(toSrtConfig(profile, false, "linux").filesystem.denyWrite).toContain(join(ws, "ext"));
	});

	it("with the opt-in, protects every missing node_modules between a root and its writable root", () => {
		// The npm workspace layout from the review: a hoisted dependency in
		// <pi>/node_modules, and packages/agent loaded. A new
		// packages/node_modules/dep would shadow the hoisted one.
		const pi = join(ws, "pi");
		mkdirSync(join(pi, "node_modules", "dep"), { recursive: true });
		mkdirSync(join(pi, "packages", "agent", "dist"), { recursive: true });
		writeFileSync(join(pi, "package.json"), "{}\n");
		writeFileSync(join(pi, "packages", "agent", "package.json"), "{}\n");
		writeFileSync(join(pi, "packages", "agent", "dist", "cli.js"), "");
		const result = check(sources({ extensionPaths: [], piEntry: join(pi, "packages", "agent", "dist", "cli.js") }));
		expect(result.exposed.map((r) => r.path).sort()).toEqual([join(pi, "node_modules"), join(pi, "packages", "agent")]);
		expect(result.missing.sort()).toEqual([join(ws, "node_modules"), join(pi, "packages", "node_modules")]);
		const profile = applySelfHosting(toBackendProfile(defaultProfile({ cwd: ws }), ws), result);
		expect(profile.writeDeny).toEqual(expect.arrayContaining([join(pi, "packages", "node_modules")]));
		expect(profile.materializeWriteDeny).toEqual(expect.arrayContaining([join(pi, "packages", "node_modules")]));
	});

	it("refuses a symlinked node_modules between a root and its writable root", () => {
		mkdirSync(join(outside, "elsewhere"));
		symlinkSync(join(outside, "elsewhere"), join(ws, "node_modules"));
		const result = check(sources());
		expect(result.refused.map((r) => r.root.path)).toContain(join(ws, "node_modules"));
		expect(formatCodeRootProblems(result, true)).toMatch(/replace it with a directory/);
	});

	it("follows symlinked workspace packages to the code they name, transitively", () => {
		// pi started from packages/agent outside the workspace; cwd is the
		// sibling package it loads through node_modules/@x/tui, which in turn
		// links @x/ai.
		const pi = join(outside, "pi-fork");
		const tui = join(ws, "tui");
		const ai = join(ws, "ai");
		mkdirSync(join(pi, "node_modules", "@x"), { recursive: true });
		mkdirSync(join(pi, "packages", "agent", "dist"), { recursive: true });
		writeFileSync(join(pi, "packages", "agent", "package.json"), "{}\n");
		writeFileSync(join(pi, "packages", "agent", "dist", "cli.js"), "");
		for (const dir of [tui, ai]) {
			mkdirSync(join(dir, "node_modules", "@x"), { recursive: true });
			writeFileSync(join(dir, "package.json"), "{}\n");
		}
		symlinkSync(tui, join(pi, "node_modules", "@x", "tui"));
		symlinkSync(ai, join(tui, "node_modules", "@x", "ai"));
		const result = check(sources({ extensionPaths: [], piEntry: join(pi, "packages", "agent", "dist", "cli.js") }));
		expect(result.exposed.map((r) => r.path).sort()).toEqual([ai, tui]);
		expect(formatCodeRootProblems(result, false)).toContain(
			`package linked from ${join(pi, "node_modules", "@x", "tui")}`,
		);
		// The workspace itself as one of the linked packages: refused outright.
		const self = check(sources({ extensionPaths: [], piEntry: join(pi, "packages", "agent", "dist", "cli.js") }), [
			tui,
		]);
		expect(self.refused.map((r) => r.root.path)).toContain(tui);
	});

	it("reads extension paths from -e and --extension", () => {
		expect(extensionArguments(["node", "pi", "-e", "./a.ts", "--extension", "/b", "--extension=c", "-p", "x"])).toEqual(
			["./a.ts", "/b", "c"],
		);
	});

	it("counts every existing node_modules above a root as loaded code", () => {
		mkdirSync(join(ws, "node_modules", "dep"), { recursive: true });
		writeFileSync(join(ws, "node_modules", "dep", "package.json"), "{}\n");
		writeFileSync(join(ws, "node_modules", "dep", "index.js"), "");
		const result = check(
			sources({ extensionPaths: [{ path: join(ws, "node_modules", "dep", "index.js"), from: "x" }] }),
		);
		// The package itself is inside node_modules, which is what is reported.
		expect(result.exposed.map((r) => r.path)).toEqual([join(ws, "node_modules")]);
	});

	it("refuses a code root that contains a writable root, even with the opt-in", () => {
		const result = check(sources(), [join(ws, "ext", "src")]);
		expect(result.refused.map((r) => r.root.path)).toEqual([join(ws, "ext")]);
		expect(formatCodeRootProblems(result, true)).toMatch(/run pi from another worktree/);
	});

	it("refuses the workspace itself as the loaded package", () => {
		writeFileSync(join(ws, "package.json"), "{}\n");
		mkdirSync(join(ws, "src"));
		writeFileSync(join(ws, "src", "index.ts"), "");
		const result = check(sources({ extensionPaths: [{ path: join(ws, "src", "index.ts"), from: "x" }] }));
		expect(result.refused.map((r) => r.root.path)).toEqual([ws]);
		expect(formatCodeRootProblems(result, true)).toMatch(/contains the writable root/);
	});

	it("refuses code loaded through a symlink below a writable root, even with the opt-in", () => {
		mkdirSync(join(outside, "linked", "src"), { recursive: true });
		writeFileSync(join(outside, "linked", "package.json"), "{}\n");
		writeFileSync(join(outside, "linked", "src", "index.ts"), "");
		mkdirSync(join(ws, "node_modules"));
		symlinkSync(join(outside, "linked"), join(ws, "node_modules", "linked"));
		const result = check(
			sources({ extensionPaths: [{ path: join(ws, "node_modules", "linked", "src", "index.ts"), from: "x" }] }),
		);
		expect(result.refused.map((r) => r.root.path)).toContain(join(ws, "node_modules", "linked"));
		expect(formatCodeRootProblems(result, true)).toMatch(/load it by its real path/);
	});

	it("refuses a Node binary below a writable root, even with the opt-in", () => {
		mkdirSync(join(ws, ".nvm", "bin"), { recursive: true });
		writeFileSync(join(ws, ".nvm", "bin", "node"), "");
		const result = check(sources({ extensionPaths: [], execPath: join(ws, ".nvm", "bin", "node") }));
		expect(result.refused.map((r) => r.root.from)).toEqual(["the Node binary"]);
		expect(formatCodeRootProblems(result, true)).toMatch(/install Node outside the writable roots/);
	});

	// Review of #69: `["/work/project/tools/notify.sh"]` was accepted, and the
	// agent could rewrite what the trusted process runs on every ask.
	it("refuses an attended.notify program below a writable root, even with the opt-in (#30)", () => {
		mkdirSync(join(ws, "tools"), { recursive: true });
		writeFileSync(join(ws, "tools", "notify.sh"), "#!/bin/sh\n");
		const result = check(sources({ extensionPaths: [], notifyProgram: join(ws, "tools", "notify.sh") }));
		expect(result.refused.map((r) => r.root.from)).toEqual(["the attended.notify program"]);
		expect(formatCodeRootProblems(result, true)).toMatch(
			/install it, and anything it loads, outside the writable roots/,
		);
		const fine = check(sources({ extensionPaths: [], notifyProgram: join(outside, "node", "bin", "node") }));
		expect(fine.refused).toEqual([]);
		expect(fine.exposed).toEqual([]);
	});

	it("resolves pi-enclave's own dependencies, as its imports do", () => {
		const own = join(import.meta.dirname, "..", "..", "src", "index.ts");
		const entries = resolveDependencyEntries(own);
		expect(entries.some((entry) => entry.includes(join("@anthropic-ai", "sandbox-runtime")))).toBe(true);
		expect(entries.some((entry) => entry.includes(join("@earendil-works", "pi-coding-agent")))).toBe(true);
	});

	it("skips synthetic paths and package specs", () => {
		const result = check(
			sources({
				extensionPaths: [
					{ path: "builtin:read", from: "x" },
					{ path: "npm:some-package", from: "x" },
				],
			}),
		);
		expect(result).toEqual({ exposed: [], refused: [], missing: [] });
	});

	it("checks the running Node binary among the native host executables", () => {
		const empty = join(root, "empty-path");
		mkdirSync(empty);
		const result = hostRuntimeSafety([dirname(process.execPath)], empty, "linux");
		expect(result.ok).toBe(false);
		expect(result.detail).toContain(process.execPath);
	});

	it("accepts a seccomp helper the profile write-denies, and only then", () => {
		const helper = join(ws, "ext", "node_modules", "apply-seccomp");
		mkdirSync(join(ws, "ext", "node_modules"));
		writeFileSync(helper, "");
		expect(hostExecutableSafety([ws], [helper]).ok).toBe(false);
		expect(hostExecutableSafety([ws], [helper], [join(ws, "ext")]).ok).toBe(true);
		expect(hostExecutableSafety([ws], [helper], [join(ws, "other")]).ok).toBe(false);
	});
});

describe("session_start with loaded code under cwd (#36)", () => {
	let agentDir: string;
	let previousAgentDir: string | undefined;
	beforeEach(() => {
		agentDir = join(root, "agent");
		previousAgentDir = process.env.PI_CODING_AGENT_DIR;
		process.env.PI_CODING_AGENT_DIR = agentDir;
		mocks.compile.mockReset();
		mocks.compile.mockImplementation(
			async (profile: Profile) => ({ profile, backend: "fake" }) as unknown as CompiledProfile,
		);
	});
	afterEach(() => {
		if (previousAgentDir === undefined) delete process.env.PI_CODING_AGENT_DIR;
		else process.env.PI_CODING_AGENT_DIR = previousAgentDir;
	});

	async function start(
		allowSelfHosting: boolean,
		// pi reports the extension at its configured path, by default under cwd.
		extension = { path: join(ws, "ext", "src", "index.ts"), baseDir: join(ws, "ext", "src") },
		commands: { name: string; source: string; sourceInfo: { path: string; baseDir?: string } }[] = [],
	) {
		const { default: register } = await import("../../src/index.ts");
		const effective: EffectiveProfile = defaultProfile({ cwd: ws, agentDir });
		effective.sandbox.allowSelfHosting = allowSelfHosting;
		effective.attended.mode = "off";
		mocks.loadConfig.mockReturnValue({ ok: true, profile: effective, provenance: new Map(), sources: [] });
		const handlers = new Map<string, (event: unknown, context: ExtensionContext) => unknown>();
		const api = {
			registerTool: () => {},
			registerCommand: () => {},
			registerFlag: () => {},
			registerMessageRenderer: () => {},
			appendEntry: () => {},
			on: (event: string, handler: (event: unknown, context: ExtensionContext) => unknown) => {
				handlers.set(event, handler);
			},
			getAllTools: () => OWNED_TOOLS.map((name) => ({ name, sourceInfo: extension })),
			getCommands: () => [{ name: "enclave", source: "extension", sourceInfo: extension }, ...commands],
		} as unknown as ExtensionAPI;
		register(api);
		const notify = vi.fn();
		const context = {
			cwd: ws,
			mode: "print",
			hasUI: false,
			isProjectTrusted: () => false,
			ui: { notify, setStatus: () => {} },
			sessionManager: {
				getSessionId: () => "s1",
				getSessionFile: () => undefined,
				getEntries: () => [],
				getBranch: () => [],
			},
			modelRegistry: {},
		} as unknown as ExtensionContext;
		await handlers.get("session_start")?.({}, context);
		const toolCall = await handlers.get("tool_call")?.(
			{ toolName: "write", toolCallId: "t1", input: { path: "a.txt", content: "x" } },
			context,
		);
		return { notify, toolCall };
	}

	it("refuses auto mode by default", async () => {
		const stderr = vi.spyOn(process.stderr, "write").mockImplementation(() => true);
		try {
			const { notify, toolCall } = await start(false);
			expect(notify).toHaveBeenCalledWith(expect.stringContaining(join(ws, "ext")), "error");
			expect(mocks.compile).not.toHaveBeenCalled();
			expect(toolCall).toEqual(expect.objectContaining({ block: true, reason: expect.stringMatching(/refusing/) }));
		} finally {
			stderr.mockRestore();
		}
	});

	it("with the opt-in, compiles the code root into writeDeny", async () => {
		const stderr = vi.spyOn(process.stderr, "write").mockImplementation(() => true);
		try {
			const { notify } = await start(true);
			const errors = notify.mock.calls.filter(([, level]) => level === "error");
			expect(errors).toEqual([]);
			expect(mocks.compile).toHaveBeenCalledTimes(1);
			const compiled = mocks.compile.mock.calls[0]?.[0] as Profile;
			expect(compiled.writeDeny).toContain(join(ws, "ext"));
			expect(compiled.selfHosted).toEqual([join(ws, "ext"), join(ws, "node_modules")]);
		} finally {
			stderr.mockRestore();
		}
	});

	// Review of #47: getCommands() also lists prompt templates and skills.
	it("starts in a Node project with a project prompt and skill", async () => {
		writeFileSync(join(ws, "package.json"), "{}\n");
		mkdirSync(join(ws, ".pi", "prompts"), { recursive: true });
		mkdirSync(join(ws, ".agents", "skills", "deploy"), { recursive: true });
		writeFileSync(join(ws, ".pi", "prompts", "review.md"), "review\n");
		writeFileSync(join(ws, ".agents", "skills", "deploy", "SKILL.md"), "deploy\n");
		mkdirSync(join(outside, "ext", "src"), { recursive: true });
		writeFileSync(join(outside, "ext", "package.json"), "{}\n");
		writeFileSync(join(outside, "ext", "src", "index.ts"), "");
		const stderr = vi.spyOn(process.stderr, "write").mockImplementation(() => true);
		try {
			const { notify } = await start(
				false,
				{ path: join(outside, "ext", "src", "index.ts"), baseDir: join(outside, "ext", "src") },
				[
					{
						name: "review",
						source: "prompt",
						sourceInfo: { path: join(ws, ".pi", "prompts", "review.md"), baseDir: join(ws, ".pi", "prompts") },
					},
					{
						name: "skill:deploy",
						source: "skill",
						sourceInfo: {
							path: join(ws, ".agents", "skills", "deploy", "SKILL.md"),
							baseDir: join(ws, ".agents", "skills", "deploy"),
						},
					},
				],
			);
			expect(notify.mock.calls.filter(([, level]) => level === "error")).toEqual([]);
			expect(mocks.compile).toHaveBeenCalledTimes(1);
		} finally {
			stderr.mockRestore();
		}
	});
});
