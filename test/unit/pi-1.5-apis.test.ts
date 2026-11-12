/**
 * The pi 1.5 APIs pi-enclave takes part in (#28), driven through the
 * extension's own handlers with a fake pi: the active tool set, the
 * project-trust question, declared tool hints, the turn-end lock sweep and
 * every session_start reason.
 */
import { mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { ExtensionAPI, ExtensionContext } from "@earendil-works/pi-coding-agent";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { CompiledProfile, Profile, RunRequest } from "../../src/backend/types.ts";
import { defaultProfile, OWNED_TOOLS } from "../../src/config/defaults.ts";
import type { EffectiveProfile } from "../../src/config/types.ts";
import { BREAKER_ENTRY_TYPE } from "../../src/gate/breaker.ts";
import { narrowByDeclaredHints } from "../../src/gate/gate.ts";
import { answerProjectTrust, trustRequiringResources } from "../../src/gate/project-trust.ts";
import { checkTool, grantWarnings } from "../../src/gate/tools.ts";

const mocks = vi.hoisted(() => ({
	loadConfig: vi.fn(),
	runs: [] as RunRequest[],
}));

vi.mock("../../src/probe-host.ts", async (original) => ({
	...(await original<typeof import("../../src/probe-host.ts")>()),
	probeHost: () => ({ ok: true, platform: "linux", backend: "bwrap", piVersion: "1.5.2", checks: [] }),
}));
vi.mock("../../src/config/sources.ts", async (original) => ({
	...(await original<typeof import("../../src/config/sources.ts")>()),
	loadConfig: mocks.loadConfig,
}));
vi.mock("../../src/backend/select.ts", () => ({
	selectBackend: async () => ({
		backend: {
			name: "fake",
			compile: async (profile: Profile) =>
				({ profile, backend: "fake", describe: () => "" }) as unknown as CompiledProfile,
			run: async (_compiled: CompiledProfile, request: RunRequest) => {
				mocks.runs.push(request);
				return { exitCode: 0, violations: [] };
			},
			fs: () => ({}),
			dispose: async () => {},
		},
		report: { ok: true, platform: "linux", backend: "bwrap", piVersion: "1.5.2", checks: [] },
	}),
}));
vi.mock("../../src/gate/code-roots.ts", async (original) => ({
	...(await original<typeof import("../../src/gate/code-roots.ts")>()),
	checkCodeRoots: () => ({ exposed: [], refused: [] }),
}));

let root: string;
let ws: string;
let agentDir: string;
let previousAgentDir: string | undefined;

beforeEach(() => {
	root = realpathSync(mkdtempSync(join(tmpdir(), "enclave-pi15-")));
	ws = join(root, "ws");
	agentDir = join(root, "agent");
	mkdirSync(ws, { recursive: true });
	previousAgentDir = process.env.PI_CODING_AGENT_DIR;
	process.env.PI_CODING_AGENT_DIR = agentDir;
	mocks.runs.length = 0;
});
afterEach(() => {
	if (previousAgentDir === undefined) delete process.env.PI_CODING_AGENT_DIR;
	else process.env.PI_CODING_AGENT_DIR = previousAgentDir;
	rmSync(root, { recursive: true, force: true });
});

type Handler = (event: unknown, context: ExtensionContext) => unknown;
interface Tool {
	name: string;
	execute: (
		id: string,
		params: unknown,
		signal: undefined,
		onUpdate: undefined,
		ctx: ExtensionContext,
	) => Promise<unknown>;
}
interface FakeTool {
	name: string;
	sourceInfo: { path: string; baseDir?: string };
	annotations?: Record<string, boolean>;
}

async function session(
	options: {
		edit?: (profile: EffectiveProfile) => void;
		others?: FakeTool[];
		entries?: unknown[];
		startSession?: boolean;
	} = {},
) {
	vi.resetModules();
	const { default: register } = await import("../../src/index.ts");
	const effective = defaultProfile({ cwd: ws, agentDir });
	effective.attended.mode = "off";
	options.edit?.(effective);
	mocks.loadConfig.mockReturnValue({ ok: true, profile: effective, provenance: new Map(), sources: [] });
	const handlers = new Map<string, Handler>();
	const tools = new Map<string, Tool>();
	const extension = { path: join(root, "ext", "index.ts"), baseDir: join(root, "ext") };
	const others: FakeTool[] = [...(options.others ?? [])];
	const registry = (): FakeTool[] => [...OWNED_TOOLS.map((name) => ({ name, sourceInfo: extension })), ...others];
	let active = registry().map((tool) => tool.name);
	const setActiveTools = vi.fn((names: string[]) => {
		active = names.filter((name) => registry().some((tool) => tool.name === name));
	});
	const api = {
		registerTool: (tool: Tool) => tools.set(tool.name, tool),
		registerCommand: () => {},
		registerFlag: () => {},
		registerMessageRenderer: () => {},
		appendEntry: () => {},
		sendUserMessage: () => {},
		on: (event: string, handler: Handler) => handlers.set(event, handler),
		getAllTools: () => registry(),
		getActiveTools: () => [...active],
		setActiveTools,
		getCommands: () => [{ name: "enclave", source: "extension", sourceInfo: extension }],
	} as unknown as ExtensionAPI;
	register(api);
	const notes: string[] = [];
	const context = {
		cwd: ws,
		mode: "print",
		hasUI: false,
		abort: () => {},
		isProjectTrusted: () => false,
		ui: { notify: (message: string) => notes.push(message), setStatus: () => {} },
		sessionManager: {
			getSessionId: () => "s1",
			getSessionFile: () => undefined,
			getEntries: () => options.entries ?? [],
			getBranch: () => [],
		},
		modelRegistry: {},
	} as unknown as ExtensionContext;
	const start = async (reason = "startup") => handlers.get("session_start")?.({ reason }, context);
	if (options.startSession !== false) await start();
	const gate = async (id: string, toolName: string, input: Record<string, unknown>) =>
		(await handlers.get("tool_call")?.({ toolName, toolCallId: id, input }, context)) as
			| { block?: boolean; reason?: string }
			| undefined;
	return {
		handlers,
		context,
		tools,
		others,
		notes,
		start,
		gate,
		active: () => active,
		setActiveTools,
		shutdown: () => handlers.get("session_shutdown")?.({}, context),
	};
}

const quiet = () => vi.spyOn(process.stderr, "write").mockImplementation(() => true);

describe("the tools declared to the model (#28)", () => {
	it("declares only allowlisted tools, with an MCP server's tools present", async () => {
		const stderr = quiet();
		try {
			const s = await session({
				others: [
					{ name: "codemode", sourceInfo: { path: "<builtin:codemode>" } },
					{ name: "mcp__docs__search", sourceInfo: { path: "<mcp:docs>" } },
					{ name: "journal_search", sourceInfo: { path: "/ext/muninn/index.ts" } },
				],
				edit: (profile) => {
					profile.tools.allow.journal_search = { readOnly: true, source: "/ext/muninn/index.ts" };
				},
			});
			expect(s.active().sort()).toEqual([...OWNED_TOOLS, "journal_search"].sort());
			// A server that connects later brings tools that are hidden before the next prompt.
			s.others.push({ name: "mcp__jira__create", sourceInfo: { path: "<mcp:jira>" } });
			s.active().push("mcp__jira__create");
			await s.handlers.get("before_agent_start")?.({ prompt: "next", messageType: "user" }, s.context);
			expect(s.active()).not.toContain("mcp__jira__create");
			// pi-enclave does not claim to be the extension that connects MCP servers.
			expect(s.handlers.has("mcp_servers_change")).toBe(false);
			// The gate still refuses them: hiding is not the enforcement.
			expect((await s.gate("t1", "mcp__docs__search", {}))?.block).toBe(true);
			await s.shutdown();
		} finally {
			stderr.mockRestore();
		}
	});

	it("does not offer a grant pinned to another source", async () => {
		const stderr = quiet();
		try {
			const s = await session({
				others: [{ name: "deploy", sourceInfo: { path: "/ext/impostor.ts" } }],
				edit: (profile) => {
					profile.tools.allow.deploy = { reviewed: true, source: "/ext/real.ts" };
				},
			});
			expect(s.active()).not.toContain("deploy");
			await s.shutdown();
		} finally {
			stderr.mockRestore();
		}
	});

	it("puts a hidden tool back when a reload allows it, and leaves everything alone with auto off", async () => {
		const stderr = quiet();
		try {
			const s = await session({ others: [{ name: "mcp__docs__search", sourceInfo: { path: "<mcp:docs>" } }] });
			expect(s.active()).not.toContain("mcp__docs__search");
			const wider = defaultProfile({ cwd: ws, agentDir });
			wider.attended.mode = "off";
			wider.tools.allow.mcp__docs__search = { reviewed: true };
			mocks.loadConfig.mockReturnValue({ ok: true, profile: wider, provenance: new Map(), sources: [] });
			await s.start("reload");
			expect(s.active()).toContain("mcp__docs__search");
			const off = defaultProfile({ cwd: ws, agentDir });
			off.auto = false;
			mocks.loadConfig.mockReturnValue({ ok: true, profile: off, provenance: new Map(), sources: [] });
			s.others.push({ name: "codemode", sourceInfo: { path: "<builtin:codemode>" } });
			s.active().push("codemode");
			await s.start("reload");
			expect(s.active()).toContain("codemode");
			await s.shutdown();
		} finally {
			stderr.mockRestore();
		}
	});
});

describe("the project-trust question (#28)", () => {
	const ok = (edit: (profile: EffectiveProfile) => void = () => {}) => {
		const profile = defaultProfile({ cwd: "/work", home: "/home/u", agentDir: "/home/u/.pi/agent" });
		edit(profile);
		return { ok: true as const, profile, provenance: new Map(), sources: [] };
	};

	it("says no to a headless run in a directory with project extensions, and names them", () => {
		const project = join(root, "proj");
		mkdirSync(join(project, ".pi", "extensions"), { recursive: true });
		writeFileSync(join(project, ".pi", "settings.json"), "{}");
		for (const mode of ["print", "json", "rpc"] as const) {
			const answer = answerProjectTrust({ cwd: project, mode, hasUI: mode === "rpc", config: ok(), home: root });
			expect(answer.trusted).toBe("no");
			expect(answer.message).toContain(join(project, ".pi", "extensions"));
			expect(answer.message).toContain("attended.headlessTrust");
		}
	});

	it("leaves a listed project to pi, and the TUI to the person with a warning", () => {
		const project = join(root, "proj");
		mkdirSync(join(project, ".pi", "extensions"), { recursive: true });
		const listed = ok((profile) => {
			profile.attended.headlessTrust = [project];
		});
		expect(answerProjectTrust({ cwd: project, mode: "print", hasUI: false, config: listed }).trusted).toBe("undecided");
		const tui = answerProjectTrust({ cwd: project, mode: "tui", hasUI: true, config: ok(), home: root });
		expect(tui.trusted).toBe("undecided");
		expect(tui.message).toContain("outside the sandbox");
	});

	it("fails closed headless when the configuration does not load, and steps aside with auto off", () => {
		const broken = { ok: false as const, message: "bad", sources: [] };
		expect(answerProjectTrust({ cwd: root, mode: "print", hasUI: false, config: broken }).trusted).toBe("no");
		expect(
			answerProjectTrust({
				cwd: root,
				mode: "print",
				hasUI: false,
				config: ok((profile) => {
					profile.auto = false;
				}),
			}).trusted,
		).toBe("undecided");
	});

	it("finds .agents/skills above the project but not the user's own", () => {
		const project = join(root, "a", "b");
		mkdirSync(join(root, "a", ".agents", "skills"), { recursive: true });
		mkdirSync(join(root, ".agents", "skills"), { recursive: true });
		mkdirSync(project, { recursive: true });
		expect(trustRequiringResources(project, root)).toEqual([join(root, "a", ".agents", "skills")]);
	});

	it("is answered by the extension's own handler", async () => {
		const stderr = quiet();
		try {
			const s = await session();
			mkdirSync(join(ws, ".pi", "extensions"), { recursive: true });
			const answer = await s.handlers.get("project_trust")?.({ type: "project_trust", cwd: ws }, {
				cwd: ws,
				mode: "print",
				hasUI: false,
				ui: { notify: () => {} },
			} as unknown as ExtensionContext);
			expect(answer).toEqual({ trusted: "no" });
			expect(stderr).toHaveBeenCalledWith(expect.stringContaining("not loading project resources"));
			expect(stderr).toHaveBeenCalledWith(expect.stringContaining("own project files"));
			await s.shutdown();
		} finally {
			stderr.mockRestore();
		}
	});

	// pi's startup context (cli/project-trust.ts): notify prints nothing in
	// interactive mode, which is when the first trust prompt is shown.
	const startupContext = (cwd: string) =>
		({
			cwd,
			mode: "tui",
			hasUI: true,
			ui: {
				notify: (_message: string) => {
					/* interactive startup: dropped */
				},
				select: async () => undefined,
				confirm: async () => false,
				input: async () => undefined,
			},
		}) as unknown as ExtensionContext;

	it("shows the TUI warning on stderr before the first session, and through notify after (review of #56)", async () => {
		const stderr = quiet();
		try {
			const s = await session({ startSession: false });
			mkdirSync(join(ws, ".pi", "extensions"), { recursive: true });
			const answer = await s.handlers.get("project_trust")?.({ type: "project_trust", cwd: ws }, startupContext(ws));
			expect(answer).toEqual({ trusted: "undecided" });
			expect(stderr).toHaveBeenCalledWith(expect.stringContaining(join(ws, ".pi", "extensions")));
			stderr.mockClear();
			await s.start();
			const notified: string[] = [];
			const later = {
				...startupContext(ws),
				ui: { notify: (message: string) => notified.push(message) },
			} as unknown as ExtensionContext;
			await s.handlers.get("project_trust")?.({ type: "project_trust", cwd: ws }, later);
			expect(notified.join()).toContain(join(ws, ".pi", "extensions"));
			expect(stderr).not.toHaveBeenCalled();
			await s.shutdown();
		} finally {
			stderr.mockRestore();
		}
	});

	it("answers no in a headless run when deciding throws, instead of falling back to pi's trust store", async () => {
		const stderr = quiet();
		try {
			const s = await session();
			mocks.loadConfig.mockImplementationOnce(() => {
				throw new Error("boom");
			});
			const headless = {
				cwd: ws,
				mode: "print",
				hasUI: false,
				ui: { notify: () => {} },
			} as unknown as ExtensionContext;
			expect(await s.handlers.get("project_trust")?.({ type: "project_trust", cwd: ws }, headless)).toEqual({
				trusted: "no",
			});
			expect(stderr).toHaveBeenCalledWith(expect.stringContaining("boom"));
			mocks.loadConfig.mockImplementationOnce(() => {
				throw new Error("boom");
			});
			expect(await s.handlers.get("project_trust")?.({ type: "project_trust", cwd: ws }, startupContext(ws))).toEqual({
				trusted: "undecided",
			});
			await s.shutdown();
		} finally {
			stderr.mockRestore();
		}
	});
});

describe("declared tool hints (#28)", () => {
	const tools = defaultProfile({ cwd: "/work", home: "/home/u", agentDir: "/home/u/.pi/agent" }).tools;
	tools.allow.web_fetch = { readOnly: true, source: "/ext/web.ts" };

	it("reviews a readOnly grant on an open-world tool while the network is off, and never widens", () => {
		const base = checkTool({ tool: "web_fetch", tools, owned: OWNED_TOOLS, source: "/ext/web.ts" });
		expect(base).toMatchObject({ allowed: true, reviewed: false });
		expect(narrowByDeclaredHints(base, "web_fetch", OWNED_TOOLS, "off", { openWorldHint: true })).toMatchObject({
			reviewed: true,
		});
		expect(narrowByDeclaredHints(base, "web_fetch", OWNED_TOOLS, "proxy", { openWorldHint: true })).toMatchObject({
			reviewed: false,
		});
		// A hint that claims safety changes nothing.
		const reviewed = { ...base, reviewed: true } as typeof base;
		expect(narrowByDeclaredHints(reviewed, "web_fetch", OWNED_TOOLS, "off", { readOnlyHint: true })).toEqual(reviewed);
	});

	it("warns at startup when a grant contradicts the tool's annotations", () => {
		const warnings = grantWarnings(
			tools,
			[
				{
					name: "web_fetch",
					annotations: { openWorldHint: true, readOnlyHint: false },
					sourceInfo: { path: "/ext/web.ts" },
				},
			],
			OWNED_TOOLS,
			"off",
		);
		expect(warnings.join("\n")).toContain("openWorldHint: true");
		expect(warnings.join("\n")).toContain("readOnlyHint: false");
	});
});

describe("session lifecycle (#28)", () => {
	it("sweeps a lock entry a later handler blocked, at turn end", async () => {
		const stderr = quiet();
		try {
			const s = await session();
			await s.handlers.get("turn_start")?.({ turnIndex: 1 }, s.context);
			expect((await s.gate("t1", "bash", { command: "ls" }))?.block).toBeFalsy();
			// A later extension blocked t1, so pi never ran it and sent no tool_result.
			await s.handlers.get("turn_end")?.({ turnIndex: 1 }, s.context);
			await expect(
				s.tools.get("bash")?.execute("t1", { command: "ls" }, undefined, undefined, s.context),
			).rejects.toThrow(/policy gate|not.*locked|did not pass/);
			expect(mocks.runs).toHaveLength(0);
			await s.shutdown();
		} finally {
			stderr.mockRestore();
		}
	});

	it.each(["startup", "reload", "new", "resume", "fork"])(
		"on %s, restores the breaker and starts with an empty lock table",
		async (reason) => {
			const stderr = quiet();
			try {
				const s = await session();
				expect((await s.gate("t1", "bash", { command: "ls" }))?.block).toBeFalsy();
				const tripped = defaultProfile({ cwd: ws, agentDir });
				tripped.attended.mode = "off";
				mocks.loadConfig.mockReturnValue({ ok: true, profile: tripped, provenance: new Map(), sources: [] });
				const entries = [
					{ type: "custom", customType: BREAKER_ENTRY_TYPE, data: { consecutive: 3, recent: [true, true, true] } },
				];
				(s.context.sessionManager as unknown as { getEntries: () => unknown[] }).getEntries = () => entries;
				await s.start(reason);
				// The call allowed before the session start cannot run after it.
				await expect(
					s.tools.get("bash")?.execute("t1", { command: "ls" }, undefined, undefined, s.context),
				).rejects.toThrow();
				// The persisted open breaker is in force.
				const after = await s.gate("t2", "bash", { command: "ls" });
				expect(after?.block).toBe(true);
				expect(after?.reason).toMatch(/breaker/i);
				expect(mocks.runs).toHaveLength(0);
				await s.shutdown();
			} finally {
				stderr.mockRestore();
			}
		},
	);
});
