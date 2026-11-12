/**
 * #29: the execution-boundary check on a pi that offers `pi.wrapToolExecution`
 * (the frycm/pi prototype), driven through the extension's own handlers with a
 * fake pi. Without the API nothing is registered and the batch withholding of
 * third-party tools stays; with it, a third-party call runs inside the lock's
 * invocation check, which compares the complete gated action, asks the breaker
 * again and runs the call once.
 */
import { existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { ExtensionAPI, ExtensionContext, ToolDefinition } from "@earendil-works/pi-coding-agent";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { CompiledProfile, Profile } from "../../src/backend/types.ts";
import { defaultProfile, OWNED_TOOLS } from "../../src/config/defaults.ts";
import type { EffectiveProfile } from "../../src/config/types.ts";
import { BREAKER_ENTRY_TYPE } from "../../src/gate/breaker.ts";
import {
	createExecutionCheck,
	type ExecutionRefusal,
	hasExecutionWrapper,
	type ToolExecutionWrapper,
} from "../../src/gate/execution.ts";
import { ActionLock } from "../../src/gate/lock.ts";

const READY = { ok: true, platform: "linux", backend: "bwrap", piVersion: "1.5.2", checks: [] };
const mocks = vi.hoisted(() => ({ loadConfig: vi.fn(), probe: { report: undefined as unknown } }));

vi.mock("../../src/probe-host.ts", async (original) => ({
	...(await original<typeof import("../../src/probe-host.ts")>()),
	probeHost: () => mocks.probe.report,
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
			run: async () => ({ exitCode: 0, violations: [] }),
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
	mocks.probe.report = READY;
	root = realpathSync(mkdtempSync(join(tmpdir(), "enclave-exec-")));
	ws = join(root, "ws");
	agentDir = join(root, "agent");
	mkdirSync(ws, { recursive: true });
	previousAgentDir = process.env.PI_CODING_AGENT_DIR;
	process.env.PI_CODING_AGENT_DIR = agentDir;
});
afterEach(() => {
	if (previousAgentDir === undefined) delete process.env.PI_CODING_AGENT_DIR;
	else process.env.PI_CODING_AGENT_DIR = previousAgentDir;
	rmSync(root, { recursive: true, force: true });
});

type Handler = (event: unknown, context: ExtensionContext) => unknown;
type Decision = { block?: boolean; reason?: string } | undefined;

const SEARCH = "mcp__docs__search";

async function session(
	options: {
		wrapper?: boolean;
		edit?: (profile: EffectiveProfile) => void;
		entries?: unknown[];
		/** What loadConfig returns instead of the edited default profile. */
		config?: unknown;
		/** Skip session_start, so no policy is loaded. */
		unstarted?: boolean;
		/** Another extension provides `read`, which the ownership check refuses. */
		foreignRead?: boolean;
		/** What the host probe reports at extension load. */
		probe?: unknown;
	} = {},
) {
	vi.resetModules();
	if (options.probe) mocks.probe.report = options.probe;
	const { default: register } = await import("../../src/index.ts");
	const effective = defaultProfile({ cwd: ws, agentDir });
	effective.attended.mode = "off";
	effective.tools.allow[SEARCH] = { readOnly: true };
	options.edit?.(effective);
	mocks.loadConfig.mockReturnValue(
		options.config ?? { ok: true, profile: effective, provenance: new Map(), sources: [] },
	);
	const handlers = new Map<string, Handler>();
	const commands = new Map<string, { handler: (args: string, ctx: ExtensionContext) => Promise<void> }>();
	const extension = { path: join(root, "ext", "index.ts"), baseDir: join(root, "ext") };
	const registry = () => [
		...OWNED_TOOLS.map((name) => ({
			name,
			sourceInfo: options.foreignRead && name === "read" ? { path: join(root, "other", "index.ts") } : extension,
		})),
		{ name: SEARCH, sourceInfo: { path: "<mcp:docs>" } },
	];
	const wrappers: ToolExecutionWrapper[] = [];
	const tools = new Map<string, ToolDefinition>();
	const api = {
		registerTool: (tool: ToolDefinition) => tools.set(tool.name, tool),
		registerCommand: (name: string, command: { handler: (args: string, ctx: ExtensionContext) => Promise<void> }) =>
			commands.set(name, command),
		registerFlag: () => {},
		registerMessageRenderer: () => {},
		appendEntry: () => {},
		sendUserMessage: () => {},
		on: (event: string, handler: Handler) => handlers.set(event, handler),
		getAllTools: () => registry(),
		getActiveTools: () => registry().map((tool) => tool.name),
		setActiveTools: () => {},
		getCommands: () => [{ name: "enclave", source: "extension", sourceInfo: extension }],
		...(options.wrapper
			? {
					wrapToolExecution: (wrapper: ToolExecutionWrapper) => {
						wrappers.push(wrapper);
						return () => {};
					},
				}
			: {}),
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
	if (!options.unstarted) {
		await handlers.get("session_start")?.({ reason: "startup" }, context);
		await handlers.get("turn_start")?.({ turnIndex: 0 }, context);
	}
	const auditPath = join(agentDir, "enclave", "audit", "s1.jsonl");
	return {
		wrappers,
		notes,
		gate: async (id: string, toolName: string, input: Record<string, unknown>) =>
			(await handlers.get("tool_call")?.({ toolName, toolCallId: id, input }, context)) as Decision,
		/** Run one execution through the registered wrapper, the way the prototype does. */
		execute: (
			id: string,
			toolName: string,
			input: Record<string, unknown>,
			options: { parent?: string; run?: (input: Record<string, unknown>) => Promise<unknown> } = {},
		) => {
			const frozen = structuredClone(input);
			const next = vi.fn(
				options.run
					? () => (options.run as (input: Record<string, unknown>) => Promise<unknown>)(frozen)
					: async () => ({ content: [{ type: "text", text: "ran" }], details: {} }),
			);
			const wrapper = wrappers[0];
			if (!wrapper) throw new Error("no wrapper registered");
			const call = {
				toolName,
				toolCallId: id,
				...(options.parent !== undefined ? { parentToolCallId: options.parent } : {}),
				input: frozen,
			};
			const result = wrapper(call, next, { cwd: ws });
			return { result, next };
		},
		/** The registered tool's own execute, which binds its invocation itself. */
		ownTool: (id: string, toolName: string) => (input: Record<string, unknown>) => {
			const tool = tools.get(toolName);
			if (!tool) throw new Error(`${toolName} is not registered`);
			return tool.execute(id, input as never, undefined, undefined, context as never);
		},
		/** What pi does once a call is over, whether it ran or was refused. */
		end: async (id: string, toolName: string, isError: boolean) => {
			await handlers.get("tool_result")?.({ toolCallId: id }, context);
			await handlers.get("tool_execution_end")?.({ toolCallId: id, toolName, isError, durationMs: 1 }, context);
		},
		auditPath,
		records: () =>
			existsSync(auditPath)
				? readFileSync(auditPath, "utf8")
						.trim()
						.split("\n")
						.map((line) => JSON.parse(line) as Record<string, unknown>)
				: [],
		status: async () => {
			notes.length = 0;
			await commands.get("enclave")?.handler("status", context);
			return notes.join("\n");
		},
		shutdown: () => handlers.get("session_shutdown")?.({}, context),
	};
}

const quiet = () => vi.spyOn(process.stderr, "write").mockImplementation(() => true);

/** One adverse outcome away from opening the breaker. */
const nearlyOpen = [{ type: "custom", customType: BREAKER_ENTRY_TYPE, data: { consecutive: 2, recent: [true, true] } }];

describe("the execution-boundary check (#29)", () => {
	it("is found by a feature probe, not by version", () => {
		expect(hasExecutionWrapper({})).toBe(false);
		expect(hasExecutionWrapper({ wrapToolExecution: "yes" })).toBe(false);
		expect(hasExecutionWrapper({ wrapToolExecution: () => () => {} })).toBe(true);
	});

	it("tells the session about a refusal before any check of the lock, as unavailable", async () => {
		const refused: ExecutionRefusal[] = [];
		const check = createExecutionCheck({
			lock: new ActionLock(),
			owned: OWNED_TOOLS,
			refusal: () => "fixture: nothing may run",
			passThrough: () => false,
			onRefused: (refusal) => refused.push(refusal),
		});
		const next = vi.fn(async () => ({}));
		await expect(
			check({ toolName: "bash", toolCallId: "c1", parentToolCallId: "p1", input: {} }, next, { cwd: "/" }),
		).rejects.toThrow("fixture: nothing may run");
		expect(next).not.toHaveBeenCalled();
		expect(refused).toEqual([
			{
				toolName: "bash",
				toolCallId: "c1",
				parentToolCallId: "p1",
				kind: "unavailable",
				reason: "fixture: nothing may run",
			},
		]);
	});

	it("registers nothing on upstream pi, where a third-party sibling is still withheld", async () => {
		const stderr = quiet();
		try {
			const s = await session({ entries: nearlyOpen });
			expect(s.wrappers).toHaveLength(0);
			expect((await s.gate("b1", "bash", { command: "ls" }))?.block).toBeFalsy();
			const sibling = await s.gate("m1", SEARCH, { query: "x" });
			expect(sibling?.block).toBe(true);
			expect(sibling?.reason).toMatch(/withheld/);
			expect(await s.status()).toContain("checked when admitted only");
			await s.shutdown();
		} finally {
			stderr.mockRestore();
		}
	});

	it("admits the sibling when the call is re-checked at execution", async () => {
		const stderr = quiet();
		try {
			const s = await session({ wrapper: true, entries: nearlyOpen });
			expect(s.wrappers).toHaveLength(1);
			expect((await s.gate("b1", "bash", { command: "ls" }))?.block).toBeFalsy();
			expect((await s.gate("m1", SEARCH, { query: "x" }))?.block).toBeFalsy();
			const { result, next } = s.execute("m1", SEARCH, { query: "x" });
			await expect(result).resolves.toMatchObject({ content: [{ text: "ran" }] });
			expect(next).toHaveBeenCalledOnce();
			expect(await s.status()).toContain("every tool is re-checked when it runs");
			await s.shutdown();
		} finally {
			stderr.mockRestore();
		}
	});

	it("refuses a third-party call when the breaker opened after it was admitted", async () => {
		const stderr = quiet();
		try {
			const s = await session({ wrapper: true, entries: nearlyOpen });
			expect((await s.gate("m1", SEARCH, { query: "x" }))?.block).toBeFalsy();
			// A later call in the same batch is denied, and that is the strike that opens it.
			expect((await s.gate("m2", "mcp__other__send", { to: "x" }))?.block).toBe(true);
			const { result, next } = s.execute("m1", SEARCH, { query: "x" });
			await expect(result).rejects.toThrow(/circuit breaker/);
			expect(next).not.toHaveBeenCalled();
			await s.shutdown();
		} finally {
			stderr.mockRestore();
		}
	});

	it("refuses arguments other than the gated ones, a call nobody gated, and a second run", async () => {
		const stderr = quiet();
		try {
			const s = await session({ wrapper: true });
			expect((await s.gate("m1", SEARCH, { query: "x" }))?.block).toBeFalsy();
			const changed = s.execute("m1", SEARCH, { query: "y" });
			await expect(changed.result).rejects.toThrow(/differs from the complete gated action/);
			expect(changed.next).not.toHaveBeenCalled();

			const ungated = s.execute("m9", SEARCH, { query: "x" });
			await expect(ungated.result).rejects.toThrow(/did not pass the policy gate/);
			expect(ungated.next).not.toHaveBeenCalled();

			expect((await s.gate("m2", SEARCH, { query: "z" }))?.block).toBeFalsy();
			await expect(s.execute("m2", SEARCH, { query: "z" }).result).resolves.toBeDefined();
			const again = s.execute("m2", SEARCH, { query: "z" });
			await expect(again.result).rejects.toThrow(/already started|finished/);
			expect(again.next).not.toHaveBeenCalled();
			await s.shutdown();
		} finally {
			stderr.mockRestore();
		}
	});

	it("leaves an owned tool's invocation for the tool itself to bind", async () => {
		const stderr = quiet();
		try {
			const s = await session({ wrapper: true });
			expect((await s.gate("b1", "bash", { command: "ls" }))?.block).toBeFalsy();
			// `next` is the real tool, which binds its own invocation: had the
			// wrapper bound it first, the tool would refuse it as already started.
			const { result, next } = s.execute("b1", "bash", { command: "ls" }, { run: s.ownTool("b1", "bash") });
			await expect(result).resolves.toBeDefined();
			expect(next).toHaveBeenCalledOnce();
			await s.shutdown();
		} finally {
			stderr.mockRestore();
		}
	});

	it("records a call stopped at execution as refused, with the check that stopped it, and not as executed", async () => {
		const stderr = quiet();
		try {
			const s = await session({ wrapper: true, entries: nearlyOpen });
			const gated = await s.gate("m1", SEARCH, { query: "x" });
			expect(gated?.block).toBeFalsy();
			expect((await s.gate("m2", "mcp__other__send", { to: "x" }))?.block).toBe(true);
			await expect(s.execute("m1", SEARCH, { query: "x" }).result).rejects.toThrow(/circuit breaker/);
			await s.end("m1", SEARCH, true);

			const nested = s.execute("n1", SEARCH, { query: "x" }, { parent: "p1" });
			await expect(nested.result).rejects.toThrow(/did not pass the policy gate/);
			await s.end("n1", SEARCH, true);
			await s.shutdown();

			const records = s.records();
			const allowed = records.find((record) => record.kind === "decision" && record.tool === SEARCH);
			expect(allowed).toMatchObject({ outcome: "allow" });
			const refused = records.filter((record) => record.kind === "execution_refused");
			expect(refused).toEqual([
				expect.objectContaining({
					toolCallId: "m1",
					tool: SEARCH,
					hash: allowed?.hash,
					refusal: "breaker-open",
					reason: expect.stringMatching(/circuit breaker/),
				}),
				expect.objectContaining({ toolCallId: "n1", parentToolCallId: "p1", refusal: "not-locked" }),
			]);
			expect(refused[1]).not.toHaveProperty("hash");
			expect(records.filter((record) => record.kind === "executed")).toEqual([]);
		} finally {
			stderr.mockRestore();
		}
	});

	it("records only the refusal when a tool ran and failed, not the other way round", async () => {
		const stderr = quiet();
		try {
			const s = await session({ wrapper: true });
			expect((await s.gate("m1", SEARCH, { query: "x" }))?.block).toBeFalsy();
			const failing = s.execute(
				"m1",
				SEARCH,
				{ query: "x" },
				{ run: async () => Promise.reject(new Error("tool failed")) },
			);
			await expect(failing.result).rejects.toThrow("tool failed");
			await s.end("m1", SEARCH, true);
			await s.shutdown();
			const records = s.records();
			expect(records.filter((record) => record.kind === "execution_refused")).toEqual([]);
			expect(records.filter((record) => record.kind === "executed")).toEqual([
				expect.objectContaining({ toolCallId: "m1", isError: true }),
			]);
		} finally {
			stderr.mockRestore();
		}
	});

	const BROKEN_PROBE = {
		ok: false,
		platform: "linux",
		backend: "bwrap",
		piVersion: "1.5.2",
		checks: [{ id: "fixture", title: "fixture check", status: "fail", detail: "fixture: probe failed" }],
	};
	const reasons: {
		reason: string;
		options: Parameters<typeof session>[0];
		before?: (s: Awaited<ReturnType<typeof session>>) => Promise<void>;
		message: RegExp;
	}[] = [
		{
			reason: "the configuration did not load",
			options: { config: { ok: false, message: "fixture: bad configuration", sources: [] } },
			message: /fixture: bad configuration/,
		},
		{
			reason: "the host probe failed",
			options: { unstarted: true, probe: BROKEN_PROBE },
			message: /fixture: probe failed/,
		},
		{ reason: "another extension owns a tool", options: { foreignRead: true }, message: /"read" is provided by/ },
		{ reason: "no policy is loaded", options: { unstarted: true }, message: /no policy is loaded/ },
		{
			reason: "the required audit log stopped",
			options: {
				edit: (profile) => {
					profile.audit.required = true;
				},
			},
			before: async (s) => {
				rmSync(s.auditPath);
				mkdirSync(s.auditPath);
				await s.gate("b0", "bash", { command: "ls" });
			},
			message: /audit\.required/,
		},
	];

	it.each(reasons)("refuses every tool, owned or not, when $reason", async ({ options, before, message }) => {
		const stderr = quiet();
		try {
			const s = await session({ wrapper: true, ...options });
			await before?.(s);
			for (const [id, tool, input] of [
				["b1", "bash", { command: "ls" }],
				["m1", SEARCH, { query: "x" }],
			] as const) {
				const { result, next } = s.execute(id, tool, input);
				await expect(result).rejects.toThrow(message);
				expect(next).not.toHaveBeenCalled();
			}
			await s.shutdown();
		} finally {
			stderr.mockRestore();
		}
	});

	it("passes through with auto off", async () => {
		const stderr = quiet();
		try {
			const off = await session({
				wrapper: true,
				edit: (profile) => {
					profile.auto = false;
				},
			});
			const passed = off.execute("m9", SEARCH, { query: "x" });
			await expect(passed.result).resolves.toBeDefined();
			expect(passed.next).toHaveBeenCalledOnce();
			await off.shutdown();
		} finally {
			stderr.mockRestore();
		}
	});
});
