/**
 * #29: the execution-boundary check on a pi that offers `pi.wrapToolExecution`
 * (the frycm/pi prototype), driven through the extension's own handlers with a
 * fake pi. Without the API nothing is registered and the batch withholding of
 * third-party tools stays; with it, a third-party call runs inside the lock's
 * invocation check, which compares the complete gated action, asks the breaker
 * again and runs the call once.
 */
import { mkdirSync, mkdtempSync, realpathSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { ExtensionAPI, ExtensionContext } from "@earendil-works/pi-coding-agent";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { CompiledProfile, Profile } from "../../src/backend/types.ts";
import { defaultProfile, OWNED_TOOLS } from "../../src/config/defaults.ts";
import type { EffectiveProfile } from "../../src/config/types.ts";
import { BREAKER_ENTRY_TYPE } from "../../src/gate/breaker.ts";
import { hasExecutionWrapper, type ToolExecutionWrapper } from "../../src/gate/execution.ts";

const mocks = vi.hoisted(() => ({ loadConfig: vi.fn() }));

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
	} = {},
) {
	vi.resetModules();
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
		...OWNED_TOOLS.map((name) => ({ name, sourceInfo: extension })),
		{ name: SEARCH, sourceInfo: { path: "<mcp:docs>" } },
	];
	const wrappers: ToolExecutionWrapper[] = [];
	const api = {
		registerTool: () => {},
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
	await handlers.get("session_start")?.({ reason: "startup" }, context);
	await handlers.get("turn_start")?.({ turnIndex: 0 }, context);
	return {
		wrappers,
		notes,
		gate: async (id: string, toolName: string, input: Record<string, unknown>) =>
			(await handlers.get("tool_call")?.({ toolName, toolCallId: id, input }, context)) as Decision,
		/** Run one execution through the registered wrapper, the way the prototype does. */
		execute: (id: string, toolName: string, input: Record<string, unknown>) => {
			const next = vi.fn(async () => ({ content: [{ type: "text", text: "ran" }], details: {} }));
			const wrapper = wrappers[0];
			if (!wrapper) throw new Error("no wrapper registered");
			const result = wrapper({ toolName, toolCallId: id, input: structuredClone(input) }, next, { cwd: ws });
			return { result, next };
		},
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
			const { result, next } = s.execute("b1", "bash", { command: "ls" });
			await expect(result).resolves.toBeDefined();
			expect(next).toHaveBeenCalledOnce();
			await s.shutdown();
		} finally {
			stderr.mockRestore();
		}
	});

	it("refuses everything when the configuration did not load, and passes through with auto off", async () => {
		const stderr = quiet();
		try {
			const broken = await session({
				wrapper: true,
				config: { ok: false, message: "fixture: bad configuration", sources: [] },
			});
			const refused = broken.execute("b1", "bash", { command: "ls" });
			await expect(refused.result).rejects.toThrow(/fixture: bad configuration/);
			expect(refused.next).not.toHaveBeenCalled();
			await broken.shutdown();

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
