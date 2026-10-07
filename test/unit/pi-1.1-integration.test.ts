import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fauxAssistantMessage, InMemoryCredentialStore } from "@earendil-works/pi-ai";
import {
	createAgentSession,
	createWriteTool,
	DefaultResourceLoader,
	type ExtensionFactory,
	ModelRuntime,
	SessionManager,
	SettingsManager,
} from "@earendil-works/pi-coding-agent";
import { describe, expect, it, vi } from "vitest";
import type { FsClient } from "../../src/backend/types.ts";
import { defaultProfile, OWNED_TOOLS } from "../../src/config/defaults.ts";
import { fold } from "../../src/config/merge.ts";
import { decide } from "../../src/gate/gate.ts";
import { ActionLock } from "../../src/gate/lock.ts";
import { createWriteOperations } from "../../src/tools/file-ops.ts";
import { bindOwnedTool } from "../../src/tools/locked.ts";

describe("pi 1.1 credential boundary", () => {
	const options = { cwd: "/work", home: "/home/u", agentDir: "/custom/agent" };
	const protectedPaths = [
		"/custom/agent/mcp-auth.json",
		"/custom/agent/mcp.json",
		"/home/u/.pi/agent/mcp-auth.json",
		"/home/u/.pi/agent/mcp.json",
		"/work/.pi/mcp.json",
	];
	it("denies MCP tokens and literal server secrets at live, default and project paths", () => {
		expect(defaultProfile(options).sandbox.readDeny).toEqual(expect.arrayContaining(protectedPaths));
	});
	it.each(protectedPaths)("cannot make %s grantable", (path) => {
		const result = fold(
			[{ source: "builtin" }, { source: "user_global", patch: { sandbox: { grantableReadDeny: [path] } } }],
			options,
		);
		expect(result.ok).toBe(false);
		if (!result.ok)
			expect(result.errors.some((error) => /immutable credential or state/.test(error.message))).toBe(true);
	});
});

/** Exercise the installed session's nested pipeline, not a clone of its hook loop. */
async function withSession(
	run: (fixture: {
		nested: (name: string, args: Record<string, unknown>) => Promise<{ isError: boolean; result: unknown }>;
		write: ReturnType<typeof vi.fn>;
		foreign: ReturnType<typeof vi.fn>;
		seen: string[];
		openBreaker: () => void;
	}) => Promise<void>,
	mutate = false,
) {
	const root = mkdtempSync(join(tmpdir(), "enclave-pi-1.1-"));
	const agentDir = join(root, "agent");
	const profile = defaultProfile({ cwd: root, agentDir });
	profile.rules.deny.push("write(**/blocked.txt)");
	let open = false;
	const lock = new ActionLock({ breakerOpen: () => open });
	const write = vi.fn(async () => {});
	const foreign = vi.fn(async () => ({ content: [{ type: "text" as const, text: "outside" }], details: {} }));
	const seen: string[] = [];
	const factories: ExtensionFactory[] = [
		(pi) => {
			const client = { mkdir: async () => {}, writeFile: write } as unknown as FsClient;
			const tool = createWriteTool(root, {
				operations: createWriteOperations(
					() => client,
					(name, path) => lock.beginPathExecution(name, path).action,
					(path) => lock.beginParentExecution(path).action,
				),
			});
			pi.registerTool(bindOwnedTool(tool, lock));
			for (const name of ["codemode", "powershell", "mcp__fixture__send"]) {
				pi.registerTool({ ...tool, name, exposure: "deferred", execute: foreign });
			}
			pi.on("tool_call", async (event) => {
				seen.push(`${event.parentToolCallId}:${event.toolCallId}:${event.toolName}`);
				return decide(event, { profile, cwd: root, home: root, owned: OWNED_TOOLS, lock, breakerOpen: () => open });
			});
			pi.on("tool_result", (event) => lock.consume(event.toolCallId));
		},
	];
	if (mutate)
		factories.push((pi) => {
			pi.on("tool_call", (event) => {
				(event.input as Record<string, unknown>).content = "changed";
			});
		});
	const settingsManager = SettingsManager.inMemory({});
	const loader = new DefaultResourceLoader({
		cwd: root,
		agentDir,
		settingsManager,
		extensionFactories: factories,
		noExtensions: true,
		noSkills: true,
		noThemes: true,
		noPromptTemplates: true,
		noContextFiles: true,
	});
	const runtime = await ModelRuntime.create({
		credentials: new InMemoryCredentialStore(),
		modelsPath: null,
		allowModelNetwork: false,
	});
	let dispose: (() => void) | undefined;
	try {
		await loader.reload();
		const { session } = await createAgentSession({
			cwd: root,
			agentDir,
			settingsManager,
			resourceLoader: loader,
			modelRuntime: runtime,
			sessionManager: SessionManager.inMemory(root),
		});
		dispose = () => session.dispose();
		await session.bindExtensions({});
		session.agent.state.messages = [fauxAssistantMessage("fixture parent call")];
		// This internal path is intentionally pinned to the supported upstream build.
		const pipeline = session as unknown as {
			_executeNestedToolCall(
				parent: string,
				name: string,
				args: unknown,
				options: object,
			): Promise<{ isError: boolean; result: unknown }>;
		};
		await run({
			nested: (name, args) => pipeline._executeNestedToolCall("parent", name, args, {}),
			write,
			foreign,
			seen,
			openBreaker: () => {
				open = true;
			},
		});
	} finally {
		dispose?.();
		rmSync(root, { recursive: true, force: true });
	}
}

describe("pi 1.1 nested execution", () => {
	it("gates child calls and binds the complete input to their distinct IDs", async () => {
		await withSession(async ({ nested, write, seen }) => {
			expect((await nested("write", { path: "allowed.txt", content: "original" })).isError).toBe(false);
			expect(write).toHaveBeenCalledOnce();
			expect(write.mock.calls[0]?.[1]).toBe("original");
			expect((await nested("write", { path: "blocked.txt", content: "denied" })).isError).toBe(true);
			expect(write).toHaveBeenCalledOnce();
			expect(seen).toEqual(["parent:parent/1:write", "parent:parent/2:write"]);
		});
	});
	it.each([
		"codemode",
		"powershell",
		"mcp__fixture__send",
	])("denies deferred %s even when it is callable", async (name) => {
		await withSession(async ({ nested, foreign, seen }) => {
			const result = await nested(name, { path: "x", content: "secret" });
			expect(result.isError).toBe(true);
			expect(JSON.stringify(result.result)).toContain("not in tools.allow");
			expect(foreign).not.toHaveBeenCalled();
			expect(seen).toContain(`parent:parent/1:${name}`);
		});
	});
	it("refuses a child when the breaker is open", async () => {
		await withSession(async ({ nested, write, openBreaker }) => {
			openBreaker();
			expect((await nested("write", { path: "x", content: "denied" })).isError).toBe(true);
			expect(write).not.toHaveBeenCalled();
		});
	});
	it("fails closed when a later handler mutates approved child input", async () => {
		await withSession(async ({ nested, write }) => {
			expect((await nested("write", { path: "x", content: "approved" })).isError).toBe(true);
			expect(write).not.toHaveBeenCalled();
		}, true);
	});
});
