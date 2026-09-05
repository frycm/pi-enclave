import {
	createEditTool,
	createLsTool,
	createReadTool,
	createWriteTool,
	type ExtensionContext,
} from "@earendil-works/pi-coding-agent";
import { describe, expect, it, vi } from "vitest";
import type { FsClient } from "../../src/backend/types.ts";
import { defaultProfile, OWNED_TOOLS } from "../../src/config/defaults.ts";
import { decide } from "../../src/gate/gate.ts";
import { ActionLock } from "../../src/gate/lock.ts";
import { canonicalize } from "../../src/policy/canonical.ts";
import {
	createEditOperations,
	createLsOperations,
	createReadOperations,
	createWriteOperations,
} from "../../src/tools/file-ops.ts";
import { bindOwnedTool } from "../../src/tools/locked.ts";

const cwd = "/work";
const home = "/home/u";
const ctx = { cwd } as ExtensionContext;
const canonical = (tool: string, input: Record<string, unknown>) =>
	canonicalize({ tool, input, cwd, home, profileName: "dev" });

function memoryFs(): FsClient {
	return {
		access: async () => {},
		head: async () => Buffer.alloc(0),
		readFile: async () => Buffer.from("one\ntwo\n"),
		writeFile: async () => {},
		mkdir: async () => {},
	} as unknown as FsClient;
}

describe("complete owned tool invocation binding", () => {
	it.each([
		false,
		true,
	])("keeps concurrent same-path read grants separate through gate and real pi tools (reverse=%s)", async (reverse) => {
		const profile = defaultProfile({ cwd, home, agentDir: `${home}/.pi/agent` });
		profile.sandbox.readDeny.push("/work/private");
		profile.sandbox.grantableReadDeny.push("/work/private");
		const lock = new ActionLock();
		const inputs = [
			{ path: "/work/private/notes", limit: 1, allow_read: "/work/private" },
			{ path: "/work/private/notes", offset: 2, limit: 1 },
		];
		const deps = { profile, cwd, home, owned: OWNED_TOOLS, lock, escalator: { confirm: async () => true } };
		for (const [i, input] of inputs.entries())
			expect((await decide({ toolName: "read", toolCallId: String(i), input }, deps)).block).toBe(false);
		const selected: Array<{ hash: string; granted: boolean }> = [];
		let accessCount = 0;
		let release!: () => void;
		const both = new Promise<void>((resolve) => {
			release = resolve;
		});
		const operations = createReadOperations(
			(action) => {
				const granted = action?.capability?.kind === "read";
				selected.push({ hash: action?.hash ?? "missing", granted });
				return {
					...memoryFs(),
					access: async () => {
						if (++accessCount === 2) release();
						await both;
						if (!granted) throw new Error("base profile denied");
					},
				};
			},
			(tool, path) => lock.beginPathExecution(tool, path).action,
		);
		const tool = bindOwnedTool(createReadTool(cwd, { operations }), lock);
		const order = reverse ? [1, 0] : [0, 1];
		const results = await Promise.allSettled(
			order.map((i) => tool.execute(String(i), inputs[i], undefined, undefined, ctx)),
		);
		expect(results[order.indexOf(0)]?.status).toBe("fulfilled");
		expect(results[order.indexOf(1)]).toMatchObject({
			status: "rejected",
			reason: expect.objectContaining({ message: expect.stringContaining("base profile denied") }),
		});
		expect(new Set(selected.map((entry) => entry.hash)).size).toBe(2);
		expect(lock.entries().every((entry) => entry.state === "consumed")).toBe(true);
	});

	it("refuses changed input, cwd, IDs and replay before touching the helper", async () => {
		const lock = new ActionLock();
		const input = { path: "/work/notes", limit: 1 };
		lock.register(canonical("read", input), "read");
		const access = vi.fn(async () => {});
		const tool = bindOwnedTool(
			createReadTool(cwd, {
				operations: createReadOperations(
					() => ({ ...memoryFs(), access }),
					(name, path) => lock.beginPathExecution(name, path).action,
				),
			}),
			lock,
		);
		await expect(tool.execute("other", input, undefined, undefined, ctx)).rejects.toThrow("ID");
		await expect(tool.execute("read", { ...input, offset: 2 }, undefined, undefined, ctx)).rejects.toThrow("differs");
		await expect(
			tool.execute("read", input, undefined, undefined, { cwd: "/elsewhere" } as ExtensionContext),
		).rejects.toThrow("differs");
		expect(access).not.toHaveBeenCalled();
		await tool.execute("read", input, undefined, undefined, ctx);
		await expect(tool.execute("read", input, undefined, undefined, ctx)).rejects.toThrow("already started");
	});

	it("preserves edit's multiple operations and ordinary write parent creation", async () => {
		const lock = new ActionLock();
		const client = memoryFs();
		const writeFile = vi.fn(client.writeFile);
		const mkdir = vi.fn(client.mkdir);
		const fs = () => ({ ...client, writeFile, mkdir });
		const guard = (tool: string, path: string) => lock.beginPathExecution(tool, path).action;
		const editInput = { path: "/work/notes", edits: [{ oldText: "one", newText: "three" }] };
		lock.register(canonical("edit", editInput), "edit");
		await bindOwnedTool(createEditTool(cwd, { operations: createEditOperations(fs, guard) }), lock).execute(
			"edit",
			editInput,
			undefined,
			undefined,
			ctx,
		);
		expect(writeFile).toHaveBeenCalledWith("/work/notes", "three\ntwo\n");
		const input = { path: "/work/new/notes", content: "hi" };
		lock.register(canonical("write", input), "write");
		await bindOwnedTool(
			createWriteTool(cwd, {
				operations: createWriteOperations(fs, guard, (path) => lock.beginParentExecution(path).action),
			}),
			lock,
		).execute("write", input, undefined, undefined, ctx);
		expect(mkdir).toHaveBeenCalledWith("/work/new");
	});

	it.each(["breaker", "abort", "reset"])("refuses queued mkdir before any side effect after %s", async (cause) => {
		let open = false;
		const lock = new ActionLock({ breakerOpen: () => open });
		const input = { path: "/work/new/file", content: "hi" };
		lock.register(canonical("write", input), "write");
		const mkdir = vi.fn(async () => {});
		const controller = new AbortController();
		if (cause === "breaker") open = true;
		if (cause === "abort") controller.abort();
		if (cause === "reset") lock.reset();
		const tool = bindOwnedTool(
			createWriteTool(cwd, {
				operations: createWriteOperations(
					() => ({ ...memoryFs(), mkdir }),
					(name, path) => lock.beginPathExecution(name, path).action,
					(path) => lock.beginParentExecution(path).action,
				),
			}),
			lock,
		);
		await expect(tool.execute("write", input, controller.signal, undefined, ctx)).rejects.toThrow();
		expect(mkdir).not.toHaveBeenCalled();
	});

	it("invalidates a retained async scope after reset and after completion", async () => {
		const lock = new ActionLock();
		const input = { path: "/work/notes" };
		lock.register(canonical("read", input), "read");
		await lock.runInvocation("read", "read", input, cwd, async () => {
			lock.reset();
			expect(() => lock.beginPathExecution("read", input.path)).toThrow("reset");
		});
		lock.register(canonical("read", input), "next");
		let late!: Promise<unknown>;
		let release!: () => void;
		const wait = new Promise<void>((resolve) => {
			release = resolve;
		});
		await lock.runInvocation("next", "read", input, cwd, async () => {
			late = wait.then(() => lock.beginPathExecution("read", input.path));
		});
		const rejected = expect(late).rejects.toThrow("finished");
		release();
		await rejected;
	});
});

it("lists immediate directory entries under the correct invocation, even with a queued child ls", async () => {
	const lock = new ActionLock();
	const parent = { path: "/work" };
	lock.register(canonical("ls", parent), "parent");
	lock.register(canonical("ls", { path: "/work/notes" }), "child");
	const selected: string[] = [];
	const client = {
		...memoryFs(),
		exists: async () => true,
		readdir: async () => ["notes", "nested"],
		stat: async (path: string) => ({ isDirectory: () => path !== "/work/notes" }),
	};
	const tool = bindOwnedTool(
		createLsTool(cwd, {
			operations: createLsOperations(
				(action) => {
					selected.push(action?.hash ?? "missing");
					return client;
				},
				(name, path) => lock.beginPathExecution(name, path).action,
				(path) => lock.beginDirectoryEntryExecution(path).action,
			),
		}),
		lock,
	);
	const result = await tool.execute("parent", parent, undefined, undefined, ctx);
	expect(JSON.stringify(result)).toContain("notes");
	expect(JSON.stringify(result)).toContain("nested/");
	expect(selected.every((hash) => hash === canonical("ls", parent).hash)).toBe(true);
	await lock.runInvocation("child", "ls", { path: "/work/notes" }, cwd, async () => {
		expect(() => lock.beginDirectoryEntryExecution("/work/elsewhere")).toThrow("immediate entry");
		expect(() => lock.beginDirectoryEntryExecution("/work/notes/deep/file")).toThrow("immediate entry");
	});
});
