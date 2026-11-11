import { describe, expect, it, vi } from "vitest";
import type { FsClient, FsClientLease } from "../../src/backend/types.ts";
import { ActionLock } from "../../src/gate/lock.ts";
import { canonicalize } from "../../src/policy/canonical.ts";
import { createReadOperations } from "../../src/tools/file-ops.ts";

function client(content: string): FsClient {
	return {
		readFile: async () => Buffer.from(content),
		async *createReadStream() {
			yield Buffer.from(content);
		},
		head: async () => Buffer.alloc(0),
		writeFile: async () => {},
		mkdir: async () => {},
		access: async () => {},
		stat: async () => ({ isDirectory: () => false }),
		readdir: async () => [],
		exists: async () => true,
		glob: async () => [],
		grep: async () => ({ stdout: "", exitCode: 1 }),
	};
}

describe("filesystem capability helper", () => {
	it("cancels during lease acquisition and disposes a late helper without reading", async () => {
		let acquired!: (lease: FsClientLease) => void;
		const pending = new Promise<FsClientLease>((resolve) => {
			acquired = resolve;
		});
		const controller = new AbortController();
		const fs = client("must not be read");
		const read = vi.spyOn(fs, "createReadStream");
		const dispose = vi.fn(async () => {});
		const next = createReadOperations(() => pending)
			.createReadStream("/private/report", { signal: controller.signal })
			[Symbol.asyncIterator]()
			.next();
		controller.abort();
		await expect(next).rejects.toThrow(/abort/i);
		acquired({ client: fs, dispose });
		await vi.waitFor(() => expect(dispose).toHaveBeenCalledOnce());
		expect(read).not.toHaveBeenCalled();
	});

	it.each(["abort", "reset", "breaker"])("revokes a streaming lease between chunks after %s", async (cause) => {
		let open = false;
		const lock = new ActionLock({ breakerOpen: () => open });
		const input = { path: "/private/report", allow_read: "/private" };
		const action = canonicalize({ tool: "read", input, cwd: "/work", home: "/home/u", profileName: "dev" });
		lock.register(action, "read");
		const dispose = vi.fn(async () => {});
		const advanced = vi.fn();
		const fs = client("unused");
		fs.createReadStream = async function* () {
			try {
				yield Buffer.from("first");
				advanced();
				yield Buffer.from("second");
			} finally {
				advanced("closed");
			}
		};
		const ref = vi.fn(() => ({ client: fs, dispose }));
		const ops = createReadOperations(ref, (name, path) => lock.beginPathExecution(name, path).action);
		const controller = new AbortController();
		await lock.runInvocation(
			"read",
			"read",
			input,
			"/work",
			async () => {
				const iterator = ops.createReadStream(input.path, { signal: controller.signal })[Symbol.asyncIterator]();
				expect(Buffer.from((await iterator.next()).value ?? []).toString()).toBe("first");
				expect(dispose).not.toHaveBeenCalled();
				if (cause === "abort") controller.abort();
				if (cause === "reset") lock.reset();
				if (cause === "breaker") open = true;
				await expect(iterator.next()).rejects.toThrow();
				expect(advanced.mock.calls).toEqual([["closed"]]);
				expect(dispose).toHaveBeenCalledOnce();
			},
			controller.signal,
		);
		expect(ref).toHaveBeenCalledOnce();
		expect(ref).toHaveBeenCalledWith(action);
	});

	it("closes a one-shot streaming helper on abort while its consumer is paused", async () => {
		const dispose = vi.fn(async () => {});
		const controller = new AbortController();
		const fs = client("first");
		const iterator = createReadOperations(() => ({ client: fs, dispose }))
			.createReadStream("/private/report", { signal: controller.signal })
			[Symbol.asyncIterator]();
		await iterator.next();
		controller.abort();
		expect(dispose).toHaveBeenCalledOnce();
		await expect(iterator.next()).rejects.toThrow(/abort/i);
		expect(dispose).toHaveBeenCalledOnce();
	});

	it("uses and disposes a one-shot lease for an approved read action", async () => {
		const action = canonicalize({
			tool: "read",
			input: { path: "/private/report", allow_read: "/private" },
			cwd: "/work",
			home: "/home/u",
			profileName: "dev",
		});
		const dispose = vi.fn(async () => {});
		const ref = vi.fn(() => ({ client: client("capability"), dispose }));
		const operations = createReadOperations(ref, () => action);

		expect((await operations.readFile("/private/report")).toString()).toBe("capability");
		expect(ref).toHaveBeenCalledWith(action);
		expect(dispose).toHaveBeenCalledOnce();
	});

	it("still disposes the one-shot helper when the operation fails", async () => {
		const action = canonicalize({
			tool: "read",
			input: { path: "/private/report", allow_read: "/private" },
			cwd: "/work",
			home: "/home/u",
			profileName: "dev",
		});
		const failing = client("unused");
		failing.readFile = async () => {
			throw new Error("read failed");
		};
		const dispose = vi.fn(async () => {});
		const operations = createReadOperations(
			() => ({ client: failing, dispose }),
			() => action,
		);

		await expect(operations.readFile("/private/report")).rejects.toThrow("read failed");
		expect(dispose).toHaveBeenCalledOnce();
	});
});
