import { describe, expect, it, vi } from "vitest";
import type { FsClient } from "../../src/backend/types.ts";
import { canonicalize } from "../../src/policy/canonical.ts";
import { createReadOperations } from "../../src/tools/file-ops.ts";

function client(content: string): FsClient {
	return {
		readFile: async () => Buffer.from(content),
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
