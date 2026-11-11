import { spawn } from "node:child_process";
import {
	closeSync,
	existsSync,
	ftruncateSync,
	mkdtempSync,
	openSync,
	readFileSync,
	renameSync,
	rmSync,
	writeFileSync,
	writeSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { createReadTool } from "@earendil-works/pi-coding-agent";
import { afterEach, describe, expect, it, vi } from "vitest";
import { HelperFsClient } from "../../src/fs/client.ts";
import { READ_CHUNK_BYTES } from "../../src/fs/protocol.ts";
import { createReadOperations } from "../../src/tools/file-ops.ts";

const HELPER = join(dirname(fileURLToPath(import.meta.url)), "../../src/fs/helper.mjs");
const roots: string[] = [];
const clients: HelperFsClient[] = [];
afterEach(async () => {
	await Promise.all(clients.splice(0).map((client) => client.dispose()));
	for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function fixture() {
	const root = mkdtempSync(join(tmpdir(), "enclave-stream-"));
	roots.push(root);
	const spawnHelper = vi.fn(() => spawn(process.execPath, [HELPER], { stdio: ["pipe", "pipe", "pipe"] }));
	const client = new HelperFsClient({
		compiled: {
			backend: "seatbelt",
			profile: { mode: "workspace-write", writableRoots: [root], readDeny: [], network: "off", allowPty: false },
			describe: () => "unsandboxed protocol fixture",
		},
		spawnHelper,
	});
	clients.push(client);
	return { root, client, spawnHelper };
}

describe("sandbox helper streaming protocol", () => {
	it.each(["abort", "timeout", "oversized"])("closes a pending or rejected chunk after %s", async (cause) => {
		const { root, spawnHelper } = fixture();
		const script = join(root, "fixture.mjs");
		const closed = join(root, "closed");
		const asked = join(root, "asked");
		writeFileSync(
			script,
			`import { writeFileSync } from 'node:fs';
const send = v => {const p=Buffer.from(JSON.stringify(v));const h=Buffer.alloc(4);h.writeUInt32BE(p.length);process.stdout.write(Buffer.concat([h,p]));};
let buffer=Buffer.alloc(0);
process.stdin.on('data', chunk=>{buffer=Buffer.concat([buffer,chunk]);while(buffer.length>=4 && buffer.length>=4+buffer.readUInt32BE(0)){const n=buffer.readUInt32BE(0);const r=JSON.parse(buffer.subarray(4,4+n));buffer=buffer.subarray(4+n);if(r.op==='readChunk'){writeFileSync(${JSON.stringify(asked)},'asked');if(${JSON.stringify(cause)}==='oversized')send({id:r.id,ok:true,result:{data:'A'.repeat(100000),done:false}});continue;}if(r.op==='closeRead'||r.op==='cancel')writeFileSync(${JSON.stringify(closed)},'closed');send({id:r.id,ok:true,result:r.op==='exists'?true:null});}});
process.stdin.on('end',()=>process.exit());
send({ready:true,protocol:3,pid:process.pid});`,
		);
		spawnHelper.mockImplementation(() => spawn(process.execPath, [script], { stdio: ["pipe", "pipe", "pipe"] }));
		// Use a bounded test deadline for the fixture that never answers a chunk.
		const timed = new HelperFsClient({
			compiled: {
				backend: "seatbelt",
				profile: { mode: "workspace-write", writableRoots: [root], readDeny: [], network: "off", allowPty: false },
				describe: () => "wire fixture",
			},
			spawnHelper,
			callTimeoutMs: cause === "timeout" ? 200 : 5_000,
		});
		clients.push(timed);
		const controller = new AbortController();
		const next = timed
			.createReadStream(join(root, "file"), { signal: controller.signal })
			[Symbol.asyncIterator]()
			.next();
		const rejected = expect(next).rejects.toThrow(
			cause === "abort" ? /abort/i : cause === "timeout" ? /timed out/ : /oversized/,
		);
		if (cause === "abort") {
			await vi.waitFor(() => expect(existsSync(asked)).toBe(true), { timeout: 2_000, interval: 5 });
			controller.abort();
		}
		await rejected;
		await timed.exists(root);
		expect(readFileSync(closed, "utf8")).toBe("closed");
	});

	it("reads a file above the whole-file cap through the real pi tool", async () => {
		const { root, client } = fixture();
		const path = join(root, "large.txt");
		const fd = openSync(path, "w");
		try {
			writeSync(fd, "first\n");
			ftruncateSync(fd, 40 * 1024 * 1024);
		} finally {
			closeSync(fd);
		}
		const whole = vi.spyOn(client, "readFile").mockRejectedValue(new Error("whole-file read forbidden"));
		const tool = createReadTool(root, { operations: createReadOperations(() => client) });
		const result = await tool.execute("large", { path, limit: 1 }, undefined, undefined);
		expect(JSON.stringify(result.content)).toContain("first");
		expect(JSON.stringify(result.content)).toContain("more lines");
		expect(whole).not.toHaveBeenCalled();
	});

	it("pins one descriptor, bounds chunks and excludes data appended after opening", async () => {
		const { root, client } = fixture();
		const path = join(root, "file");
		writeFileSync(path, Buffer.alloc(READ_CHUNK_BYTES * 2, "a"));
		const iterator = client.createReadStream(path)[Symbol.asyncIterator]();
		const first = await iterator.next();
		expect(first.value).toHaveLength(READ_CHUNK_BYTES);
		renameSync(path, join(root, "original"));
		writeFileSync(path, "replacement");
		writeFileSync(join(root, "original"), "appended", { flag: "a" });
		const second = await iterator.next();
		expect(Buffer.from(second.value ?? []).toString()).toBe("a".repeat(READ_CHUNK_BYTES));
		expect((await iterator.next()).done).toBe(true);
	});

	it("releases descriptors on early return without waiting for EOF", async () => {
		const { root, client } = fixture();
		const path = join(root, "file");
		writeFileSync(path, Buffer.alloc(READ_CHUNK_BYTES * 2));
		// More than the helper's open-stream bound catches leaked descriptors.
		for (let i = 0; i < 40; i++) {
			const iterator = client.createReadStream(path)[Symbol.asyncIterator]();
			await iterator.next();
			await iterator.return?.();
		}
		expect(await client.exists(path)).toBe(true);
	});

	it("closes a paused stream immediately on abort and refuses further chunks", async () => {
		const { root, client } = fixture();
		const path = join(root, "file");
		writeFileSync(path, Buffer.alloc(READ_CHUNK_BYTES * 2));
		for (let i = 0; i < 40; i++) {
			const controller = new AbortController();
			const iterator = client.createReadStream(path, { signal: controller.signal })[Symbol.asyncIterator]();
			await iterator.next();
			controller.abort();
			await expect(iterator.next()).rejects.toThrow(/abort/i);
		}
		expect(await client.exists(path)).toBe(true);
	});

	it("does not reopen a retired stream on a replacement helper", async () => {
		const { root, client, spawnHelper } = fixture();
		const path = join(root, "file");
		writeFileSync(path, Buffer.alloc(READ_CHUNK_BYTES * 2));
		const iterator = client.createReadStream(path)[Symbol.asyncIterator]();
		await iterator.next();
		client.retire();
		await expect(iterator.next()).rejects.toThrow("retired");
		expect(spawnHelper).toHaveBeenCalledOnce();
		expect(await client.exists(path)).toBe(true);
		expect(spawnHelper).toHaveBeenCalledTimes(2);
	});

	it("cancels while helper startup is pending", async () => {
		const { root, client, spawnHelper } = fixture();
		let started!: () => void;
		const pending = new Promise<void>((resolve) => {
			started = resolve;
		});
		spawnHelper.mockImplementation(() => {
			started();
			return spawn(process.execPath, ["-e", "process.stdin.resume()"], { stdio: ["pipe", "pipe", "pipe"] });
		});
		const controller = new AbortController();
		const next = client
			.createReadStream(join(root, "file"), { signal: controller.signal })
			[Symbol.asyncIterator]()
			.next();
		const rejected = expect(next).rejects.toThrow(/abort/i);
		await pending;
		controller.abort();
		await rejected;
	});

	it("does not start a helper for a read already cancelled", async () => {
		const { root, client, spawnHelper } = fixture();
		const controller = new AbortController();
		controller.abort();
		await expect(
			client.createReadStream(join(root, "file"), { signal: controller.signal })[Symbol.asyncIterator]().next(),
		).rejects.toThrow(/abort/i);
		expect(spawnHelper).not.toHaveBeenCalled();
	});
});
