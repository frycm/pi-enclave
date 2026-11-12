/**
 * The helper must never block on, or read without end from, something that
 * is not a regular file (#35). It is one thread: a blocking open of a FIFO
 * used to stop it reading the cancel frame and every later request, so one
 * `mkfifo` disabled the file tools for the rest of the session.
 */
import { spawn, spawnSync } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it, vi } from "vitest";
import { HelperFsClient } from "../../src/fs/client.ts";

const HELPER = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "src", "fs", "helper.mjs");
const roots: string[] = [];
const clients: HelperFsClient[] = [];
afterEach(async () => {
	await Promise.all(clients.splice(0).map((client) => client.dispose()));
	for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function client(root: string, options: { callTimeoutMs?: number; livenessGraceMs?: number } = {}) {
	const spawnHelper = vi.fn(() => spawn(process.execPath, [HELPER], { stdio: ["pipe", "pipe", "pipe"] }));
	const fs = new HelperFsClient({
		compiled: {
			backend: "seatbelt",
			profile: { mode: "workspace-write", writableRoots: [root], readDeny: [], network: "off", allowPty: false },
			describe: () => "unsandboxed test helper",
		},
		spawnHelper: spawnHelper as never,
		callTimeoutMs: options.callTimeoutMs ?? 5_000,
		...(options.livenessGraceMs !== undefined ? { livenessGraceMs: options.livenessGraceMs } : {}),
	});
	clients.push(fs);
	return { fs, spawnHelper };
}

function workspace(): string {
	const root = mkdtempSync(join(tmpdir(), "enclave-special-"));
	roots.push(root);
	return root;
}

function mkfifo(path: string): void {
	const result = spawnSync("mkfifo", [path], { encoding: "utf8" });
	if (result.status !== 0) throw new Error(result.stderr || "mkfifo failed");
}

describe("helper special files (#35)", () => {
	for (const op of ["head", "readFile", "writeFile"] as const) {
		it(`${op} on a FIFO fails at once, and the next operation succeeds`, async () => {
			const root = workspace();
			const fifo = join(root, "pipe");
			mkfifo(fifo);
			writeFileSync(join(root, "ok.txt"), "fine");
			const { fs } = client(root);
			const started = Date.now();
			const call = op === "head" ? fs.head(fifo, 16) : op === "readFile" ? fs.readFile(fifo) : fs.writeFile(fifo, "x");
			await expect(call).rejects.toThrow(/not a regular file/);
			expect(Date.now() - started).toBeLessThan(1_000);
			expect((await fs.readFile(join(root, "ok.txt"))).toString()).toBe("fine");
		});
	}

	it("refuses a character device rather than reading it without end", async () => {
		const root = workspace();
		const { fs } = client(root);
		await expect(fs.readFile("/dev/zero")).rejects.toThrow(/not a regular file/);
		await expect(fs.head("/dev/zero", 16)).rejects.toThrow(/not a regular file/);
		await expect(fs.writeFile("/dev/null", "x")).rejects.toThrow(/not a regular file/);
	});

	it("refuses a directory, and still reads, writes and creates regular files", async () => {
		const root = workspace();
		mkdirSync(join(root, "dir"));
		const { fs } = client(root);
		await expect(fs.readFile(join(root, "dir"))).rejects.toThrow();
		await expect(fs.writeFile(join(root, "dir"), "x")).rejects.toThrow();
		const created = join(root, "new.txt");
		await fs.writeFile(created, "first version, longer");
		await fs.writeFile(created, "second");
		// Truncated, not overwritten in place.
		expect(readFileSync(created, "utf8")).toBe("second");
		expect((await fs.head(created, 3)).toString()).toBe("sec");
		expect(existsSync(created)).toBe(true);
	});
});

describe("a helper that stops answering (#35)", () => {
	it("is killed after a call times out and replaced for the next call", async () => {
		const root = workspace();
		writeFileSync(join(root, "ok.txt"), "fine");
		// Reports ready, then never answers anything: the shape of a helper
		// stuck in a blocking call.
		const hung = [
			`const header = Buffer.alloc(4);`,
			`const body = Buffer.from(JSON.stringify({ ready: true, protocol: 3 }));`,
			`header.writeUInt32BE(body.length, 0);`,
			`process.stdout.write(Buffer.concat([header, body]));`,
			`process.stdin.resume();`,
			`setInterval(() => {}, 1000);`,
		].join("\n");
		let spawned = 0;
		const spawnHelper = vi.fn(() => {
			spawned++;
			return spawned === 1
				? spawn(process.execPath, ["-e", hung], { stdio: ["pipe", "pipe", "pipe"] })
				: spawn(process.execPath, [HELPER], { stdio: ["pipe", "pipe", "pipe"] });
		});
		const fs = new HelperFsClient({
			compiled: {
				backend: "seatbelt",
				profile: { mode: "workspace-write", writableRoots: [root], readDeny: [], network: "off", allowPty: false },
				describe: () => "unsandboxed test helper",
			},
			spawnHelper: spawnHelper as never,
			callTimeoutMs: 300,
			livenessGraceMs: 200,
		});
		clients.push(fs);

		await expect(fs.readFile(join(root, "ok.txt"))).rejects.toThrow(/timed out/);
		const first = spawnHelper.mock.results[0]?.value as { exitCode: number | null; signalCode: string | null };
		await vi.waitFor(() => expect(first.signalCode).toBe("SIGKILL"), { timeout: 2_000 });
		expect((await fs.readFile(join(root, "ok.txt"))).toString()).toBe("fine");
		expect(spawnHelper).toHaveBeenCalledTimes(2);
	});

	it("is kept when it still answers, as after a slow search", async () => {
		const root = workspace();
		const slow = join(root, "slow-rg.sh");
		writeFileSync(slow, "#!/bin/sh\nsleep 2\n");
		chmodSync(slow, 0o755);
		const spawnHelper = vi.fn(() =>
			spawn(process.execPath, [HELPER], {
				env: { ...process.env, PI_ENCLAVE_RG: slow, PI_ENCLAVE_FD: slow },
				stdio: ["pipe", "pipe", "pipe"],
			}),
		);
		const fs = new HelperFsClient({
			compiled: {
				backend: "seatbelt",
				profile: { mode: "workspace-write", writableRoots: [root], readDeny: [], network: "off", allowPty: false },
				describe: () => "unsandboxed test helper",
			},
			spawnHelper: spawnHelper as never,
			callTimeoutMs: 300,
			livenessGraceMs: 500,
		});
		clients.push(fs);
		await expect(fs.grep(["--json", "x", root], { path: root })).rejects.toThrow(/timed out/);
		// Past the grace period: a helper that answered the ping is not replaced.
		await new Promise((resolve) => setTimeout(resolve, 700));
		expect(await fs.exists(root)).toBe(true);
		expect(spawnHelper).toHaveBeenCalledTimes(1);
	});

	it("is kept while it is still sending, as when the pong queues behind a large frame", async () => {
		const root = workspace();
		// Answers the first request with a large frame written slowly, the
		// way a big readFile drains through a pipe, then answers the ping that
		// queued behind it, then everything else at once.
		const busy = [
			`const send = (m) => { const b = Buffer.from(JSON.stringify(m)); const h = Buffer.alloc(4); h.writeUInt32BE(b.length, 0); return Buffer.concat([h, b]); };`,
			`process.stdout.write(send({ ready: true, protocol: 3 }));`,
			`let held = Buffer.alloc(0); let draining = false; const queued = [];`,
			`process.stdin.on("data", (chunk) => {`,
			`  held = Buffer.concat([held, chunk]);`,
			`  while (held.length >= 4 && held.length >= 4 + held.readUInt32BE(0)) {`,
			`    const request = JSON.parse(held.subarray(4, 4 + held.readUInt32BE(0)).toString());`,
			`    held = held.subarray(4 + held.readUInt32BE(0));`,
			`    if (request.op === "cancel") continue;`,
			`    const reply = send({ id: request.id, ok: true, result: request.op === "readFile" ? "x".repeat(400000) : request.op === "ping" ? "pong" : true });`,
			`    if (request.op !== "readFile") { if (draining) queued.push(reply); else process.stdout.write(reply); continue; }`,
			`    draining = true; let at = 0; const piece = Math.ceil(reply.length / 20);`,
			`    const timer = setInterval(() => {`,
			`      process.stdout.write(reply.subarray(at, at + piece)); at += piece;`,
			`      if (at >= reply.length) { clearInterval(timer); draining = false; for (const q of queued.splice(0)) process.stdout.write(q); }`,
			`    }, 60);`,
			`  }`,
			`});`,
		].join("\n");
		const spawnHelper = vi.fn(() => spawn(process.execPath, ["-e", busy], { stdio: ["pipe", "pipe", "pipe"] }));
		const fs = new HelperFsClient({
			compiled: {
				backend: "seatbelt",
				profile: { mode: "workspace-write", writableRoots: [root], readDeny: [], network: "off", allowPty: false },
				describe: () => "unsandboxed test helper",
			},
			spawnHelper: spawnHelper as never,
			callTimeoutMs: 200,
			livenessGraceMs: 200,
		});
		clients.push(fs);

		// The frame takes about 1.2 s; the call gives up at 0.2 s and the
		// ping's grace period would end at 0.4 s.
		await expect(fs.readFile(join(root, "big.txt"))).rejects.toThrow(/timed out/);
		await new Promise((resolve) => setTimeout(resolve, 1_500));
		const first = spawnHelper.mock.results[0]?.value as { signalCode: string | null };
		expect(first.signalCode).toBeNull();
		expect(await fs.exists(root)).toBe(true);
		expect(spawnHelper).toHaveBeenCalledTimes(1);
	});
});
