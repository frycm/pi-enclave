/**
 * Measure the filesystem helper.
 *
 * Phase 1's exit criteria require read latency through the helper to be measured
 * rather than assumed: routing every file operation through another process is
 * the design's main performance cost, and "probably fine" is not a number.
 */
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { SrtBackend } from "../src/backend/srt.ts";
import { createDevProfile } from "../src/config/profile.ts";

const workspace = mkdtempSync(join(tmpdir(), "enclave-bench-"));
const small = join(workspace, "small.txt");
const large = join(workspace, "large.txt");
writeFileSync(small, "x".repeat(4 * 1024));
writeFileSync(large, "y".repeat(1024 * 1024));

const backend = new SrtBackend({ weakerNestedSandbox: process.env.PI_ENCLAVE_WEAKER_NESTED === "1" });
const started = Date.now();
const compiled = await backend.compile(createDevProfile({ cwd: workspace }));
const compileMs = Date.now() - started;

const fs = backend.fs(compiled);
const readyAt = Date.now();
await fs.readFile(small); // forces the helper to start
const startupMs = Date.now() - readyAt;

async function bench(label: string, iterations: number, run: () => Promise<unknown>) {
	await run();
	const t0 = process.hrtime.bigint();
	for (let i = 0; i < iterations; i++) await run();
	const totalMs = Number(process.hrtime.bigint() - t0) / 1e6;
	console.log(`  ${label.padEnd(28)} ${(totalMs / iterations).toFixed(3)} ms/call  (${iterations} calls)`);
}

console.log(`backend: ${backend.name}${backend.weakened ? " [WEAKENED]" : ""}`);
console.log(`  profile compile              ${compileMs} ms (once per session)`);
console.log(`  helper startup               ${startupMs} ms (once per profile)`);
await bench("read 4 KB", 200, () => fs.readFile(small));
await bench("read 1 MB", 50, () => fs.readFile(large));
await bench("stat", 200, () => fs.stat(workspace));
await bench("readdir", 200, () => fs.readdir(workspace));
await bench("write 4 KB", 200, () => fs.writeFile(join(workspace, "out.txt"), "z".repeat(4096)));

await backend.dispose();
