/**
 * Measure the filesystem helper.
 *
 * Phase 1's exit criteria require read latency through the helper to be measured
 * rather than assumed: routing every file operation through another process is
 * the design's main performance cost, and "probably fine" is not a number.
 */
import { mkdtempSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { SrtBackend } from "../src/backend/srt.ts";
import { createDevProfile } from "../src/config/profile.ts";
import { sanitizeVerificationPath } from "./test-path.ts";

sanitizeVerificationPath();

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

// The comparison that matters: what routing through the sandbox costs versus
// doing the same operation directly in this process, which is what pi's own
// tools do. A ratio is more useful than an absolute number, since it is the
// part a faster machine will not improve away.
console.log("\n  vs. direct (unsandboxed) in this process:");

async function compare(label: string, iterations: number, sandboxed: () => Promise<unknown>, direct: () => unknown) {
	await sandboxed();
	direct();
	const t0 = process.hrtime.bigint();
	for (let i = 0; i < iterations; i++) await sandboxed();
	const sandboxMs = Number(process.hrtime.bigint() - t0) / 1e6 / iterations;
	const t1 = process.hrtime.bigint();
	for (let i = 0; i < iterations; i++) direct();
	const directMs = Number(process.hrtime.bigint() - t1) / 1e6 / iterations;
	const overhead = directMs > 0 ? `${(sandboxMs / directMs).toFixed(1)}x` : "n/a";
	console.log(
		`  ${label.padEnd(28)} ${sandboxMs.toFixed(3)} ms vs ${directMs.toFixed(3)} ms direct  (${overhead}, +${(sandboxMs - directMs).toFixed(3)} ms)`,
	);
}

await compare(
	"read 4 KB",
	200,
	() => fs.readFile(small),
	() => readFileSync(small),
);
await compare(
	"read 1 MB",
	50,
	() => fs.readFile(large),
	() => readFileSync(large),
);
await compare(
	"stat",
	200,
	() => fs.stat(workspace),
	() => statSync(workspace),
);

// A realistic search: the whole source tree. Skipped rather than fatal when rg
// is absent -- a benchmark that cannot run one case should still report the
// others, and `probe()` already warns about the missing tool.
const repo = process.env.PI_ENCLAVE_REPO ?? process.cwd();
const rgArgs = ["--json", "--line-number", "--color=never", "--hidden", "--", "export", repo];
try {
	console.log("");
	await bench("grep over the repo", 10, () => fs.grep(rgArgs));
} catch (error) {
	console.log(`  grep over the repo           skipped: ${(error as Error).message}`);
}

await backend.dispose();
