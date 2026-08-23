/**
 * Print the conformance table for a backend.
 *
 * Defaults to the unsandboxed NoopBackend, which is the falsifiability control:
 * every falsifiable denial row must read FAIL. Steps 4-5 point this at the real
 * backends, where every row must read PASS.
 */
import { SrtBackend } from "../src/backend/srt.ts";
import type { SandboxBackend } from "../src/backend/types.ts";
import { createFixture, plantSecrets } from "../test/conformance/fixture.ts";
import { NoopBackend } from "../test/conformance/noop-backend.ts";
import { runConformance } from "../test/conformance/runner.ts";

const which = process.argv[2] ?? "noop";
// PI_ENCLAVE_WEAKER_NESTED exists for running this suite inside a container,
// where capability-bearing user namespaces are unavailable. It weakens the
// boundary, so the report says so on its first line.
const weaker = process.env.PI_ENCLAVE_WEAKER_NESTED === "1";
const backend: SandboxBackend = which === "srt" ? new SrtBackend({ weakerNestedSandbox: weaker }) : new NoopBackend();

const restore = plantSecrets();
const started = Date.now();
// The helper rows run against both: a real backend must pass them, and the
// noop backend's fs client is the real filesystem, so it must leak through them.
const rows = await runConformance(backend, createFixture, { includeFs: true });
const elapsed = Date.now() - started;
restore();
await backend.dispose();

const width = Math.max(...rows.map((r) => r.title.length));
const heading =
	which === "srt"
		? `${backend.name} (sandbox-runtime)${weaker ? " -- WEAKER NESTED MODE: capabilities are not dropped" : ""}`
		: "noop (enforces nothing)";
console.log(`backend: ${heading}  [${elapsed}ms]\n`);
for (const row of rows) {
	const verdict = row.ok ? "PASS" : "FAIL";
	const expected =
		which === "srt"
			? "must PASS"
			: row.expectation === "denied"
				? row.falsifiableByNoop
					? "must FAIL"
					: "exempt"
				: "must PASS";
	console.log(`  ${verdict}  ${row.id.padEnd(4)} ${row.title.padEnd(width)}  [${expected}]`);
	console.log(`        ${row.detail}`);
}

// A real backend must pass every row. The noop control must fail every
// falsifiable denial row and pass the rest.
const wrong =
	which === "srt"
		? rows.filter((r) => !r.ok)
		: rows.filter((r) =>
				r.expectation === "denied" && r.falsifiableByNoop ? r.ok : r.expectation === "allowed" ? !r.ok : false,
			);
console.log(`\n${wrong.length === 0 ? "OK" : `WRONG: ${wrong.map((r) => r.id).join(", ")}`}`);
process.exit(wrong.length === 0 ? 0 : 1);
