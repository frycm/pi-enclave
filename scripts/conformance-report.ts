/**
 * Print the conformance table for a backend.
 *
 * Defaults to the unsandboxed NoopBackend, which is the falsifiability control:
 * every falsifiable denial row must read FAIL. Steps 4-5 point this at the real
 * backends, where every row must read PASS.
 */
import { createFixture, plantSecrets } from "../test/conformance/fixture.ts";
import { NoopBackend } from "../test/conformance/noop-backend.ts";
import { runConformance } from "../test/conformance/runner.ts";

const restore = plantSecrets();
const rows = await runConformance(new NoopBackend(), createFixture);
restore();

const width = Math.max(...rows.map((r) => r.title.length));
console.log(`backend: noop (enforces nothing)\n`);
for (const row of rows) {
	const verdict = row.ok ? "PASS" : "FAIL";
	const expected = row.expectation === "denied" ? (row.falsifiableByNoop ? "must FAIL" : "exempt") : "must PASS";
	console.log(`  ${verdict}  ${row.id.padEnd(4)} ${row.title.padEnd(width)}  [${expected}]`);
	console.log(`        ${row.detail}`);
}

const wrong = rows.filter((r) =>
	r.expectation === "denied" && r.falsifiableByNoop ? r.ok : r.expectation === "allowed" ? !r.ok : false,
);
console.log(`\n${wrong.length === 0 ? "control holds" : `CONTROL BROKEN: ${wrong.map((r) => r.id).join(", ")}`}`);
process.exit(wrong.length === 0 ? 0 : 1);
