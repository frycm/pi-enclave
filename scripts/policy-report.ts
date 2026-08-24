/**
 * Print the Phase-2 matrix as a table, with each row's own detail line.
 *
 * The same reasoning as Phase 1's conformance report: a green check tells a
 * reader that a suite passed, and the sign-off should rest on what each row
 * actually observed. The control column is the part worth reading -- a row
 * whose control passed is measuring something other than what it claims.
 */
import { destroyWorld, makeWorld, POLICY_SCENARIOS, type PolicyResult } from "../test/policy/scenarios.ts";

async function attempt(scenario: (typeof POLICY_SCENARIOS)[number], which: "run" | "control"): Promise<PolicyResult> {
	const world = makeWorld();
	try {
		return await scenario[which](world);
	} catch (error) {
		return { ok: false, detail: `threw: ${(error as Error).message}` };
	} finally {
		destroyWorld(world);
	}
}

const rows: string[] = [];
let failures = 0;

for (const scenario of POLICY_SCENARIOS) {
	const result = await attempt(scenario, "run");
	const control = await attempt(scenario, "control");
	// A control that passes is a failure of the *suite*, not of the code under
	// test, and it is reported as loudly as a failing row.
	const falsifiable = !control.ok;
	if (!result.ok || !falsifiable) failures++;

	rows.push(
		[
			`### ${scenario.id} — ${scenario.title}`,
			``,
			`| | |`,
			`|---|---|`,
			`| matrix row | ${scenario.matrixRow} |`,
			`| result | ${result.ok ? "pass" : "**FAIL**"} — ${result.detail} |`,
			`| control | ${falsifiable ? "correctly fails" : "**PASSED, so this row proves nothing**"} — ${control.detail} |`,
			`| control removes | ${scenario.controlNote} |`,
			``,
		].join("\n"),
	);
}

process.stdout.write(`# Phase-2 policy matrix\n\n${POLICY_SCENARIOS.length} rows, each with a control.\n\n`);
process.stdout.write(rows.join("\n"));
process.stdout.write(
	failures === 0
		? "\nEvery row passes and every control fails.\n"
		: `\n**${failures} row(s) did not pass or could not be falsified.**\n`,
);

process.exitCode = failures === 0 ? 0 : 1;
