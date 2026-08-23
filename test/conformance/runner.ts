/**
 * Runs the scenario list against a backend and reports structured results.
 *
 * Deliberately does not assert. Returning results rather than calling `expect`
 * lets the same suite serve two purposes: a real backend must pass every row,
 * and the unsandboxed `NoopBackend` must *fail* every denial row. A suite that
 * asserted internally could only express the first, and would never notice if
 * it had quietly become unfalsifiable.
 */
import type { CompiledProfile, SandboxBackend } from "../../src/backend/types.ts";
import { dedupeViolations } from "../../src/backend/violations.ts";
import type { Fixture } from "./fixture.ts";
import { SCENARIOS, type Scenario, type ScenarioContext, type ShellOutcome, scenarioEnv } from "./scenarios.ts";

export interface ConformanceRow {
	id: string;
	title: string;
	surface: Scenario["surface"];
	expectation: Scenario["expectation"];
	falsifiableByNoop: boolean;
	/** True when the sandbox behaved as the scenario requires. */
	ok: boolean;
	detail: string;
	/** Populated when the scenario threw rather than reaching a verdict. */
	error?: string;
}

export interface RunOptions {
	/** Include scenarios that need the filesystem helper (step 6). */
	includeFs?: boolean;
	/** Restrict to specific scenario ids. */
	only?: readonly string[];
	/**
	 * Override the child environment. Used only by the falsifiability control
	 * that checks the env scenario fails when credentials are not stripped.
	 */
	envOverride?: (fixture: Fixture) => Readonly<Record<string, string>>;
}

/**
 * Run the scenarios, each against a **freshly built fixture**.
 *
 * Per-scenario isolation is not tidiness. On a backend that enforces nothing,
 * the symlink-write scenario really does overwrite its target -- which is the
 * correct result for that row, and silently broke the later row that reads the
 * same file. Shared state between security scenarios turns one row's success
 * into another's false failure, so every scenario gets its own world.
 */
export async function runConformance(
	backend: SandboxBackend,
	makeFixture: () => Fixture,
	options: RunOptions = {},
): Promise<ConformanceRow[]> {
	const { includeFs = false, only, envOverride } = options;

	const selected = SCENARIOS.filter(
		(scenario) => (includeFs || scenario.surface !== "fs") && (!only || only.includes(scenario.id)),
	);

	const rows: ConformanceRow[] = [];
	let counter = 0;

	for (const scenario of selected) {
		const fixture = makeFixture();
		const compiled: CompiledProfile = await backend.compile(fixture.profile);
		const env = envOverride ? envOverride(fixture) : scenarioEnv(fixture);

		const sh = async (command: string): Promise<ShellOutcome> => {
			// A unique id per invocation: sandbox-runtime attributes violations by
			// this key and compares only the first 100 characters, so reusing the
			// command text would cross-attribute between similar scenarios.
			const commandId = `conformance-${scenario.id}-${++counter}`;
			const chunks: Buffer[] = [];
			const result = await backend.run(compiled, {
				command,
				cwd: fixture.workspace,
				env,
				commandId,
				timeout: 30,
				onData: (chunk) => chunks.push(chunk),
			});
			return {
				exitCode: result.exitCode,
				output: Buffer.concat(chunks).toString("utf8"),
				violationKinds: dedupeViolations(result.violations).map((v) => v.kind),
			};
		};

		const context: ScenarioContext = { backend, compiled, fixture, sh };
		try {
			const outcome = await scenario.run(context);
			rows.push({
				id: scenario.id,
				title: scenario.title,
				surface: scenario.surface,
				expectation: scenario.expectation,
				falsifiableByNoop: scenario.falsifiableByNoop,
				ok: outcome.ok,
				detail: outcome.detail,
			});
		} catch (error) {
			// A scenario that throws is a failure, never a pass. The most dangerous
			// bug in a security suite is one where an error is mistaken for silence.
			rows.push({
				id: scenario.id,
				title: scenario.title,
				surface: scenario.surface,
				expectation: scenario.expectation,
				falsifiableByNoop: scenario.falsifiableByNoop,
				ok: false,
				detail: "scenario threw before reaching a verdict",
				error: error instanceof Error ? error.message : String(error),
			});
		} finally {
			fixture.cleanup();
		}
	}

	return rows;
}

/** Render rows for a failure message or a CI log. */
export function formatRows(rows: readonly ConformanceRow[]): string {
	return rows
		.map((row) => `  ${row.ok ? "PASS" : "FAIL"} ${row.id} ${row.title}\n       ${row.error ?? row.detail}`)
		.join("\n");
}
