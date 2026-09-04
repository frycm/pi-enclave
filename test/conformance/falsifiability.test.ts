/**
 * The meta-test: proof that the conformance suite can fail.
 *
 * A security suite that cannot distinguish "enforced" from "not enforced" is
 * worse than no suite, because it reports green either way. This runs every
 * scenario against a backend that deliberately enforces nothing and requires
 * each falsifiable denial row to report a failure.
 *
 * Two denial rows are honestly *not* falsifiable this way, and are marked as
 * such in `scenarios.ts` rather than quietly counted as proof:
 *
 * - **C7 (sudo/su)** holds unsandboxed too, because the test user is not root.
 * - **C9 (environment)** is enforced by `buildChildEnv` inside the pi process
 *   rather than by the kernel, so the noop backend still receives a sanitised
 *   environment. It gets its own control below.
 *
 * Two more are falsifiable only on a host that can run their control, which is
 * decided at the assertion rather than declared in `scenarios.ts`: **C5** needs
 * a host with egress, and **C12** needs a host whose own processes hold
 * capabilities. Both are recorded with the host's measured value so a green row
 * says which of the two it was.
 *
 * When the real backends land in steps 4-5 they run the same scenarios and must
 * pass every row. This file is what makes that meaningful.
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
	createFixture,
	hostCapEff,
	hostHasNetwork,
	hostHasSearchTools,
	hostHoldsCapabilities,
	plantSecrets,
	SECRET_ENV,
} from "./fixture.ts";
import { NoopBackend } from "./noop-backend.ts";
import { type ConformanceRow, formatRows, runConformance } from "./runner.ts";
import { SCENARIOS } from "./scenarios.ts";

describe("conformance suite falsifiability", () => {
	let restoreSecrets: () => void;
	let rows: ConformanceRow[];

	beforeAll(async () => {
		restoreSecrets = plantSecrets();
		// The helper rows too: the noop backend's fs client is the real
		// filesystem, so F1-F3 and F6-F8 must leak through it.
		rows = await runConformance(new NoopBackend(), createFixture, { includeFs: true });
	}, 180_000);

	afterAll(() => {
		restoreSecrets?.();
	});

	it("runs every scenario, helper rows included", () => {
		expect(rows.map((r) => r.id)).toEqual(SCENARIOS.map((s) => s.id));
	});

	it("every falsifiable denial scenario FAILS without a sandbox", () => {
		// C5 can only be falsified where an unsandboxed process would actually
		// reach the internet. On an isolated runner it fails for the wrong reason,
		// which would report the suite as unfalsifiable when the host simply
		// cannot run that control.
		const networkControlAvailable = hostHasNetwork();
		// C12 has the same shape: it can only be falsified where an unsandboxed
		// process holds capabilities to begin with. Under an ordinary unprivileged
		// user -- a GitHub runner -- CapEff is already zero, so the noop backend
		// passes the row without any sandbox being involved. That is a fact about
		// the host, not a suite that stopped testing anything, and the row still
		// separates secure bwrap from the weaker nested mode there.
		const capabilityControlAvailable = hostHoldsCapabilities();
		// F6 and F7 drive rg and fd unsandboxed; without them on the host the
		// search does not happen and the row passes for the wrong reason.
		const searchControlAvailable = hostHasSearchTools();
		const wronglyPassing = rows.filter(
			(row) =>
				row.expectation === "denied" &&
				row.falsifiableByNoop &&
				row.ok &&
				!(row.id === "C5" && !networkControlAvailable) &&
				!(row.id === "C12" && !capabilityControlAvailable) &&
				!((row.id === "F6" || row.id === "F7") && !searchControlAvailable),
		);
		expect(
			wronglyPassing,
			"These passed against a backend that enforces nothing, so they are not testing the " +
				`sandbox:\n${formatRows(wronglyPassing)}`,
		).toEqual([]);
	});

	it("at least one scenario covers each denial category", () => {
		// Guards against a row silently dropping out: nothing fails when a test
		// stops running, so the absence has to be asserted explicitly.
		const ran = new Set(rows.filter((r) => r.expectation === "denied" && r.falsifiableByNoop).map((r) => r.id));
		for (const id of ["C1", "C2", "C2b", "C3", "C4", "C5", "C8", "F1", "F2", "F3", "F8"]) {
			expect(ran.has(id), `${id} is not in the falsifiable denial set`).toBe(true);
		}
	});

	it("the allowed scenarios pass, so a failure there means broken tooling not a weak sandbox", () => {
		// F11 drives fd as an allowed compatibility control. A host without the
		// search prerequisites cannot run that control; CI installs both tools and
		// therefore exercises it, while a developer host reports the exemption
		// alongside F6/F7 instead of turning a missing binary into a product failure.
		const searchControlAvailable = hostHasSearchTools();
		const brokenBaseline = rows.filter(
			(row) => row.expectation === "allowed" && !row.ok && !(row.id === "F11" && !searchControlAvailable),
		);
		expect(
			brokenBaseline,
			"These check ordinary work still functions and should pass even unsandboxed. A failure " +
				"here means the test environment is missing something (git, python3, curl), not that " +
				`the sandbox is wrong:\n${formatRows(brokenBaseline)}`,
		).toEqual([]);
	});

	it("every non-falsifiable row explains why", () => {
		// The escape hatch must stay expensive to use: an unexplained exemption is
		// indistinguishable from a scenario someone silenced to get a green run.
		for (const scenario of SCENARIOS) {
			if (scenario.falsifiableByNoop) continue;
			expect(scenario.falsifiabilityNote, `${scenario.id} is exempt without a note`).toBeTruthy();
		}
	});

	it("records which environment-dependent controls this host could run", () => {
		// An exemption that leaves no trace is how a suite quietly stops proving
		// things. Print what was skipped and why, so a green run on an
		// unprivileged host is not read as stronger evidence than it is.
		const capEff = hostCapEff();
		const notes = [
			`C5 network control: ${hostHasNetwork() ? "ran" : "skipped -- host has no egress"}`,
			`F6/F7/F11 search controls: ${hostHasSearchTools() ? "ran" : "skipped -- rg or fd not on PATH"}`,
			`C12 capability control: ${
				hostHoldsCapabilities()
					? `ran -- host CapEff=${capEff}`
					: capEff === null
						? "skipped -- no capability model on this platform"
						: `skipped -- host holds no capabilities (CapEff=${capEff})`
			}`,
		];
		console.log(`falsifiability controls on this host:\n  ${notes.join("\n  ")}`);
		expect(notes).toHaveLength(3);

		// The row itself must carry the baseline, not just this log line: the
		// conformance report is what a reviewer reads, and "no capabilities" means
		// two different things depending on what the host started with.
		if (process.platform === "linux") {
			expect(rows.find((row) => row.id === "C12")?.detail).toContain("host CapEff=");
		}
	});

	it("reports a usable detail for every row", () => {
		for (const row of rows) {
			expect(row.detail.length, row.id).toBeGreaterThan(0);
		}
	});
});

describe("C9 control: the environment scenario fails when credentials are not stripped", () => {
	let restoreSecrets: () => void;

	beforeAll(() => {
		restoreSecrets = plantSecrets();
	});
	afterAll(() => restoreSecrets?.());

	it("detects a leak when the raw parent environment is passed through", async () => {
		// C9 cannot be falsified by removing the sandbox, because the boundary it
		// tests is buildChildEnv rather than the kernel. So falsify the thing it
		// actually tests: hand the child `process.env` -- which is precisely what
		// pi's own sandbox example does, and what SRT returns -- and require the
		// scenario to catch it.
		const rows = await runConformance(new NoopBackend(), createFixture, {
			only: ["C9"],
			envOverride: () => process.env as Record<string, string>,
		});

		expect(rows).toHaveLength(1);
		expect(
			rows[0]?.ok,
			"C9 passed even with the parent environment passed straight through, so it is not " +
				"detecting credential leaks at all",
		).toBe(false);
		expect(rows[0]?.detail).toContain("LEAKED");
	}, 60_000);

	it("passes once buildChildEnv is in the path", async () => {
		const rows = await runConformance(new NoopBackend(), createFixture, { only: ["C9"] });
		expect(rows[0]?.ok, rows[0]?.detail).toBe(true);
	}, 60_000);

	it("plants credentials the scenario could actually find", () => {
		// If the fixture stopped setting these, C9 would pass vacuously.
		for (const [name, value] of Object.entries(SECRET_ENV)) {
			expect(process.env[name], name).toBe(value);
		}
	});
});
