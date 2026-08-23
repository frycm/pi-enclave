/**
 * The conformance suite against the real sandbox-runtime backend.
 *
 * Every row must pass. The falsifiability meta-test is what makes that
 * meaningful: it proves each of these rows fails when nothing is enforced, so a
 * green run here is evidence of a boundary rather than evidence of a weak test.
 *
 * Runs on macOS (seatbelt) and Linux (bwrap) alike -- one backend implementation
 * serves both. Skipped elsewhere, and skipped when the host cannot give
 * bubblewrap a capability-bearing user namespace, which `probe()` reports with
 * the sysctl remediation rather than letting every row fail obscurely.
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { SrtBackend, toSrtConfig, UNADVERTISED_WRITE_PATHS } from "../../src/backend/srt.ts";
import { formatProbeReport } from "../../src/probe.ts";
import { probeHost } from "../../src/probe-host.ts";
import { createFixture, plantSecrets } from "./fixture.ts";
import { type ConformanceRow, formatRows, runConformance } from "./runner.ts";
import { SCENARIOS } from "./scenarios.ts";

const report = probeHost("0.84.2");
// A host that cannot support the sandbox produces N identical failures with no
// common explanation. Skip with the probe's own diagnosis instead.
const supported = report.ok && (process.platform === "darwin" || process.platform === "linux");

describe.skipIf(!supported)("conformance: sandbox-runtime backend", () => {
	let backend: SrtBackend;
	let restoreSecrets: () => void;
	let rows: ConformanceRow[];

	beforeAll(async () => {
		restoreSecrets = plantSecrets();
		backend = new SrtBackend();
		rows = await runConformance(backend, createFixture);
	}, 300_000);

	afterAll(async () => {
		await backend?.dispose();
		restoreSecrets?.();
	});

	it("passes every row", () => {
		const failed = rows.filter((row) => !row.ok);
		expect(failed, `\n${formatRows(rows)}`).toEqual([]);
	});

	it("runs every non-fs scenario", () => {
		expect(rows.map((r) => r.id)).toEqual(SCENARIOS.filter((s) => s.surface !== "fs").map((s) => s.id));
	});

	// Individual rows, so a failure names the boundary that broke rather than
	// reporting "conformance failed".
	for (const scenario of SCENARIOS.filter((s) => s.surface !== "fs")) {
		it(`${scenario.id}: ${scenario.title}`, () => {
			const row = rows.find((r) => r.id === scenario.id);
			expect(row, `${scenario.id} did not run`).toBeDefined();
			expect(row?.ok, row?.error ?? row?.detail).toBe(true);
		});
	}
});

describe.skipIf(!supported)("sandbox-runtime profile translation", () => {
	it("denies the write paths sandbox-runtime grants but pi-enclave does not advertise", () => {
		// getDefaultWritePaths() unions ~/.npm/_logs and ~/.claude/debug into every
		// profile. A sandbox that can write those is wider than the status line
		// claims, and ~/.claude/debug sits beside configuration that steers another
		// agent.
		const config = toSrtConfig({
			mode: "workspace-write",
			writableRoots: ["/tmp/ws"],
			readDeny: [],
			network: "off",
			allowPty: true,
		});
		expect(config.filesystem.denyWrite).toEqual(UNADVERTISED_WRITE_PATHS);
		expect(config.filesystem.allowWrite).toEqual(["/tmp/ws"]);
	});

	it("allowlists no host when the profile is offline", () => {
		const config = toSrtConfig({
			mode: "workspace-write",
			writableRoots: [],
			readDeny: [],
			network: "off",
			allowPty: false,
		});
		expect(config.network.allowedDomains).toEqual([]);
	});
});

describe.skipIf(!supported)("stale profile guard", () => {
	it("refuses to run against a profile the manager no longer holds", async () => {
		// sandbox-runtime is process-global: wrapWithSandboxArgv reads the
		// manager's current configuration and ignores whatever CompiledProfile the
		// caller passed. Without this guard, holding on to an older profile would
		// silently execute under the newer -- possibly wider -- one.
		const backend = new SrtBackend();
		const fixture = createFixture();
		try {
			const first = await backend.compile(fixture.profile);
			// A second compile replaces the manager's configuration.
			await backend.compile({ ...fixture.profile, writableRoots: [] });

			await expect(
				backend.run(first, { command: "true", cwd: fixture.workspace, env: {}, commandId: "stale-1" }),
			).rejects.toThrow(/stale profile/);
		} finally {
			await backend.dispose();
			fixture.cleanup();
		}
	}, 60_000);

	it("rejects a profile compiled by something else entirely", async () => {
		const backend = new SrtBackend();
		try {
			await expect(
				backend.run(
					{ backend: "seatbelt", profile: createFixture().profile, describe: () => "forged" },
					{ command: "true", cwd: process.cwd(), env: {}, commandId: "forged-1" },
				),
			).rejects.toThrow(/only run profiles it compiled itself/);
		} finally {
			await backend.dispose();
		}
	});
});

describe.skipIf(supported)("conformance skipped", () => {
	it("explains why", () => {
		console.log(`conformance skipped on ${process.platform}:\n${formatProbeReport(report)}`);
		expect(true).toBe(true);
	});
});
