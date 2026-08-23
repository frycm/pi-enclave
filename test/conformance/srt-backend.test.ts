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
import { effectiveProfile, partitionSrtDefaults, SrtBackend, srtTmpDir, toSrtConfig } from "../../src/backend/srt.ts";
import { formatProbeReport } from "../../src/probe.ts";
import { probeHost } from "../../src/probe-host.ts";
import { createFixture, plantSecrets } from "./fixture.ts";
import { type ConformanceRow, formatRows, runConformance } from "./runner.ts";
import { SCENARIOS } from "./scenarios.ts";

const report = probeHost("0.84.2");

/**
 * Inside a container, capability-bearing user namespaces are unavailable and
 * sandbox-runtime's weaker nested mode is the only way to run at all. It is an
 * explicit opt-in, never inferred: see SrtBackendOptions.weakerNestedSandbox.
 */
const weakerNested = process.env.PI_ENCLAVE_WEAKER_NESTED === "1";

// A host that cannot support the sandbox produces N identical failures with no
// common explanation. Skip with the probe's own diagnosis instead -- except when
// the only failing check is namespace nesting and weaker mode was requested,
// which is precisely the case that mode exists for.
const blocking = report.checks.filter(
	(check) => check.status === "fail" && !(weakerNested && check.id === "linux-namespace-nesting"),
);
const supported = blocking.length === 0 && (process.platform === "darwin" || process.platform === "linux");

describe.skipIf(!supported)("conformance: sandbox-runtime backend", () => {
	let backend: SrtBackend;
	let restoreSecrets: () => void;
	let rows: ConformanceRow[];

	beforeAll(async () => {
		restoreSecrets = plantSecrets();
		backend = new SrtBackend({ weakerNestedSandbox: weakerNested });
		rows = await runConformance(backend, createFixture, { includeFs: true });
	}, 300_000);

	afterAll(async () => {
		await backend?.dispose();
		restoreSecrets?.();
	});

	/**
	 * C12 asserts the sandboxed process holds no capabilities, which is exactly
	 * what weaker nested mode gives up. In that mode it must fail: making it pass
	 * would hide the weakening, and leaving the suite red would train everyone to
	 * ignore a failing security run. So both directions are asserted.
	 */
	const CAPABILITY_ROW = "C12";

	it("passes every row", () => {
		const expectedFailures = weakerNested ? [CAPABILITY_ROW] : [];
		const failed = rows.filter((row) => !row.ok && !expectedFailures.includes(row.id));
		expect(failed, `\n${formatRows(rows)}`).toEqual([]);
	});

	it.skipIf(!weakerNested)("reports the capability row as failing in weaker nested mode", () => {
		// The weakening must be visible in the run, not only in the docs.
		const row = rows.find((r) => r.id === CAPABILITY_ROW);
		expect(row?.ok, "weaker nested mode kept capabilities but C12 passed; the row has stopped detecting it").toBe(
			false,
		);
		expect(row?.detail).toMatch(/HOLDS CAPABILITIES/);
	});

	it("runs every scenario, including the filesystem helper", () => {
		expect(rows.map((r) => r.id)).toEqual(SCENARIOS.map((s) => s.id));
	});

	// Individual rows, so a failure names the boundary that broke rather than
	// reporting "conformance failed".
	for (const scenario of SCENARIOS) {
		it.skipIf(weakerNested && scenario.id === CAPABILITY_ROW)(`${scenario.id}: ${scenario.title}`, () => {
			const row = rows.find((r) => r.id === scenario.id);
			expect(row, `${scenario.id} did not run`).toBeDefined();
			expect(row?.ok, row?.error ?? row?.detail).toBe(true);
		});
	}
});

describe.skipIf(!supported)("sandbox-runtime profile translation", () => {
	const requested = {
		mode: "workspace-write" as const,
		writableRoots: ["/tmp/ws"],
		readDeny: [],
		network: "off" as const,
		allowPty: true,
	};

	it("represents every non-device sandbox-runtime default explicitly", () => {
		// getDefaultWritePaths() unions paths into every profile -- ~/.npm/_logs,
		// ~/.claude/debug, and the /tmp/claude the child's TMPDIR is pointed at. A
		// sandbox that can write something the status line does not mention is
		// wider than advertised, so each default must be either an advertised root
		// or an explicit deny. Computed from SRT's list, not a hand-kept copy, so a
		// new default in a future SRT lands in the denied set rather than nowhere.
		const profile = effectiveProfile(requested);
		const config = toSrtConfig(profile);
		const { advertised, devices, denied } = partitionSrtDefaults(profile.writableRoots);
		for (const path of devices) expect(path).toMatch(/^\/dev\//);
		expect(config.filesystem.denyWrite).toEqual(denied);
		expect(denied.length + advertised.length + devices.length).toBeGreaterThan(devices.length);
		expect(denied.some((p) => p.endsWith("/.claude/debug"))).toBe(true);
		expect(denied.some((p) => p.endsWith("/.npm/_logs"))).toBe(true);
	});

	it("advertises the temp directory the child is actually given", () => {
		// SRT injects TMPDIR=/tmp/claude and makes it writable regardless of the
		// profile. Denying it would leave the child with an unwritable TMPDIR;
		// omitting it would describe a narrower boundary than the real one.
		const profile = effectiveProfile(requested);
		expect(profile.writableRoots).toContain(srtTmpDir());
		const { denied } = partitionSrtDefaults(profile.writableRoots);
		expect(denied.filter((p) => p.endsWith("/tmp/claude"))).toEqual([]);
		expect(toSrtConfig(profile).filesystem.allowWrite).toEqual(["/tmp/ws", srtTmpDir()]);
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

describe.skipIf(!supported)("pty policy", () => {
	it("carries allowPty: false through to the kernel where the backend can", async () => {
		// The inverse of C6. Seatbelt denies PTYs unless the profile allows them,
		// so the translation must carry the field in both directions -- a profile
		// that always allowed PTYs would pass C6 too. bubblewrap never restricts
		// PTYs (sandbox-runtime documents allowPty as macOS-only), and the compiled
		// profile must say so rather than claim a restriction that is not there.
		const backend = new SrtBackend({ weakerNestedSandbox: weakerNested });
		const fixture = createFixture();
		try {
			const compiled = await backend.compile({ ...fixture.profile, allowPty: false });
			let output = "";
			// The marker is assembled at runtime so a traceback that quotes the
			// source line cannot contain it.
			await backend.run(compiled, {
				command: `python3 -c "import pty,os; m,s=pty.openpty(); print('PTY-'+'OK')" 2>&1 || echo PTY-DENIED`,
				cwd: fixture.workspace,
				env: { PATH: process.env.PATH ?? "" },
				commandId: "pty-off-1",
				onData: (chunk) => {
					output += chunk.toString("utf8");
				},
			});
			if (process.platform === "linux") {
				expect(
					compiled.profile.allowPty,
					"bwrap cannot deny PTYs; the compiled profile must say they are allowed",
				).toBe(true);
				expect(output).toContain("PTY-OK");
			} else {
				expect(compiled.profile.allowPty).toBe(false);
				expect(output, "a PTY was allocated under allowPty: false").not.toContain("PTY-OK");
				expect(output).toContain("PTY-DENIED");
			}
		} finally {
			await backend.dispose();
			fixture.cleanup();
		}
	}, 60_000);
});

describe.skipIf(!supported)("stale profile guard", () => {
	it("refuses to run against a profile the manager no longer holds", async () => {
		// sandbox-runtime is process-global: wrapWithSandboxArgv reads the
		// manager's current configuration and ignores whatever CompiledProfile the
		// caller passed. Without this guard, holding on to an older profile would
		// silently execute under the newer -- possibly wider -- one.
		const backend = new SrtBackend({ weakerNestedSandbox: weakerNested });
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
		const backend = new SrtBackend({ weakerNestedSandbox: weakerNested });
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
