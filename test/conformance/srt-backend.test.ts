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
import {
	existsSync,
	lstatSync,
	mkdirSync,
	mkdtempSync,
	readFileSync,
	realpathSync,
	rmSync,
	symlinkSync,
	writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, dirname, isAbsolute, join, resolve } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { scratchBase } from "../../src/backend/scratch.ts";
import { checkUnixSocketBlocking } from "../../src/backend/self-test.ts";
import { effectiveProfile, partitionSrtDefaults, SrtBackend, toSrtConfig } from "../../src/backend/srt.ts";
import { SandboxDenied } from "../../src/backend/types.ts";
import { formatProbeReport } from "../../src/probe.ts";
import { probeHost } from "../../src/probe-host.ts";
import { createFixture, plantSecrets, SECRET_FILE_CONTENT } from "./fixture.ts";
import { type ConformanceRow, formatRows, runConformance } from "./runner.ts";
import { SCENARIOS, scenarioEnv } from "./scenarios.ts";

// npm prepends this checkout's node_modules/.bin to PATH before starting
// Vitest. Production correctly refuses that host-code lookup path; the native
// conformance harness removes only npm's test-runner injection so it can test
// the sandbox itself under the same safe PATH production requires.
const ambientPath = process.env.PATH;
const checkoutRoot = resolve(process.cwd());
process.env.PATH = (ambientPath ?? "")
	.split(delimiter)
	.filter((entry) => {
		if (!isAbsolute(entry)) return false;
		const resolved = resolve(entry);
		return resolved !== checkoutRoot && !resolved.startsWith(`${checkoutRoot}/`);
	})
	.join(delimiter);
afterAll(() => {
	if (ambientPath === undefined) delete process.env.PATH;
	else process.env.PATH = ambientPath;
});

const report = probeHost("1.5.2");

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

	it("resolves a symlinked deny entry the way each backend needs", () => {
		// Seatbelt matches canonical paths, so the link alone denies nothing;
		// bwrap aborts at startup if asked to mask the link itself. macOS gets
		// both spellings, Linux gets the target only.
		const dir = mkdtempSync(join(tmpdir(), "enclave-denylink-"));
		const target = join(dir, "real");
		const link = join(dir, "link");
		mkdirSync(target);
		symlinkSync(target, link);
		try {
			const base = { ...requested, readDeny: [link] };
			const canonical = realpathSync(target);
			expect(toSrtConfig(base, false, "darwin").filesystem.denyRead).toEqual([link, canonical]);
			expect(toSrtConfig(base, false, "linux").filesystem.denyRead).toEqual([canonical]);
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	});

	it("treats /private/tmp/claude as an alias only on macOS", () => {
		// On macOS /private/tmp is /tmp, so both SRT defaults are the advertised
		// root. On Linux /private/tmp/claude is a separate directory SRT would
		// make writable if it existed; folding it into the alias would leave it
		// writable and unadvertised.
		const mac = partitionSrtDefaults(["/tmp/claude"], "darwin");
		expect(mac.advertised.sort()).toEqual(["/private/tmp/claude", "/tmp/claude"]);
		const linux = partitionSrtDefaults(["/tmp/claude"], "linux");
		expect(linux.advertised).toEqual(["/tmp/claude"]);
		expect(linux.denied).toContain("/private/tmp/claude");
		expect(toSrtConfig(effectiveProfile(requested, "linux"), false, "linux").filesystem.denyWrite).toContain(
			"/private/tmp/claude",
		);
	});

	it("advertises the temp directory the child is actually given", () => {
		// The backend pins SRT's injected TMPDIR to its own session scratch
		// (#20), so that is the root the profile must advertise, and SRT's fixed
		// default /tmp/claude falls into the explicitly denied set.
		const scratch = "/run/user/1000/pi-enclave-1000/session-1-abc";
		const profile = effectiveProfile(requested, process.platform, process.env, scratch);
		expect(profile.writableRoots).toContain(scratch);
		expect(profile.tmpDir).toBe(scratch);
		const { denied } = partitionSrtDefaults(profile.writableRoots);
		expect(denied).not.toContain(scratch);
		expect(denied).toContain("/tmp/claude");
		expect(toSrtConfig(profile).filesystem.allowWrite).toEqual(["/tmp/ws", scratch]);
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

describe.skipIf(!supported || process.platform !== "linux")("session-start Unix-socket self-test (#34)", () => {
	it("refuses socket(AF_UNIX) inside the compiled sandbox on this host", async () => {
		// compile() already ran this probe and would have thrown on failure; it
		// is repeated here so the CI row shows the verdict and the errno, and so
		// a compile() that stopped running it would still leave this assertion.
		// The unsandboxed control is in falsifiability.test.ts.
		const backend = new SrtBackend({ weakerNestedSandbox: weakerNested });
		const fixture = createFixture();
		try {
			const compiled = await backend.compile(fixture.profile);
			const result = await checkUnixSocketBlocking(backend, compiled, {
				cwd: fixture.workspace,
				env: scenarioEnv(fixture),
			});
			console.info(`unix-socket self-test: ${result.detail}`);
			expect(result.ok, result.detail).toBe(true);
			expect(result.detail).toMatch(/EPERM|EACCES/);
		} finally {
			await backend.dispose();
			fixture.cleanup();
		}
	}, 60_000);
});

describe.skipIf(!supported)("per-session scratch directory (#20)", () => {
	it("gives the child a private TMPDIR, keeps /tmp/claude unwritable, and removes the directory on dispose", async () => {
		const first = new SrtBackend({ weakerNestedSandbox: weakerNested });
		const second = new SrtBackend({ weakerNestedSandbox: weakerNested });
		const fixture = createFixture();
		const probe = `/tmp/claude/pi-enclave-scratch-probe-${process.pid}`;
		let scratch: string | undefined;
		try {
			const compiled = await first.compile(fixture.profile);
			scratch = first.scratchDir;
			expect(scratch).toBeDefined();
			expect(compiled.profile.tmpDir).toBe(scratch);
			expect(compiled.profile.writableRoots).toContain(scratch);
			expect(compiled.profile.writableRoots).not.toContain("/tmp/claude");
			const stats = lstatSync(scratch ?? "");
			expect(stats.isDirectory() && !stats.isSymbolicLink()).toBe(true);
			expect(stats.mode & 0o777).toBe(0o700);
			expect(scratch?.startsWith(realpathSync(dirname(scratchBase())))).toBe(true);

			let output = "";
			await first.run(compiled, {
				command:
					`printf 'TMPDIR=%s\\n' "$TMPDIR"; f=$(mktemp) && printf ok > "$f" && echo MKTEMP-OK; ` +
					`mkdir -p /tmp/claude 2>/dev/null; printf leak > ${JSON.stringify(probe)} 2>/dev/null; true`,
				cwd: fixture.workspace,
				env: scenarioEnv(fixture),
				commandId: "scratch-tmpdir-1",
				onData: (chunk) => {
					output += chunk.toString("utf8");
				},
			});
			expect(output).toContain(`TMPDIR=${scratch}`);
			expect(output).toContain("MKTEMP-OK");
			expect(existsSync(probe), "the shared /tmp/claude was writable from the sandbox").toBe(false);

			await second.compile(fixture.profile);
			expect(second.scratchDir).toBeDefined();
			expect(second.scratchDir).not.toBe(scratch);
		} finally {
			await second.dispose();
			await first.dispose();
			rmSync(probe, { force: true });
			fixture.cleanup();
		}
		expect(existsSync(scratch ?? ""), "the scratch directory survived dispose").toBe(false);
	}, 60_000);
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

describe.skipIf(!supported)("invocation-scoped write capability", () => {
	it.skipIf(process.platform === "darwin")(
		"widens exactly one call and does not leak the grant to the next call",
		async () => {
			const backend = new SrtBackend({ weakerNestedSandbox: weakerNested });
			const fixture = createFixture();
			try {
				const compiled = await backend.compile(fixture.profile);
				await backend.run(compiled, {
					command: `printf capability > ${JSON.stringify(fixture.outsideFile)}`,
					cwd: fixture.workspace,
					env: { PATH: process.env.PATH ?? "" },
					commandId: "write-capability-1",
					writeCapability: fixture.outsideFile,
				});
				expect(readFileSync(fixture.outsideFile, "utf8")).toBe("capability");

				await backend.run(compiled, {
					command: `printf leaked > ${JSON.stringify(fixture.outsideFile)}`,
					cwd: fixture.workspace,
					env: { PATH: process.env.PATH ?? "" },
					commandId: "write-capability-base-sibling",
				});
				expect(readFileSync(fixture.outsideFile, "utf8")).toBe("capability");
			} finally {
				await backend.dispose();
				fixture.cleanup();
			}
		},
		60_000,
	);

	it.skipIf(process.platform !== "darwin")(
		"refuses a Bash grant that a detached Seatbelt child could retain",
		async () => {
			const backend = new SrtBackend();
			const fixture = createFixture();
			try {
				const compiled = await backend.compile(fixture.profile);
				await expect(
					backend.run(compiled, {
						command: "true",
						cwd: fixture.workspace,
						env: { PATH: process.env.PATH ?? "" },
						commandId: "macos-detached-write-capability",
						writeCapability: fixture.outsideFile,
					}),
				).rejects.toThrow(/could outlive the invocation/);
			} finally {
				await backend.dispose();
				fixture.cleanup();
			}
		},
		60_000,
	);

	it.skipIf(process.platform === "darwin")(
		"refuses a write capability inside or above a read-denied credential root",
		async () => {
			// macOS refuses every Bash write capability before profile widening; the
			// adjacent native test covers that stronger platform boundary. This case
			// exercises the overlap check on Linux, where capabilities are supported.
			const backend = new SrtBackend({ weakerNestedSandbox: weakerNested });
			const fixture = createFixture();
			try {
				const compiled = await backend.compile(fixture.profile);
				for (const target of [join(fixture.deniedHome, "out"), dirname(fixture.deniedHome)]) {
					await expect(
						backend.run(compiled, {
							command: "true",
							cwd: fixture.workspace,
							env: { PATH: process.env.PATH ?? "" },
							commandId: `denied-write-capability-${target.length}`,
							writeCapability: target,
						}),
					).rejects.toThrow(/immutable denied path/);
				}
			} finally {
				await backend.dispose();
				fixture.cleanup();
			}
		},
		60_000,
	);
});

describe.skipIf(!supported)("invocation-scoped read capability", () => {
	it("isolates a streaming read grant from its sibling and revokes it on cancellation", async () => {
		const backend = new SrtBackend({ weakerNestedSandbox: weakerNested });
		const fixture = createFixture();
		try {
			const path = join(fixture.deniedHome, ".ssh", "id_ed25519");
			writeFileSync(path, SECRET_FILE_CONTENT.repeat(8_192));
			const compiled = await backend.compile(fixture.profile);
			const base = backend.fs(compiled);
			const lease = await backend.fsWithReadCapability(compiled, fixture.deniedHome, "stream-grant", fixture.workspace);
			const controller = new AbortController();
			const granted = lease.client.createReadStream(path, { signal: controller.signal })[Symbol.asyncIterator]();
			const sibling = base.createReadStream(path)[Symbol.asyncIterator]();
			try {
				const first = await granted.next();
				expect(Buffer.from(first.value ?? []).toString()).toContain(SECRET_FILE_CONTENT);
				await expect(sibling.next()).rejects.toBeInstanceOf(SandboxDenied);
				controller.abort();
				await expect(granted.next()).rejects.toThrow(/abort/i);
			} finally {
				await granted.return?.();
				await sibling.return?.();
				await lease.dispose();
			}
			await expect(lease.client.createReadStream(path)[Symbol.asyncIterator]().next()).rejects.toThrow("shut down");
			await expect(base.createReadStream(path)[Symbol.asyncIterator]().next()).rejects.toBeInstanceOf(SandboxDenied);
		} finally {
			await backend.dispose();
			fixture.cleanup();
		}
	}, 60_000);

	it("uses an ephemeral file helper without widening an overlapping base helper", async () => {
		const backend = new SrtBackend({ weakerNestedSandbox: weakerNested });
		const fixture = createFixture();
		try {
			const compiled = await backend.compile(fixture.profile);
			const deniedFile = join(fixture.deniedHome, ".ssh", "id_ed25519");
			const base = backend.fs(compiled);
			const lease = await backend.fsWithReadCapability(
				compiled,
				fixture.deniedHome,
				"sha256:read-capability",
				fixture.workspace,
			);
			try {
				const [widened, ordinary] = await Promise.allSettled([
					lease.client.readFile(deniedFile),
					base.readFile(deniedFile),
				]);
				expect(widened.status).toBe("fulfilled");
				if (widened.status === "fulfilled") expect(widened.value.toString()).toContain(SECRET_FILE_CONTENT);
				expect(ordinary.status).toBe("rejected");
				if (ordinary.status === "rejected") expect(ordinary.reason).toBeInstanceOf(SandboxDenied);
			} finally {
				await lease.dispose();
			}

			await expect(base.readFile(deniedFile)).rejects.toBeInstanceOf(SandboxDenied);
		} finally {
			await backend.dispose();
			fixture.cleanup();
		}
	}, 60_000);

	it.skipIf(process.platform === "darwin")(
		"widens one Bash call and not its sibling",
		async () => {
			const backend = new SrtBackend({ weakerNestedSandbox: weakerNested });
			const fixture = createFixture();
			try {
				const compiled = await backend.compile(fixture.profile);
				const deniedFile = join(fixture.deniedHome, ".ssh", "id_ed25519");
				let widened = "";
				await backend.run(compiled, {
					command: `cat ${JSON.stringify(deniedFile)}`,
					cwd: fixture.workspace,
					env: { PATH: process.env.PATH ?? "" },
					commandId: "read-capability-shell",
					readCapability: fixture.deniedHome,
					onData: (chunk) => {
						widened += chunk.toString();
					},
				});
				expect(widened).toContain(SECRET_FILE_CONTENT);

				let ordinary = "";
				await backend.run(compiled, {
					command: `cat ${JSON.stringify(deniedFile)}`,
					cwd: fixture.workspace,
					env: { PATH: process.env.PATH ?? "" },
					commandId: "read-capability-shell-sibling",
					onData: (chunk) => {
						ordinary += chunk.toString();
					},
				});
				expect(ordinary).not.toContain(SECRET_FILE_CONTENT);
			} finally {
				await backend.dispose();
				fixture.cleanup();
			}
		},
		60_000,
	);

	it.skipIf(process.platform !== "darwin")(
		"refuses a Bash grant whose process lifetime cannot be bounded",
		async () => {
			const backend = new SrtBackend();
			const fixture = createFixture();
			try {
				const compiled = await backend.compile(fixture.profile);
				await expect(
					backend.run(compiled, {
						command: "true",
						cwd: fixture.workspace,
						env: { PATH: process.env.PATH ?? "" },
						commandId: "macos-read-capability",
						readCapability: fixture.deniedHome,
					}),
				).rejects.toThrow(/could outlive the invocation/);
			} finally {
				await backend.dispose();
				fixture.cleanup();
			}
		},
		60_000,
	);
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

describe.skipIf(!supported || process.platform !== "darwin")("macOS process lifecycle", () => {
	it("reaps a descriptor-closed background descendant when the foreground command succeeds", async () => {
		const backend = new SrtBackend();
		const fixture = createFixture();
		const sentinel = join(fixture.workspace, "background-survived");
		try {
			const compiled = await backend.compile(fixture.profile);
			await backend.run(compiled, {
				command: `(sleep 0.4; printf survived > ${JSON.stringify(sentinel)}) </dev/null >/dev/null 2>&1 &`,
				cwd: fixture.workspace,
				env: { PATH: process.env.PATH ?? "" },
				commandId: "background-reap-1",
			});
			await new Promise((resolve) => setTimeout(resolve, 700));
			expect(existsSync(sentinel), "a process from a completed sandbox action was still running").toBe(false);
		} finally {
			await backend.dispose();
			fixture.cleanup();
		}
	}, 60_000);
});

describe.skipIf(supported)("conformance skipped", () => {
	it("explains why", () => {
		console.log(`conformance skipped on ${process.platform}:\n${formatProbeReport(report)}`);
		expect(true).toBe(true);
	});
});
