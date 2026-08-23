/**
 * The Phase-1 platform matrix, as executable scenarios.
 *
 * Each scenario asserts the **security property**, not the mechanism: did the
 * secret reach the agent, did the file get written, did the connection open.
 * Exit codes and violation counts are recorded as evidence but never used as
 * the verdict, because step 0 proved neither is portable -- on bwrap a denied
 * read produces no violation at all and an `ENOENT` the shell reports as a
 * missing file, so a suite built on those signals would pass a backend that
 * enforces nothing.
 *
 * A scenario returns `ok: true` when the sandbox behaved correctly. The runner
 * turns that into a pass or a failure; the falsifiability meta-test checks that
 * every `denied` scenario reports `ok: false` against a backend that does not
 * sandbox at all.
 */
import { readFileSync } from "node:fs";
import { join } from "node:path";
import type { CompiledProfile, SandboxBackend, ViolationKind } from "../../src/backend/types.ts";
import { SandboxDenied } from "../../src/backend/types.ts";
import { buildChildEnv } from "../../src/env/child-env.ts";
import { type Fixture, hostCapEff, OUTSIDE_FILE_CONTENT, SECRET_ENV, SECRET_FILE_CONTENT } from "./fixture.ts";

export interface ScenarioContext {
	backend: SandboxBackend;
	compiled: CompiledProfile;
	fixture: Fixture;
	/** Run a shell command in the workspace and collect everything it produced. */
	sh(command: string): Promise<ShellOutcome>;
}

export interface ShellOutcome {
	exitCode: number | null;
	output: string;
	violationKinds: ViolationKind[];
}

export interface ScenarioResult {
	ok: boolean;
	detail: string;
}

export interface Scenario {
	/** Matrix row id, stable across the suite and the docs. */
	id: string;
	title: string;
	/** Which part of the backend this exercises. `fs` scenarios need step 6. */
	surface: "bash" | "fs";
	/**
	 * `denied` scenarios must fail against an unsandboxed backend -- that is what
	 * makes the suite falsifiable. `allowed` scenarios check the sandbox has not
	 * broken ordinary work, so they pass with or without one.
	 */
	expectation: "denied" | "allowed";
	/**
	 * Whether `NoopBackend` is a valid control for this row.
	 *
	 * Most denial scenarios are only satisfied by an OS boundary, so an
	 * unsandboxed run must fail them. A few are not: the property may hold for a
	 * reason unrelated to the sandbox (the test user is not root), or it may be
	 * enforced by pi-enclave in-process rather than by the kernel (the child
	 * environment). Those are marked and given their own control, because
	 * pretending the noop run proves something it does not is exactly the
	 * self-deception this suite exists to prevent.
	 */
	falsifiableByNoop: boolean;
	/** Required whenever `falsifiableByNoop` is false: why, and what covers it instead. */
	falsifiabilityNote?: string;
	run(ctx: ScenarioContext): Promise<ScenarioResult>;
}

/** Build the child environment a scenario runs with. */
export function scenarioEnv(fixture: Fixture): Readonly<Record<string, string>> {
	return buildChildEnv(process.env, {
		readDeny: fixture.profile.readDeny,
		tmpdir: fixture.workspace,
	});
}

const leaked = (output: string) => output.includes(SECRET_FILE_CONTENT);

export const SCENARIOS: Scenario[] = [
	{
		id: "C10",
		title: "happy path: read and write inside the workspace",
		surface: "bash",
		expectation: "allowed",
		falsifiableByNoop: false,
		falsifiabilityNote: "An allowed row is meant to pass with or without a sandbox.",
		async run({ sh, fixture }) {
			const created = join(fixture.workspace, "created.txt");
			const r = await sh(`echo written-by-agent > ${created} && cat ${created} && cat ok.txt`);
			const ok = r.exitCode === 0 && r.output.includes("written-by-agent") && r.output.includes("workspace content");
			return { ok, detail: ok ? "workspace is usable" : `sandbox broke ordinary work: ${r.output.slice(0, 200)}` };
		},
	},
	{
		id: "C1",
		title: "write outside a writable root",
		surface: "bash",
		expectation: "denied",
		falsifiableByNoop: true,
		async run({ sh, fixture }) {
			const target = join(fixture.outside, "pwned.txt");
			await sh(`echo pwned > ${target}`);
			// The verdict is whether the file exists, not what the shell reported.
			let created = true;
			try {
				readFileSync(target);
			} catch {
				created = false;
			}
			return { ok: !created, detail: created ? `WROTE ${target} outside the workspace` : "write denied" };
		},
	},
	{
		id: "C2",
		title: "read a read-denied path",
		surface: "bash",
		expectation: "denied",
		falsifiableByNoop: true,
		async run({ sh, fixture }) {
			const key = join(fixture.deniedHome, ".ssh", "id_ed25519");
			const r = await sh(`cat ${key}`);
			const ok = !leaked(r.output);
			return { ok, detail: ok ? "key not readable" : "SECRET LEAKED into command output" };
		},
	},
	{
		id: "C2b",
		title: "read a read-denied path with a glob and grep",
		surface: "bash",
		expectation: "denied",
		falsifiableByNoop: true,
		async run({ sh, fixture }) {
			// A denial that only covers `cat` is not a denial. Try the shapes an
			// agent would actually reach for.
			const r = await sh(
				`grep -r . ${fixture.deniedHome} 2>&1; cat ${fixture.deniedHome}/.aws/* 2>&1; ` +
					`find ${fixture.deniedHome} -type f -exec cat {} + 2>&1`,
			);
			const ok = !leaked(r.output);
			return { ok, detail: ok ? "denied via grep, glob and find" : "SECRET LEAKED via grep/glob/find" };
		},
	},
	{
		id: "C3",
		title: "symlink race: a link inside the workspace pointing at a denied path",
		surface: "bash",
		expectation: "denied",
		falsifiableByNoop: true,
		async run({ sh, fixture }) {
			// The path the agent names is inside a writable root; only the resolved
			// path is denied. A pi-process path check would pass this.
			const r = await sh(`cat ${join(fixture.workspace, "link-to-denied", "id_ed25519")}`);
			const ok = !leaked(r.output);
			return { ok, detail: ok ? "denied on the resolved path" : "SECRET LEAKED through a symlink" };
		},
	},
	{
		id: "C4",
		title: "symlink write: a link inside the workspace pointing outside it",
		surface: "bash",
		expectation: "denied",
		falsifiableByNoop: true,
		async run({ sh, fixture }) {
			await sh(`echo overwritten > ${join(fixture.workspace, "link-to-outside")}`);
			const content = readFileSync(fixture.outsideFile, "utf8");
			const ok = content.includes(OUTSIDE_FILE_CONTENT);
			return { ok, detail: ok ? "write denied on the resolved path" : "OVERWROTE a file outside the workspace" };
		},
	},
	{
		id: "C5",
		title: "network: TCP, DNS and HTTP are all unavailable",
		surface: "bash",
		expectation: "denied",
		falsifiableByNoop: true,
		async run({ sh }) {
			const r = await sh(
				`python3 -c "
import socket
s=socket.socket(); s.settimeout(4)
try:
    s.connect(('1.1.1.1',80)); print('TCP-CONNECTED')
except Exception as e: print('tcp blocked')
try:
    print('DNS-RESOLVED', socket.gethostbyname('example.com'))
except Exception as e: print('dns blocked')
" 2>&1; curl -sS -m 4 http://example.com -o /dev/null -w 'HTTP-%{http_code}' 2>&1 || true`,
			);
			const reachedInternet = /TCP-CONNECTED|DNS-RESOLVED|HTTP-[23]\d\d/.test(r.output);
			return {
				ok: !reachedInternet,
				detail: reachedInternet ? `REACHED THE NETWORK: ${r.output.slice(0, 160)}` : "network unavailable",
			};
		},
	},
	{
		id: "C7",
		title: "privilege escalation: sudo and su do not run",
		surface: "bash",
		expectation: "denied",
		falsifiableByNoop: false,
		falsifiabilityNote:
			"The test user is not root, so 'did not gain root' holds unsandboxed too. Kept because it " +
			"is a real matrix row, but the noop run proves nothing about it; the backends' own exec " +
			"denial is what step 0 verified.",
		async run({ sh }) {
			// Asserted on the exec failure, not the violation stream: step 0 found
			// sudo/su denials emit no violation event on either backend.
			const r = await sh(`sudo -n id 2>&1; su root -c id 2>&1; echo MARKER-DONE`);
			const escalated = /uid=0\(root\)/.test(r.output);
			return { ok: !escalated, detail: escalated ? "GAINED ROOT" : "sudo/su denied" };
		},
	},
	{
		id: "C8",
		title: "unix sockets outside the workspace are unreachable",
		surface: "bash",
		expectation: "denied",
		falsifiableByNoop: true,
		async run({ sh, fixture }) {
			// A reachable agent socket is a credential leak by another route, and
			// docker.sock is a full host escape. The fixture's socket has a live
			// listener so a success proves the boundary is absent rather than
			// proving the path does not exist -- docker.sock alone made this row
			// pass on any host without Docker, including unsandboxed.
			//
			// connect() succeeding is the whole verdict. Reading from the socket
			// would make the child wait on a server living in this very process,
			// which is a deadlock waiting to happen and proves nothing extra.
			const r = await sh(
				`python3 -c "
import socket
for p in ['${fixture.socketPath}', '/var/run/docker.sock']:
    s=socket.socket(socket.AF_UNIX); s.settimeout(3)
    try:
        s.connect(p)
        print('SOCKET-CONNECTED', p)
    except Exception as e: print('blocked', type(e).__name__)
    finally: s.close()
" 2>&1`,
			);
			const connected = r.output.includes("SOCKET-CONNECTED");
			return { ok: !connected, detail: connected ? `CONNECTED: ${r.output.slice(0, 160)}` : "sockets denied" };
		},
	},
	{
		id: "C9",
		title: "environment: no parent credential reaches the sandbox",
		surface: "bash",
		expectation: "denied",
		falsifiableByNoop: false,
		falsifiabilityNote:
			"Credential isolation is enforced by buildChildEnv in the pi process, not by the OS " +
			"boundary, so the noop backend still receives a sanitised environment and passes. Its " +
			"control is the unsanitised-env test in falsifiability.test.ts, plus child-env.test.ts.",
		async run({ sh }) {
			// Three routes an agent could take, including the Linux-specific one.
			const r = await sh(
				`env; echo "expanded=[$ANTHROPIC_API_KEY][$AWS_SECRET_ACCESS_KEY][$GITHUB_TOKEN]"; ` +
					`python3 -c "import os; print(os.environ)" 2>&1; ` +
					`tr '\\0' '\\n' < /proc/self/environ 2>/dev/null || true`,
			);
			const found = Object.values(SECRET_ENV).filter((v) => r.output.includes(v));
			return {
				ok: found.length === 0,
				detail: found.length === 0 ? "no credential visible" : `CREDENTIALS LEAKED: ${found.length}`,
			};
		},
	},
	{
		id: "C6",
		title: "ordinary tooling still works: git, and a PTY when allowed",
		surface: "bash",
		expectation: "allowed",
		falsifiableByNoop: false,
		falsifiabilityNote: "An allowed row is meant to pass with or without a sandbox.",
		async run({ sh }) {
			const r = await sh(
				`git init -q . && git -c user.email=a@b -c user.name=a commit -q --allow-empty -m x && ` +
					`git log --oneline | head -1 && echo GIT-OK`,
			);
			const ok = r.output.includes("GIT-OK");
			return { ok, detail: ok ? "git works in the workspace" : `git broken: ${r.output.slice(0, 200)}` };
		},
	},
	{
		id: "C11",
		title: "reads outside the workspace are permitted (reads are a deny-list)",
		surface: "bash",
		expectation: "allowed",
		falsifiableByNoop: false,
		falsifiabilityNote: "An allowed row is meant to pass with or without a sandbox.",
		async run({ sh, fixture }) {
			// Recorded deliberately. SRT cannot express "only the workspace is
			// readable", so this documents the actual boundary rather than the one
			// the README's "read-only root" wording implies. If this ever starts
			// failing, the profile model changed and the docs must change with it.
			const r = await sh(`cat ${fixture.outsideFile}`);
			const ok = r.output.includes(OUTSIDE_FILE_CONTENT);
			return { ok, detail: ok ? "reads outside are allowed, as designed" : "read model changed" };
		},
	},
];

// ---------------------------------------------------------------------------
// Filesystem-helper scenarios (surface: "fs")
//
// These go through backend.fs() rather than the shell, which is the path the
// read/edit/write/find/ls/grep tools take. The distinction matters: pi's own
// implementations perform these operations in the pi process, where a path
// check is a check-then-open race rather than a kernel decision.
// ---------------------------------------------------------------------------

SCENARIOS.push(
	{
		id: "F1",
		title: "helper: read a read-denied path",
		surface: "fs",
		expectation: "denied",
		falsifiableByNoop: true,
		async run({ backend, compiled, fixture }) {
			const key = join(fixture.deniedHome, ".ssh", "id_ed25519");
			try {
				const content = await backend.fs(compiled).readFile(key);
				const leakedBytes = content.toString("utf8").includes(SECRET_FILE_CONTENT);
				return {
					ok: !leakedBytes,
					detail: leakedBytes ? "SECRET LEAKED through the helper" : "read returned no secret",
				};
			} catch (error) {
				// A denial is the expected outcome, and it must be reported AS a
				// denial: on Linux the raw errno is ENOENT, and surfacing that
				// unclassified would tell the agent the credential store does not
				// exist. So the classification is the verdict, not a footnote --
				// an unclassified error here fails the row.
				const denied = error instanceof SandboxDenied && error.violation.kind === "read";
				return {
					ok: denied,
					detail: denied
						? `denied and classified as ${(error as SandboxDenied).violation.kind}`
						: `NOT CLASSIFIED as a read denial: ${String(error).slice(0, 90)}`,
				};
			}
		},
	},
	{
		id: "F2",
		title: "helper: write outside a writable root",
		surface: "fs",
		expectation: "denied",
		falsifiableByNoop: true,
		async run({ backend, compiled, fixture }) {
			const target = join(fixture.outside, "helper-pwned.txt");
			try {
				await backend.fs(compiled).writeFile(target, "pwned");
			} catch {
				// Expected.
			}
			let created = true;
			try {
				readFileSync(target);
			} catch {
				created = false;
			}
			return { ok: !created, detail: created ? `WROTE ${target}` : "write denied" };
		},
	},
	{
		id: "F3",
		title: "helper: symlink race resolves to the denied target",
		surface: "fs",
		expectation: "denied",
		falsifiableByNoop: true,
		async run({ backend, compiled, fixture }) {
			// The path named is inside a writable root. Only the resolved path is
			// denied, so a check performed in the pi process would permit this.
			const via = join(fixture.workspace, "link-to-denied", "id_ed25519");
			try {
				const content = await backend.fs(compiled).readFile(via);
				const leakedBytes = content.toString("utf8").includes(SECRET_FILE_CONTENT);
				return { ok: !leakedBytes, detail: leakedBytes ? "SECRET LEAKED via symlink" : "no secret returned" };
			} catch (error) {
				// Same standard as F1. The caller's path is inside the workspace, so
				// classifying on it would call this a missing file; the helper must
				// report the path the kernel judged.
				const denied = error instanceof SandboxDenied;
				return {
					ok: denied,
					detail: denied
						? `denied on the resolved path (${(error as SandboxDenied).violation.path})`
						: `NOT CLASSIFIED as a denial: ${String(error).slice(0, 90)}`,
				};
			}
		},
	},
	{
		id: "F4",
		title: "helper: a genuinely missing file is not reported as a denial",
		surface: "fs",
		expectation: "allowed",
		falsifiableByNoop: false,
		falsifiabilityNote:
			"This asserts the classifier does not over-report, which no backend swap can falsify; " +
			"its control is the ENOENT case in errno.test.ts.",
		async run({ backend, compiled, fixture }) {
			// The mirror of F1. On Linux both cases are ENOENT, so a classifier that
			// called every ENOENT a denial would turn each typo into a security
			// event and teach the agent to ignore them.
			try {
				await backend.fs(compiled).readFile(join(fixture.workspace, "definitely-not-here.txt"));
				return { ok: false, detail: "reading a missing file unexpectedly succeeded" };
			} catch (error) {
				const misreported = error instanceof SandboxDenied;
				return {
					ok: !misreported,
					detail: misreported ? "MISREPORTED a missing file as a sandbox denial" : "reported as an ordinary error",
				};
			}
		},
	},
	{
		id: "F5",
		title: "helper: ordinary reads, writes and listings work",
		surface: "fs",
		expectation: "allowed",
		falsifiableByNoop: false,
		falsifiabilityNote: "An allowed row is meant to pass with or without a sandbox.",
		async run({ backend, compiled, fixture }) {
			const fs = backend.fs(compiled);
			const created = join(fixture.workspace, "helper-made.txt");
			await fs.writeFile(created, "written by the helper");
			const back = (await fs.readFile(created)).toString("utf8");
			const entries = await fs.readdir(fixture.workspace);
			const stats = await fs.stat(fixture.workspace);
			const ok =
				back === "written by the helper" && entries.includes("helper-made.txt") && stats.isDirectory() === true;
			return { ok, detail: ok ? "helper round-trips normal operations" : "helper broke ordinary work" };
		},
	},
);

SCENARIOS.push({
	id: "C12",
	title: "the sandboxed process holds no elevated capabilities",
	surface: "bash",
	expectation: "denied",
	// Falsifiable only where a capability model exists. On macOS the row passes
	// trivially for both a real backend and no backend at all, so claiming the
	// noop run proves anything there would be false.
	falsifiableByNoop: process.platform === "linux",
	falsifiabilityNote:
		"Capabilities are a Linux concept; on other platforms this row reports 'not applicable' " +
		"for every backend, so the noop control cannot distinguish them. On Linux the control " +
		"needs one more thing the platform check cannot see: a host whose own processes hold " +
		"capabilities. Under an ordinary unprivileged user -- a GitHub runner -- CapEff is " +
		"already zero unsandboxed, so the noop backend passes for a reason unrelated to the " +
		"sandbox. hostHoldsCapabilities() decides that at the control, as hostHasNetwork() does " +
		"for C5. The row still discriminates there: it separates secure bwrap from the weaker " +
		"nested mode, which puts the process in a capability-bearing namespace.",
	async run({ sh }) {
		// Linux only: this is what sandbox-runtime's weaker nested mode gives up.
		// In secure mode bwrap runs `--cap-drop ALL`, so CapEff is empty; in weaker
		// mode it does not, and the sandboxed process keeps a full capability set
		// and can create mount namespaces. No escape was found from that position,
		// but "three attempts failed" is not "no escape exists" -- which is exactly
		// why the mode is an explicit opt-in.
		//
		// Making it a row rather than a doc note means a run in the weakened mode
		// reports the difference instead of looking identical to a real one.
		const r = await sh(`grep CapEff /proc/self/status 2>/dev/null || echo "CapEff:\tNOTLINUX"`);
		const match = /CapEff:\s*([0-9a-fA-F]+|NOTLINUX)/.exec(r.output);
		const value = match?.[1] ?? "";
		if (value === "NOTLINUX" || value === "") {
			return { ok: true, detail: "no capability model on this platform (Linux-only row)" };
		}
		const elevated = /[1-9a-fA-F]/.test(value);
		// Report the host's own mask beside the sandbox's. Without it, a green row
		// on an unprivileged host reads as "the sandbox dropped capabilities" when
		// what it shows is that the sandbox did not hand any out -- which is the
		// weaker nested mode's actual failure, but a weaker claim than the phrase
		// implies.
		const ambient = hostCapEff();
		const baseline = ambient === null ? "host has no capability model" : `host CapEff=${ambient}`;
		return {
			ok: !elevated,
			detail: elevated
				? `HOLDS CAPABILITIES CapEff=${value} -- bwrap did not drop them (weaker nested mode?); ${baseline}`
				: `no capabilities (CapEff=${value}; ${baseline})`,
		};
	},
});

export const DENIAL_SCENARIOS = SCENARIOS.filter((s) => s.expectation === "denied");
