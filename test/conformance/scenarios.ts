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
import { mkdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type { CompiledProfile, SandboxBackend, ViolationKind } from "../../src/backend/types.ts";
import { SandboxDenied } from "../../src/backend/types.ts";
import { buildChildEnv } from "../../src/env/child-env.ts";
import { createReadOperations } from "../../src/tools/file-ops.ts";
import { type GrepOutcome, runSandboxedGrep } from "../../src/tools/grep.ts";
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
		async run({ sh, compiled }) {
			// The PTY half has to allocate one. Piping `git log` into `head` never
			// does, and both backends deny PTYs by default, so a profile that lost
			// allowPty in translation would have left this row green.
			const r = await sh(
				`git init -q . && git -c user.email=a@b -c user.name=a commit -q --allow-empty -m x && ` +
					`git log --oneline | head -1 && echo GIT-OK; ` +
					`python3 -c "import pty,os; m,s=pty.openpty(); os.close(s); os.close(m); print('PTY-'+'OK')" 2>&1 || echo PTY-DENIED`,
			);
			const git = r.output.includes("GIT-OK");
			const pty = r.output.includes("PTY-OK");
			const ok = git && pty === compiled.profile.allowPty;
			return {
				ok,
				detail: ok
					? `git works; pty ${pty ? "allocated" : "denied"} as the profile says`
					: `git ${git ? "ok" : "BROKEN"}; pty ${pty ? "allocated" : "denied"} but profile allowPty=${compiled.profile.allowPty}: ${r.output.slice(0, 160)}`,
			};
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

// ---------------------------------------------------------------------------
// The two search tools. grep is re-implemented precisely because pi's would
// read a credential directory with the user's full privileges, and find's
// glob is the operation that stops pi spawning fd itself -- so each gets a
// row against the real backend, not only a unit test against a fake fs.
// ---------------------------------------------------------------------------

SCENARIOS.push(
	{
		id: "F6",
		title: "grep tool: a search over a read-denied directory returns no secret",
		surface: "fs",
		expectation: "denied",
		falsifiableByNoop: true,
		async run({ backend, compiled, fixture }) {
			const fs = backend.fs(compiled);
			let outcome: GrepOutcome;
			try {
				outcome = await runSandboxedGrep(
					{ fs, cwd: fixture.workspace },
					{
						pattern: SECRET_FILE_CONTENT.slice(0, 12),
						path: fixture.deniedHome,
					},
				);
			} catch (error) {
				if (error instanceof SandboxDenied) return { ok: true, detail: `grep denied (${error.violation.kind})` };
				throw error;
			}
			const text = outcome.content[0].text;
			if (text.includes(SECRET_FILE_CONTENT)) return { ok: false, detail: "SECRET LEAKED through the grep tool" };
			// "No matches found" is not a denial. On bwrap the directory is an empty
			// tmpfs and rg would honestly find nothing; the tool must still report
			// the search as denied, or the agent learns the directory is empty.
			const denied = outcome.isError === true && text.startsWith("sandbox denied");
			return { ok: denied, detail: denied ? text.slice(0, 80) : `NOT CLASSIFIED as a denial: ${text.slice(0, 60)}` };
		},
	},
	{
		id: "F7",
		title: "find tool: a glob over a read-denied directory lists nothing",
		surface: "fs",
		expectation: "denied",
		falsifiableByNoop: true,
		async run({ backend, compiled, fixture }) {
			const fs = backend.fs(compiled);
			let found: string[];
			try {
				found = await fs.glob("**/*", fixture.deniedHome, { ignore: [], limit: 100 });
			} catch (error) {
				if (error instanceof SandboxDenied) return { ok: true, detail: `glob denied (${error.violation.kind})` };
				throw error;
			}
			const leaked = found.some((entry) => entry.includes("id_ed25519") || entry.includes("credentials"));
			// An empty list is what the bwrap tmpfs would honestly produce; the
			// operation must throw SandboxDenied, never return.
			return {
				ok: false,
				detail: leaked
					? `LISTED the denied directory: ${found.slice(0, 3).join(", ")}`
					: "NOT CLASSIFIED: returned an empty list instead of a denial",
			};
		},
	},
	{
		id: "F8",
		title: "ls tool: a read-denied directory is reported as denied, not empty",
		surface: "fs",
		expectation: "denied",
		falsifiableByNoop: true,
		async run({ backend, compiled, fixture }) {
			// On bwrap the denied directory is an empty tmpfs, so exists() is true
			// and readdir() is [] -- "ls ~/.ssh: (empty)" would be a lie the agent
			// acts on. On seatbelt the probe itself is refused.
			const fs = backend.fs(compiled);
			const target = join(fixture.deniedHome, ".ssh");
			try {
				const present = await fs.exists(target);
				const entries = present ? await fs.readdir(target) : [];
				const leaked = entries.includes("id_ed25519");
				return {
					ok: false,
					detail: leaked
						? "LISTED the denied directory"
						: `reported as ${present ? "empty" : "missing"} rather than denied`,
				};
			} catch (error) {
				const denied = error instanceof SandboxDenied;
				return {
					ok: denied,
					detail: denied ? "classified as a denial" : `NOT CLASSIFIED: ${String(error).slice(0, 80)}`,
				};
			}
		},
	},
);

SCENARIOS.push({
	id: "F10",
	title: "helper: a deny root created after startup is still denied",
	surface: "fs",
	expectation: "denied",
	falsifiableByNoop: true,
	async run({ backend, compiled, fixture }) {
		// bwrap masks a denied directory with a tmpfs, and can only do so for a
		// directory that exists when the helper is wrapped. The helper is wrapped
		// once and lives for the session, so a ~/.aws that appears afterwards
		// would be readable through it unless the backend notices. Shell commands
		// are wrapped per call and never had this problem.
		const fs = backend.fs(compiled);
		// Get the helper running under the original wrap first.
		await fs.readFile(join(fixture.workspace, "ok.txt"));
		mkdirSync(fixture.lateDenied, { recursive: true });
		const secret = join(fixture.lateDenied, "token");
		writeFileSync(secret, `${SECRET_FILE_CONTENT}\n`);
		try {
			const content = await fs.readFile(secret);
			const leaked = content.toString("utf8").includes(SECRET_FILE_CONTENT);
			return { ok: !leaked, detail: leaked ? "SECRET LEAKED from a deny root created after startup" : "no secret" };
		} catch (error) {
			const denied = error instanceof SandboxDenied;
			return {
				ok: denied,
				detail: denied ? "denied after the helper was re-wrapped" : `NOT CLASSIFIED: ${String(error).slice(0, 80)}`,
			};
		}
	},
});

SCENARIOS.push(
	{
		id: "F11",
		title: "find tool: a path-containing pattern matches inside the workspace",
		surface: "fs",
		expectation: "allowed",
		falsifiableByNoop: false,
		falsifiabilityNote: "An allowed row is meant to pass with or without a sandbox.",
		async run({ backend, compiled, fixture }) {
			// fd --glob matches basenames unless --full-path is set, and then a
			// relative pattern needs a **/ prefix. The pattern pi's description
			// advertises must work through the helper; the denied-directory row
			// cannot show that because its pattern already starts with **/.
			const found = await backend.fs(compiled).glob("src/**/*.spec.ts", fixture.workspace, { ignore: [], limit: 100 });
			const ok = found.some((entry) => entry.endsWith(join("src", "a", "foo.spec.ts")));
			return { ok, detail: ok ? "src/**/*.spec.ts matched" : `no match: ${JSON.stringify(found.slice(0, 3))}` };
		},
	},
	{
		id: "F12",
		title: "helper: a read-denied file is denied, not returned empty",
		surface: "fs",
		expectation: "denied",
		falsifiableByNoop: true,
		async run({ backend, compiled, fixture }) {
			// Several default deny entries are files (auth.json, .netrc, .npmrc).
			// bwrap masks a denied file with a read-only /dev/null, so readFile,
			// head and a read access check all succeed with nothing in them.
			const fs = backend.fs(compiled);
			const attempts: Array<[string, () => Promise<unknown>]> = [
				["readFile", () => fs.readFile(fixture.deniedFile)],
				["head", () => fs.head(fixture.deniedFile, 64)],
				["access", () => fs.access(fixture.deniedFile, "read")],
			];
			for (const [name, attempt] of attempts) {
				try {
					const result = await attempt();
					if (Buffer.isBuffer(result) && result.toString("utf8").includes(SECRET_FILE_CONTENT)) {
						return { ok: false, detail: `SECRET LEAKED through ${name}` };
					}
					return { ok: false, detail: `${name} NOT CLASSIFIED: succeeded (masked as empty?)` };
				} catch (error) {
					if (!(error instanceof SandboxDenied))
						return { ok: false, detail: `${name} NOT CLASSIFIED: ${String(error).slice(0, 60)}` };
				}
			}
			return { ok: true, detail: "readFile, head and access all classified as denied" };
		},
	},
	{
		id: "F13",
		title: "helper: a deny symlink retargeted after startup is still denied",
		surface: "fs",
		expectation: "denied",
		falsifiableByNoop: true,
		async run({ backend, compiled, fixture }) {
			// SRT masks the link's target at wrap time. Retargeting the link to
			// another existing directory keeps the old mask while reads follow the
			// new target -- unless the backend notices the link changed.
			const fs = backend.fs(compiled);
			await fs.readFile(join(fixture.workspace, "ok.txt"));
			rmSync(fixture.deniedLink);
			symlinkSync(fixture.linkTargetB, fixture.deniedLink);
			try {
				const content = await fs.readFile(join(fixture.deniedLink, "token"));
				const leaked = content.toString("utf8").includes(SECRET_FILE_CONTENT);
				return {
					ok: false,
					detail: leaked ? "SECRET LEAKED through a retargeted deny link" : "NOT CLASSIFIED: read succeeded",
				};
			} catch (error) {
				const denied = error instanceof SandboxDenied;
				return {
					ok: denied,
					detail: denied ? "denied after the link was retargeted" : `NOT CLASSIFIED: ${String(error).slice(0, 80)}`,
				};
			}
		},
	},
);

SCENARIOS.push({
	id: "F9",
	title: "read tool: an image read through the helper is still detected as one",
	surface: "fs",
	expectation: "allowed",
	falsifiableByNoop: false,
	falsifiabilityNote: "An allowed row is meant to pass with or without a sandbox.",
	async run({ backend, compiled, fixture }) {
		// pi decodes the bytes as text when the operations object has no
		// detector. The detector here reads the head through the helper, so the
		// open stays on the sandbox side.
		const ops = createReadOperations(() => backend.fs(compiled));
		const png = join(fixture.workspace, "pixel.png");
		writeFileSync(png, PNG_1X1);
		const mime = await ops.detectImageMimeType(png);
		const text = await ops.detectImageMimeType(join(fixture.workspace, "ok.txt"));
		const ok = mime === "image/png" && text === null;
		return { ok, detail: ok ? "png detected, text not" : `png -> ${mime}, text -> ${text}` };
	},
});

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

/** A valid 1x1 PNG, for the image-detection row. */
const PNG_1X1 = Buffer.from(
	"iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==",
	"base64",
);

export const DENIAL_SCENARIOS = SCENARIOS.filter((s) => s.expectation === "denied");
