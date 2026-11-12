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
import { spawn, spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import type {
	CompiledProfile,
	Profile,
	ResourceLimits,
	SandboxBackend,
	ViolationKind,
} from "../../src/backend/types.ts";
import { SandboxDenied } from "../../src/backend/types.ts";
import { DEFAULT_PROTECTED_ASK, DEFAULT_PROTECTED_DENY } from "../../src/config/defaults.ts";
import { buildChildEnv } from "../../src/env/child-env.ts";
import { protectedWriteTargets } from "../../src/gate/protected-writes.ts";
import { createReadOperations } from "../../src/tools/file-ops.ts";
import { type GrepOutcome, runSandboxedGrep } from "../../src/tools/grep.ts";
import { type Fixture, hostCapEff, OUTSIDE_FILE_CONTENT, SECRET_ENV, SECRET_FILE_CONTENT } from "./fixture.ts";

export interface ScenarioContext {
	backend: SandboxBackend;
	compiled: CompiledProfile;
	fixture: Fixture;
	/** Run a shell command in the workspace and collect everything it produced. */
	sh(command: string, extra?: ShellExtra): Promise<ShellOutcome>;
}

/** Per-invocation request fields a scenario may set. */
export interface ShellExtra {
	/** The protected paths of an unjudged command (#64). */
	protectWrites?: readonly string[];
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
		writableRoots: fixture.profile.writableRoots,
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
		id: "C15",
		title: "protected persistence paths remain read-only inside a writable workspace",
		surface: "bash",
		expectation: "denied",
		falsifiableByNoop: true,
		async run({ sh, fixture }) {
			const extension = join(fixture.workspace, ".pi", "extensions", "evil.ts");
			const hook = join(fixture.workspace, ".git", "hooks", "pre-commit");
			const config = join(fixture.workspace, ".git", "config");
			for (const target of [extension, hook, config]) {
				await sh(
					`python3 -c "from pathlib import Path; p=Path('${target}'); p.parent.mkdir(parents=True, exist_ok=True); p.write_text('pwn')"`,
				);
			}
			const changed = [extension, hook, config].filter((target) => {
				try {
					return readFileSync(target, "utf8").includes("pwn");
				} catch {
					return false;
				}
			});
			return {
				ok: changed.length === 0,
				detail: changed.length > 0 ? `WROTE executable persistence path(s): ${changed.join(", ")}` : "writes denied",
			};
		},
	},
	{
		id: "C16",
		title: "a protected persistence leaf cannot be displaced by moving its ancestor",
		surface: "bash",
		expectation: "denied",
		falsifiableByNoop: true,
		async run({ sh, fixture }) {
			const metadata = join(fixture.workspace, ".git");
			const moved = join(fixture.workspace, ".git-displaced");
			const hook = join(metadata, "hooks", "pre-commit");
			await sh(
				`mv ${metadata} ${moved} && mkdir -p ${join(metadata, "hooks")} && ` +
					`printf pwn > ${hook} && printf '[core]\\nhooksPath=hooks\\n' > ${join(metadata, "config")}`,
			);
			let replaced = false;
			try {
				replaced = readFileSync(hook, "utf8") === "pwn";
			} catch {
				// Expected: the ancestor move or replacement write was denied.
			}
			return {
				ok: !replaced,
				detail: replaced
					? "DISPLACED the protected Git metadata tree and wrote a hook"
					: "ancestor displacement denied",
			};
		},
	},
	{
		id: "C17",
		title: "submodule and nested-repository Git configuration and hooks remain read-only (#33)",
		surface: "bash",
		expectation: "denied",
		falsifiableByNoop: true,
		async run({ sh, fixture }) {
			const submodule = join(fixture.workspace, ".git", "modules", "lib");
			const nested = join(fixture.workspace, "vendor", "inner", ".git");
			const targets = [
				join(submodule, "config"),
				join(submodule, "hooks", "post-checkout"),
				join(nested, "config"),
				join(nested, "hooks", "pre-commit"),
				// `modules` did not exist in the nested repository, so it is a
				// read-only anchor: a submodule added there cannot bring a writable
				// config with it.
				join(nested, "modules", "added", "config"),
				// A bare-shaped directory not named .git: core.bare=false and
				// core.worktree=. would make `git status` below it run this config.
				join(fixture.workspace, "tools", "cache", "config"),
				join(fixture.workspace, "tools", "cache", "hooks", "post-checkout"),
			];
			for (const target of targets) {
				await sh(`mkdir -p ${JSON.stringify(dirname(target))}; printf pwn >> ${JSON.stringify(target)}`);
			}
			// As C16 does for the workspace's own: move the nested Git directory
			// aside and plant a hook at the old path.
			const displaced = join(nested, "hooks", "post-merge");
			await sh(
				`mv ${JSON.stringify(nested)} ${JSON.stringify(`${nested}-moved`)} && ` +
					`mkdir -p ${JSON.stringify(dirname(displaced))} && printf pwn > ${JSON.stringify(displaced)}`,
			);
			targets.push(displaced);
			const changed = targets.filter((target) => {
				try {
					return readFileSync(target, "utf8").includes("pwn");
				} catch {
					return false;
				}
			});
			return {
				ok: changed.length === 0,
				detail:
					changed.length > 0
						? `WROTE Git persistence path(s): ${changed.join(", ")}`
						: "all seven writes and the displacement denied",
			};
		},
	},
	{
		id: "C18",
		title: "nested pi configuration stays read-only, by direct write and by rename (#19)",
		surface: "bash",
		expectation: "denied",
		falsifiableByNoop: true,
		async run({ sh, fixture }) {
			const ws = fixture.workspace;
			const targets = [
				join(ws, "sub", ".pi", "extensions", "x.ts"),
				join(ws, "sub", ".pi", "settings.json"),
				join(ws, "sub", ".pi", "mcp.json"),
				join(ws, "pkg", ".agents", "skills", "x", "SKILL.md"),
				// Did not exist before the session: materialised read-only.
				join(ws, ".agents", "skills", "x", "SKILL.md"),
			];
			for (const target of targets) {
				await sh(`mkdir -p ${JSON.stringify(dirname(target))}; printf pwn >> ${JSON.stringify(target)}`);
			}
			// The rename: build the tree under another name, move the protected
			// directory aside and the prepared one into its place.
			const renamed = join(ws, "sub", ".pi", "extensions", "renamed.ts");
			const staged = join(ws, "sub", "staged");
			await sh(
				`mkdir -p ${JSON.stringify(join(staged, "extensions"))} && ` +
					`printf pwn > ${JSON.stringify(join(staged, "extensions", "renamed.ts"))} && ` +
					`mv ${JSON.stringify(join(ws, "sub", ".pi"))} ${JSON.stringify(join(ws, "sub", "pi-aside"))}; ` +
					`mv ${JSON.stringify(staged)} ${JSON.stringify(join(ws, "sub", ".pi"))}`,
			);
			targets.push(renamed);
			const changed = targets.filter((target) => {
				try {
					return readFileSync(target, "utf8").includes("pwn");
				} catch {
					return false;
				}
			});
			return {
				ok: changed.length === 0,
				detail:
					changed.length > 0
						? `WROTE pi configuration path(s): ${changed.join(", ")}`
						: "all five writes and the rename into place denied",
			};
		},
	},
	{
		id: "C19",
		title: "loaded extension code below the workspace stays read-only with sandbox.allowSelfHosting (#36)",
		surface: "bash",
		expectation: "denied",
		falsifiableByNoop: true,
		async run({ sh, fixture }) {
			const ext = join(fixture.workspace, "ext");
			const targets = [
				join(ext, "src", "index.ts"),
				join(ext, "package.json"),
				join(ext, "node_modules", "dep", "index.js"),
				// Did not exist: a new file in the package is loaded code too.
				join(ext, "src", "added.ts"),
				// No node_modules above the package: one created there would
				// shadow a hoisted dependency, so it was materialised read-only.
				join(fixture.workspace, "node_modules", "dep", "index.js"),
			];
			for (const target of targets) {
				await sh(`mkdir -p ${JSON.stringify(dirname(target))}; printf pwn >> ${JSON.stringify(target)}`);
			}
			// As C16 does for Git: move the package aside and put another in its place.
			const replaced = join(ext, "src", "index.ts");
			await sh(
				`mv ${JSON.stringify(ext)} ${JSON.stringify(`${ext}-aside`)} && ` +
					`mkdir -p ${JSON.stringify(dirname(replaced))} && printf pwn > ${JSON.stringify(replaced)}`,
			);
			const changed = targets.filter((target) => {
				try {
					return readFileSync(target, "utf8").includes("pwn");
				} catch {
					return false;
				}
			});
			return {
				ok: changed.length === 0,
				detail:
					changed.length > 0
						? `WROTE loaded extension code: ${changed.join(", ")}`
						: "all five writes and the replacement denied",
			};
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
				`git -c user.email=a@b -c user.name=a commit -q --allow-empty -m x && ` +
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
				[
					"stream",
					async () => {
						for await (const chunk of fs.createReadStream(fixture.deniedFile)) return Buffer.from(chunk);
					},
				],
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
			return { ok: true, detail: "readFile, stream, head and access all classified as denied" };
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
	id: "F14",
	title: "helper: a denied file under a symlinked parent is denied, before and after a retarget",
	surface: "fs",
	expectation: "denied",
	falsifiableByNoop: true,
	async run({ backend, compiled, fixture }) {
		// The credential-path shape: the deny entry is a regular file whose
		// parent is a symlink. Seatbelt evaluates the canonical path, so a deny
		// written with the link spelling covers nothing unless every component
		// is resolved -- and a retargeted parent must be re-resolved.
		const fs = backend.fs(compiled);
		const attempt = async (label: string): Promise<ScenarioResult | undefined> => {
			try {
				const content = await fs.readFile(fixture.deniedUnderLink);
				const leaked = content.toString("utf8").includes(SECRET_FILE_CONTENT);
				return { ok: false, detail: leaked ? `SECRET LEAKED ${label}` : `NOT CLASSIFIED ${label}: read succeeded` };
			} catch (error) {
				if (error instanceof SandboxDenied) return undefined;
				return { ok: false, detail: `NOT CLASSIFIED ${label}: ${String(error).slice(0, 80)}` };
			}
		};
		const before = await attempt("through the symlinked parent");
		if (before) return before;
		rmSync(fixture.agentLink);
		symlinkSync(fixture.agentB, fixture.agentLink);
		const after = await attempt("after the parent was retargeted");
		if (after) return after;
		return { ok: true, detail: "denied through the link, and again after its retarget" };
	},
});

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

/**
 * Resource limits for the L rows (#24): small enough that each row ends in
 * seconds, so the falsifiability control (which enforces none of them) shows
 * the difference without hurting the host running it.
 */
export const TEST_LIMITS: ResourceLimits = {
	defaultTimeoutSec: 2,
	maxTimeoutSec: 30,
	maxOutputMb: 1,
	fileSizeMb: 8,
	openFiles: 256,
	processes: 64,
	memoryMb: 256,
	minFreeDiskMb: 0,
	container: { pids: 64, memoryMb: 256, cpus: 1, shmMb: 8, tmpMb: 16 },
};

interface LimitedRun {
	exitCode: number | null;
	output: string;
	error?: string;
	ms: number;
}

/** Run one command under {@link TEST_LIMITS}, bounded by the scenario itself as well. */
async function runLimited(
	{ backend, fixture }: ScenarioContext,
	command: string,
	options: { timeout?: number; maxMs?: number } = {},
): Promise<LimitedRun> {
	const compiled = await backend.compile({ ...fixture.profile, limits: TEST_LIMITS });
	const chunks: Buffer[] = [];
	const started = Date.now();
	// The control backend enforces no limit, so the row bounds itself: a row
	// that hangs is a failure, not a pass.
	const signal = AbortSignal.timeout(options.maxMs ?? 25_000);
	try {
		const result = await backend.run(compiled, {
			command,
			cwd: fixture.workspace,
			env: scenarioEnv(fixture),
			commandId: `limits-${Math.random().toString(36).slice(2)}`,
			onData: (chunk) => chunks.push(chunk),
			signal,
			...(options.timeout !== undefined ? { timeout: options.timeout } : {}),
		});
		return { exitCode: result.exitCode, output: Buffer.concat(chunks).toString("utf8"), ms: Date.now() - started };
	} catch (error) {
		return {
			exitCode: null,
			output: Buffer.concat(chunks).toString("utf8"),
			error: (error as Error).message,
			ms: Date.now() - started,
		};
	}
}

SCENARIOS.push(
	{
		id: "L1",
		title: "a command with no timeout ends at the default timeout",
		surface: "bash",
		expectation: "denied",
		falsifiableByNoop: true,
		async run(ctx) {
			const r = await runLimited(ctx, "sleep 100000", { maxMs: 10_000 });
			const ended = r.error === `timeout:${TEST_LIMITS.defaultTimeoutSec}` && r.ms < 15_000;
			const noted = r.output.includes("sandbox.limits.defaultTimeoutSec");
			return {
				ok: ended && noted,
				detail: ended
					? `ended after ${r.ms} ms${noted ? " with the default-timeout note" : " WITHOUT the note"}`
					: `RAN PAST THE DEFAULT (${r.ms} ms, ${r.error ?? `exit ${r.exitCode}`})`,
			};
		},
	},
	{
		id: "L2",
		title: "output past the cap is discarded and the command is killed",
		surface: "bash",
		expectation: "denied",
		falsifiableByNoop: true,
		async run(ctx) {
			const r = await runLimited(ctx, "head -c 16777216 /dev/zero | tr '\\0' x", { timeout: 20 });
			const bytes = Buffer.byteLength(r.output);
			const capped = bytes <= TEST_LIMITS.maxOutputMb * 1024 * 1024 + 4096;
			return {
				ok: capped && r.output.includes("sandbox.limits.maxOutputMb"),
				detail: capped ? `forwarded ${bytes} bytes, then stopped` : `FORWARDED ${bytes} bytes past a 1 MB cap`,
			};
		},
	},
	{
		id: "L3",
		title: "a runaway write stops at the file size limit",
		surface: "bash",
		expectation: "denied",
		falsifiableByNoop: true,
		async run(ctx) {
			const target = join(ctx.fixture.workspace, "big.bin");
			await runLimited(ctx, `head -c 67108864 /dev/zero > ${JSON.stringify(target)}`, { timeout: 20 });
			let size = 0;
			try {
				size = statSync(target).size;
			} catch {
				size = 0;
			}
			const bounded = size <= TEST_LIMITS.fileSizeMb * 1024 * 1024;
			return {
				ok: bounded,
				detail: bounded ? `file stopped at ${size} bytes` : `WROTE ${size} bytes past an 8 MB limit`,
			};
		},
	},
	{
		id: "L4",
		title: "a fork loop ends with a bounded process count",
		surface: "bash",
		expectation: "denied",
		// macOS counts RLIMIT_NPROC across all of the user's processes, so the
		// native backend does not set it there; the row is Linux (and container) only.
		falsifiableByNoop: process.platform === "linux",
		falsifiabilityNote:
			"The native backend limits processes only on Linux 5.14+ when the sandbox has its own user " +
			"namespace, where RLIMIT_NPROC is counted there. Elsewhere it skips the limit and the row " +
			"reports 'not applicable' for that backend; the containers use the cgroup pids limit.",
		async run(ctx) {
			if (process.platform !== "linux" && ctx.backend.name !== "docker" && ctx.backend.name !== "podman") {
				return { ok: true, detail: "processes are not limited by the native backend on this platform" };
			}
			const count = join(ctx.fixture.workspace, "count");
			const r = await runLimited(
				ctx,
				`for i in $(seq 1 400); do sleep 5 & echo $i > ${JSON.stringify(count)}; done 2>/dev/null; echo done`,
				{ timeout: 25, maxMs: 40_000 },
			);
			let started = 0;
			try {
				started = Number(readFileSync(count, "utf8").trim());
			} catch {
				started = 0;
			}
			// Decided by the backend at its first command: an older kernel, or a
			// sandbox in pi's own user namespace, would count the host's processes.
			const decision = ctx.backend.processLimit;
			if (decision && !decision.applies) {
				return { ok: true, detail: `processes are not limited by this backend here: ${decision.reason}` };
			}
			const bounded = started > 0 && started < 400;
			return {
				ok: bounded,
				detail: bounded
					? `started ${started} of 400 background processes before the limit (${r.ms} ms)`
					: `STARTED ${started} of 400 background processes with a limit of ${TEST_LIMITS.processes}`,
			};
		},
	},
	{
		id: "L5",
		title: "a memory hog is stopped without affecting the pi process",
		surface: "bash",
		expectation: "denied",
		falsifiableByNoop: process.platform === "linux",
		falsifiabilityNote:
			"macOS does not enforce RLIMIT_DATA, so the native backend does not limit memory there and " +
			"the row reports 'not applicable' for every backend.",
		async run(ctx) {
			if (process.platform !== "linux" && ctx.backend.name !== "docker" && ctx.backend.name !== "podman") {
				return { ok: true, detail: "memory is not limited by the native backend on this platform" };
			}
			// `tail -n 1` keeps a whole line in memory, and /dev/zero has no newline.
			const r = await runLimited(ctx, "head -c 1073741824 /dev/zero | tail -n 1 | wc -c", { timeout: 25 });
			const grew = r.output.includes("1073741824");
			return {
				ok: !grew && process.memoryUsage().rss > 0,
				detail: grew ? "HELD 1 GB with a 256 MB limit" : `the hog was stopped: ${r.output.trim().slice(0, 120)}`,
			};
		},
	},
	{
		id: "L6",
		title: "stdin is empty, so a program waiting for input ends at once",
		surface: "bash",
		expectation: "denied",
		falsifiableByNoop: false,
		falsifiabilityNote:
			"The control backend also spawns with stdin ignored, so it passes for the same reason a real " +
			"backend does. The row guards against a backend that hands the command a pipe nobody writes to " +
			"(the container supervisor keeps one open as its control channel).",
		async run(ctx) {
			const r = await runLimited(ctx, "read line; echo read-exit:$?", { timeout: 10, maxMs: 15_000 });
			const ended = r.output.includes("read-exit:1") && r.ms < 8_000;
			return { ok: ended, detail: ended ? `read hit EOF after ${r.ms} ms` : `WAITED ON STDIN (${r.ms} ms)` };
		},
	},
);

/**
 * The fixture's profile in read-allowlist mode (#23). The container suite
 * mounts `fixture.outside` through `readableRoots` for its open-mode rows;
 * here the only readable roots are the ones the row names.
 */
function allowlistProfile(
	fixture: Fixture,
	readAllow: readonly string[] = [],
	readDeny: readonly string[] = [],
): Profile {
	const { readableRoots: _openModeMounts, ...profile } = fixture.profile;
	return { ...profile, readDeny: [...profile.readDeny, ...readDeny], readMode: "allowlist", readAllow };
}

/**
 * Run one command under the fixture's profile in read-allowlist mode (#23),
 * with `readAllow` as the configured readable roots.
 */
async function runAllowlisted(
	{ backend, fixture }: ScenarioContext,
	command: string,
	readAllow: readonly string[] = [],
	extra: { cwd?: string; readDeny?: readonly string[] } = {},
): Promise<LimitedRun> {
	const compiled = await backend.compile(allowlistProfile(fixture, readAllow, extra.readDeny));
	const chunks: Buffer[] = [];
	const started = Date.now();
	try {
		const result = await backend.run(compiled, {
			command,
			cwd: extra.cwd ?? fixture.workspace,
			env: scenarioEnv(fixture),
			commandId: `allowlist-${Math.random().toString(36).slice(2)}`,
			timeout: 30,
			onData: (chunk) => chunks.push(chunk),
		});
		return { exitCode: result.exitCode, output: Buffer.concat(chunks).toString("utf8"), ms: Date.now() - started };
	} catch (error) {
		return {
			exitCode: null,
			output: Buffer.concat(chunks).toString("utf8"),
			error: (error as Error).message,
			ms: Date.now() - started,
		};
	}
}

const containerBackend = (ctx: ScenarioContext) => ctx.backend.name === "docker" || ctx.backend.name === "podman";

SCENARIOS.push(
	{
		id: "R1",
		title: "allowlist reads: a file outside every readable root cannot be read",
		surface: "bash",
		expectation: "denied",
		falsifiableByNoop: true,
		async run(ctx) {
			// A sibling directory the user can read, standing in for another
			// project's .env or a database dump: nothing lists it in readDeny.
			const r = await runAllowlisted(ctx, `cat ${JSON.stringify(ctx.fixture.outsideFile)}`);
			const read = r.output.includes(OUTSIDE_FILE_CONTENT);
			return { ok: !read, detail: read ? "READ a file outside the allowlist" : "outside file unreadable" };
		},
	},
	{
		id: "R2",
		title: "allowlist reads: a directory outside every readable root cannot be listed",
		surface: "bash",
		expectation: "denied",
		falsifiableByNoop: true,
		async run(ctx) {
			const r = await runAllowlisted(ctx, `ls -a ${JSON.stringify(ctx.fixture.outside)}`);
			const listed = r.output.includes("target.txt");
			return { ok: !listed, detail: listed ? "LISTED a directory outside the allowlist" : "outside directory hidden" };
		},
	},
	{
		id: "R3",
		title: "allowlist reads: the deny list still applies inside a readable root",
		surface: "bash",
		expectation: "denied",
		falsifiableByNoop: true,
		async run(ctx) {
			// A readable root holding a denied directory, as ~/.cargo holds its
			// credentials: the root is readable and the deny inside it is not.
			const readable = join(ctx.fixture.outside, "readable");
			const secret = join(readable, "secret");
			mkdirSync(secret, { recursive: true });
			writeFileSync(join(readable, "visible.txt"), "visible\n");
			writeFileSync(join(secret, "key"), `${SECRET_FILE_CONTENT}\n`);
			const r = await runAllowlisted(ctx, `cat ${JSON.stringify(join(secret, "key"))}; cat visible.txt`, [readable], {
				cwd: readable,
				readDeny: [secret],
			});
			const leakedKey = leaked(r.output);
			const rootReadable = r.output.includes("visible");
			return {
				ok: !leakedKey && rootReadable,
				detail: leakedKey
					? "SECRET LEAKED from a denied path inside a readable root"
					: rootReadable
						? "readable root readable, denied path inside it unreadable"
						: `the readable root itself was not readable: ${r.error ?? r.output.slice(0, 160)}`,
			};
		},
	},
	{
		id: "R6",
		title: "allowlist reads: a readable root cannot lift the deny it sits in",
		surface: "bash",
		expectation: "denied",
		falsifiableByNoop: true,
		async run(ctx) {
			// The configuration refuses this; the backend must not honour it either.
			const key = join(ctx.fixture.deniedHome, ".ssh", "id_ed25519");
			const r = await runAllowlisted(ctx, `cat ${JSON.stringify(key)}`, [
				ctx.fixture.deniedHome,
				join(ctx.fixture.deniedHome, ".ssh"),
			]);
			// The same root spelled through a link (review of #55): the sandbox
			// resolves an allow entry's parents, so it lands on the denied place
			// unless the root is judged on its canonical location.
			const links = mkdtempSync(join(tmpdir(), "enclave-link-"));
			let viaLink: LimitedRun;
			try {
				symlinkSync(ctx.fixture.deniedHome, join(links, "home"));
				viaLink = await runAllowlisted(ctx, `cat ${JSON.stringify(key)}`, [join(links, "home", ".ssh")]);
			} finally {
				rmSync(links, { recursive: true, force: true });
			}
			const leakedKey = leaked(r.output);
			const leakedViaLink = leaked(viaLink.output);
			return {
				ok: !leakedKey && !leakedViaLink,
				detail: leakedKey
					? "SECRET LEAKED: a readable root lifted a deny"
					: leakedViaLink
						? "SECRET LEAKED: a readable root spelled through a link lifted a deny"
						: "deny kept, also through a link",
			};
		},
	},
	{
		id: "R4",
		title: "allowlist reads: the helper cannot read outside the readable roots",
		surface: "fs",
		expectation: "denied",
		falsifiableByNoop: true,
		async run({ backend, fixture }) {
			const compiled = await backend.compile(allowlistProfile(fixture));
			try {
				const content = await backend.fs(compiled).readFile(fixture.outsideFile);
				const read = content.toString("utf8").includes(OUTSIDE_FILE_CONTENT);
				return { ok: !read, detail: read ? "READ outside the allowlist through the helper" : "read returned nothing" };
			} catch (error) {
				const denied = error instanceof SandboxDenied && error.violation.kind === "read";
				return {
					ok: denied,
					detail: denied
						? "denied and classified as a read"
						: `NOT CLASSIFIED as a read denial: ${String(error).slice(0, 90)}`,
				};
			}
		},
	},
	{
		id: "R5",
		title: "allowlist reads: the shell, node, git and the helper still work",
		surface: "fs",
		expectation: "allowed",
		falsifiableByNoop: false,
		falsifiabilityNote: "An allowed row is meant to pass with or without a sandbox.",
		async run(ctx) {
			const { backend, fixture } = ctx;
			// The container image carries its own userland; only the shell and the
			// workspace are asserted there.
			// Each tool is asserted only where the host has it, and then it must
			// work: a fallback echo would hide exactly the breakage this row is for.
			const onHost = (tool: string) => spawnSync("sh", ["-c", `command -v ${tool}`]).status === 0;
			const checks: [string, string][] = containerBackend(ctx)
				? [["ls /usr/bin >/dev/null && echo shell-ok", "shell-ok"]]
				: [
						[`${JSON.stringify(process.execPath)} -e 'console.log("node-ok")'`, "node-ok"],
						["git status --porcelain >/dev/null && echo git-ok", "git-ok"],
						...(onHost("python3") ? ([["python3 -c 'print(\"python-ok\")'", "python-ok"]] as [string, string][]) : []),
						...(onHost("rg") ? ([["rg --version >/dev/null && echo rg-ok", "rg-ok"]] as [string, string][]) : []),
					];
			const r = await runAllowlisted(ctx, ["cat ok.txt", ...checks.map(([command]) => command)].join("; "));
			const expected = ["workspace content", ...checks.map(([, marker]) => marker)];
			const missing = expected.filter((marker) => !r.output.includes(marker));
			const compiled = await backend.compile(allowlistProfile(fixture));
			let helper = "";
			try {
				helper = (await backend.fs(compiled).readFile(join(fixture.workspace, "ok.txt"))).toString("utf8");
			} catch (error) {
				helper = `helper failed: ${(error as Error).message}`;
			}
			const helperOk = helper.includes("workspace content");
			return {
				ok: missing.length === 0 && helperOk,
				detail:
					missing.length === 0 && helperOk
						? "shell, toolchain and helper work under the allowlist"
						: `BROKE ordinary work: missing ${missing.join(", ") || "none"}; ${helperOk ? "helper ok" : helper.slice(0, 120)}; ${r.error ?? r.output.slice(0, 200)}`,
			};
		},
	},
);

SCENARIOS.push({
	id: "C20",
	title: "another process's environment cannot be read through /proc",
	surface: "bash",
	expectation: "denied",
	// macOS has no /proc; the row is Linux (and container) only.
	falsifiableByNoop: process.platform === "linux",
	falsifiabilityNote: "macOS has no /proc, so there is nothing to read and nothing for the control to leak.",
	async run({ sh }) {
		if (process.platform !== "linux") return { ok: true, detail: "no /proc on this platform" };
		// A process of the same user holding a secret in its environment, as a
		// shell with an exported token or a service started by hand would (#23).
		const marker = "PROC-ENVIRON-CONFORMANCE-LEAK";
		const holder = spawn("sleep", ["30"], { env: { ...process.env, ENCLAVE_PROC_SECRET: marker }, stdio: "ignore" });
		try {
			await new Promise((resolve) => setTimeout(resolve, 100));
			const r = await sh(`grep -l -a ${marker} /proc/[0-9]*/environ 2>/dev/null; echo checked`);
			const read = r.output.includes("/environ");
			return {
				ok: !read && r.output.includes("checked"),
				detail: read ? `READ another process's environment: ${r.output.trim().slice(0, 120)}` : "not visible",
			};
		} finally {
			holder.kill();
		}
	},
});

// ---------------------------------------------------------------------------
// #64: a command nobody judged runs with the existing protected paths
// write-denied for that call. The trusted parent finds them with the same
// walk the extension uses; the rows check the backend holds them read-only.
// ---------------------------------------------------------------------------

const PROTECTED_ORIGINAL = "PROTECTED-ORIGINAL-CONTENT\n";

/** The protected paths of the fixture, as the extension would compute them for one call. */
function protectedFor(fixture: Fixture, userGlobal: readonly string[] = []): string[] {
	const found = protectedWriteTargets({
		writableRoots: fixture.profile.writableRoots,
		workspace: fixture.workspace,
		patterns: [...DEFAULT_PROTECTED_DENY, ...DEFAULT_PROTECTED_ASK, ...userGlobal],
		writeDeny: fixture.profile.writeDeny ?? [],
	});
	if (!found.ok) throw new Error(found.reason);
	return found.paths;
}

/** Plant a protected file after the profile compiled, as the agent's own earlier work would. */
function plant(fixture: Fixture, relative: string): string {
	const path = join(fixture.workspace, relative);
	mkdirSync(dirname(path), { recursive: true });
	writeFileSync(path, PROTECTED_ORIGINAL);
	return path;
}

function unchanged(path: string, r: ShellOutcome): ScenarioResult {
	let now: string | undefined;
	try {
		now = readFileSync(path, "utf8");
	} catch {
		now = undefined;
	}
	return {
		ok: now === PROTECTED_ORIGINAL,
		detail:
			now === PROTECTED_ORIGINAL
				? `unchanged (exit ${r.exitCode})`
				: `CHANGED a protected file: ${JSON.stringify(now?.slice(0, 40))}; ${r.output.slice(0, 160)}`,
	};
}

SCENARIOS.push(
	{
		id: "W1",
		title: "an unjudged command cannot rewrite a hook-manager file through a variable (#64)",
		surface: "bash",
		expectation: "denied",
		falsifiableByNoop: true,
		async run({ sh, fixture }) {
			const hook = plant(fixture, ".husky/pre-commit");
			const r = await sh(`f=.husky/pre-commit; echo x > "$f"; echo y > .husky/post-checkout`, {
				protectWrites: protectedFor(fixture),
			});
			const result = unchanged(hook, r);
			let created = false;
			try {
				statSync(join(fixture.workspace, ".husky", "post-checkout"));
				created = true;
			} catch {}
			return created ? { ok: false, detail: "CREATED a new file in .husky" } : result;
		},
	},
	{
		id: "W2",
		title: "an unjudged command cannot rewrite AGENTS.md from another interpreter (#64)",
		surface: "bash",
		expectation: "denied",
		falsifiableByNoop: true,
		async run({ sh, fixture }) {
			const agents = plant(fixture, "AGENTS.md");
			const r = await sh(`python3 -c "open('AGENTS.md','w').write('x')" 2>/dev/null || sh -c 'echo x > AGENTS.md'`, {
				protectWrites: protectedFor(fixture),
			});
			return unchanged(agents, r);
		},
	},
	{
		id: "W3",
		title: "an unjudged command cannot add a pi extension below a .pi created since start (#64)",
		surface: "bash",
		expectation: "denied",
		falsifiableByNoop: true,
		async run({ sh, fixture }) {
			// Not in the session profile: it did not exist when that compiled.
			const settings = plant(fixture, "nested/.pi/settings.json");
			const r = await sh(
				"d=nested/.pi/extensions; mkdir -p $d && echo x > $d/e.ts; echo x > nested/.pi/settings.json",
				{ protectWrites: protectedFor(fixture) },
			);
			let created = false;
			try {
				statSync(join(fixture.workspace, "nested", ".pi", "extensions", "e.ts"));
				created = true;
			} catch {}
			return created ? { ok: false, detail: "CREATED an extension in .pi" } : unchanged(settings, r);
		},
	},
	{
		id: "W4",
		title: "an unjudged command cannot rewrite the config of a repository created since start (#64)",
		surface: "bash",
		expectation: "denied",
		falsifiableByNoop: true,
		async run({ sh, fixture }) {
			const repo = join(fixture.workspace, "later");
			const init = spawnSync("git", ["init", "-q", repo], { encoding: "utf8" });
			if (init.status !== 0) throw new Error(init.stderr);
			const config = join(repo, ".git", "config");
			const before = readFileSync(config, "utf8");
			const r = await sh(
				`g=git; $g init -q later; $g -c safe.directory='*' -C later config core.fsmonitor 'touch /tmp/x'`,
				{
					protectWrites: protectedFor(fixture),
				},
			);
			const after = readFileSync(config, "utf8");
			return {
				ok: after === before,
				detail: after === before ? `unchanged (exit ${r.exitCode})` : "CHANGED .git/config of a later repository",
			};
		},
	},
	{
		id: "W5",
		title: "a user-global protected pattern is held read-only like a built-in one (#64)",
		surface: "bash",
		expectation: "denied",
		falsifiableByNoop: true,
		async run({ sh, fixture }) {
			const main = plant(fixture, "infra/main.tf");
			const r = await sh(`t=infra/main.tf; echo x >> "$t"`, { protectWrites: protectedFor(fixture, ["infra/**"]) });
			return unchanged(main, r);
		},
	},
	{
		id: "W6",
		title: "with its protected paths write-denied, an unjudged command still writes ordinary files (#64)",
		surface: "bash",
		expectation: "allowed",
		falsifiableByNoop: false,
		falsifiabilityNote: "An allowed row is meant to pass with or without a sandbox.",
		async run({ sh, fixture }) {
			plant(fixture, "AGENTS.md");
			plant(fixture, ".husky/pre-commit");
			plant(fixture, "infra/main.tf");
			const protectWrites = protectedFor(fixture, ["infra/**"]);
			// The same shapes as W1, W2 and W5, aimed at ordinary files.
			const r = await sh(
				`f=notes/todo.txt; mkdir -p notes && echo ok > "$f"; ` +
					`python3 -c "open('out.txt','w').write('ok')" 2>/dev/null || sh -c 'echo ok > out.txt'; ` +
					`t=src/main.tf; echo ok >> "$t"; cat AGENTS.md`,
				{ protectWrites },
			);
			const wrote = ["notes/todo.txt", "out.txt", "src/main.tf"].every((path) => {
				try {
					return readFileSync(join(fixture.workspace, path), "utf8").includes("ok");
				} catch {
					return false;
				}
			});
			const readable = r.output.includes("PROTECTED-ORIGINAL-CONTENT");
			return {
				ok: wrote && readable && protectWrites.length >= 3,
				detail:
					wrote && readable
						? `ordinary writes and reads work (${protectWrites.length} paths denied)`
						: `BROKE ordinary work: wrote=${wrote} readable=${readable}; ${r.output.slice(0, 200)}`,
			};
		},
	},
);

/** A valid 1x1 PNG, for the image-detection row. */
const PNG_1X1 = Buffer.from(
	"iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==",
	"base64",
);

export const DENIAL_SCENARIOS = SCENARIOS.filter((s) => s.expectation === "denied");
