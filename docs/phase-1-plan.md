# Phase 1 implementation plan — Sandbox core

**Outcome (from the README):** every pi command and file operation on macOS and Linux runs
in `workspace-write` with no network. No model involved yet.

**Baseline:** `@earendil-works/pi-coding-agent` `>=0.84.2 <0.85.0`, reference commit
`c49906e`. Local checkout `frycm/pi` is at `v0.84.2` (`914cf1472`); all file references
below were verified there.

## Verified integration facts

These are the things the plan depends on. Each was checked in the pi source, not assumed.

| Fact | Where | Consequence |
|---|---|---|
| `BashOperations.exec(command, cwd, { onData, signal, timeout, env })` is the whole bash execution surface | `src/core/tools/bash.ts:62` | One `exec` implementation sandboxes the `bash` tool |
| `user_bash` handler may return `{ operations: BashOperations }` | `src/core/extensions/types.ts:1083` | `!` / `!!` reuse the same operations object; no second code path |
| `ReadOperations` = `readFile`, `access`, `detectImageMimeType?` | `read.ts:49` | Fully redirectable |
| `EditOperations` = `readFile`, `writeFile`, `access` | `edit.ts:85` | Fully redirectable |
| `WriteOperations` = `writeFile`, `mkdir` | `write.ts:31` | Fully redirectable |
| `FindOperations` = `exists`, `glob`; `fd` is spawned **only** when no custom `glob` is supplied | `find.ts:55`, `find.ts:225` | Redirectable without re-implementing |
| `LsOperations` = `exists`, `stat`, `readdir` | `ls.ts:37` | Fully redirectable |
| `GrepOperations` = `isDirectory`, `readFile`; `rg` is spawned unconditionally from the pi process | `grep.ts:56`, `grep.ts:177-226` | **Must be re-implemented**, as the README says |
| pi's sandbox example calls `SandboxManager.wrapWithSandbox(command)` then `spawn("bash", ["-c", …], { cwd })` with inherited `process.env` | `examples/extensions/sandbox/index.ts:133-140` | Usable as a skeleton; the env inheritance is exactly the leak `ChildEnv` must close |
| The example pins `@anthropic-ai/sandbox-runtime@0.0.26`; npm latest is `0.0.73` | `examples/extensions/sandbox/package.json` | SRT capability must be re-verified on a current version before anything is built on it |

## Exit criteria

Phase 1 is done when all of the following hold on **both** backends (`seatbelt` on macOS,
`bwrap` on Linux), in CI:

1. The Phase-1 rows of the platform matrix pass as automated tests (listed in step 3).
2. `bash`, `read`, `edit`, `write`, `find`, `ls`, `grep` and `user_bash` all go through the
   backend; no file operation is performed by the pi process.
3. Sandbox denials reach the model as a structured `Violation` in tool output.
4. `/enclave status` and `/enclave backend` work; the status line shows backend and mode.
5. Read latency through the helper is measured and recorded in the README.
6. `probe()` fails closed outside the peer range and when the backend prerequisites
   (`sandbox-exec`, `bwrap`, `socat`, `rg`, `fd`) are missing.

## Work breakdown

Steps are ordered so the riskiest assumption — that SRT delivers the matrix guarantees —
is tested before anything is built on it. Each step names what it produces and how it is
verified.

### Step 0 — SRT capability spike

*Throwaway code. Output is a written decision, not a module.*

Pin a candidate SRT version (start with latest, `0.0.73`) and answer, by running real
commands through `wrapWithSandbox` on macOS and Linux:

- **Read deny:** does `filesystem.denyRead` stop `cat ~/.ssh/id_ed25519` at the kernel on
  both platforms?
- **Network off:** with `network.allowedDomains: []`, are `curl`, `nc`, raw `python socket`
  and DNS all denied? Does SRT still start its proxy, and can the child reach it?
- **Unix sockets:** are `/var/run/docker.sock`, `$SSH_AUTH_SOCK`, `~/.gnupg/S.gpg-agent`
  unreachable by default, and is `allowUnixSockets` something we can refuse to expose?
- **Violation detection:** how does SRT surface a kernel denial (macOS `sandbox-exec`
  log / bwrap exit code) so it can be distinguished from an ordinary non-zero exit?
- **Long-lived child:** can a process started under the profile stay alive across calls
  (needed for the fs helper), or does SRT assume one-shot commands?
- **Profile access:** can we get the compiled Seatbelt profile / bwrap argv out of SRT,
  for `/enclave backend` diagnostics and for the conformance suite to assert on?

**Decision recorded:** exact SRT version to pin, and whether `wrapWithSandbox` is
sufficient or the backend must call SRT's lower-level profile generation. If any of the
first three answers is "no", the backend design changes here — before step 2.

### Step 1 — Package scaffold

- npm package `pi-enclave`, ESM, TypeScript, vitest; `pi.extensions` entry in
  `package.json` so `pi -e ./pi-enclave` loads it.
- `peerDependencies`: `@earendil-works/pi-coding-agent` `>=0.84.2 <0.85.0`;
  `dependencies`: `@anthropic-ai/sandbox-runtime` pinned exactly (from step 0).
- `probe()`: reads the installed pi version, refuses outside the range; checks backend
  prerequisites per platform; returns a structured report used by `/enclave status`.
- CI: GitHub Actions matrix `macos-latest` + `ubuntu-latest` (with `bubblewrap socat
  ripgrep fd-find` installed). The conformance suite from step 3 runs here.

**Verified by:** `probe()` unit tests with a mocked pi version; CI green on both runners
with an empty test suite.

### Step 2 — `SandboxBackend` interface, `Violation`, `ChildEnv`

Pure TypeScript, no OS calls, fully unit-tested.

```ts
interface SandboxBackend {
  name: "seatbelt" | "bwrap";
  probe(): Promise<ProbeReport>;
  compile(profile: Profile): Promise<CompiledProfile>;        // done once per session
  run(compiled: CompiledProfile, req: RunRequest): Promise<RunResult>;  // bash + helper start
  fs(compiled: CompiledProfile): FsClient;                     // step 6
}

type RunResult = { exitCode: number | null; violations: Violation[] };
type Violation = { kind: "read" | "write" | "network" | "exec" | "socket";
                   path?: string; host?: string; op: string; backend: string };
```

- `Profile` for Phase 1 is `workspace-write` only: writable roots = `cwd` + `$TMPDIR`,
  read-deny = `$defaults.readDeny` (`~/.ssh`, `~/.aws`, `~/.pi/**/auth*`, …),
  `network: "off"`, no unix sockets.
- `buildChildEnv(processEnv, config)` implements the README's `CHILD_ENV_BASE`,
  `passthrough`, credential deny pattern (applied last), `HOME`/`TMPDIR` rewrite and
  `PATH` filtering. Note `BashOperations.exec` receives an `env` option from pi; the
  backend **ignores it** and uses `ChildEnv` — document this in the code.

**Verified by:** property test that no name matching `envDeny` ever survives
`buildChildEnv` regardless of `passthrough`; snapshot tests of the constructed env.

### Step 3 — Backend-conformance suite

A backend-agnostic harness: `describeConformance(backendFactory)` that builds a temp
workspace, plants a fake `$HOME` with `.ssh/id_ed25519`, `.aws/credentials`, sets
`ANTHROPIC_API_KEY` / `AWS_SECRET_ACCESS_KEY` / `GITHUB_TOKEN` in the test process, and
runs every Phase-1 matrix row through the backend under test. Each scenario asserts on
`violations[]`, not on exit codes or stderr text.

| # | Scenario (README matrix, phase 1) | Assert |
|---|---|---|
| C1 | Write outside writable root via `bash`, `write`, `edit` | `Violation{kind:"write"}` |
| C2 | Read `~/.ssh/id_ed25519` via `bash`, `read`, `grep`, `find` | `Violation{kind:"read"}` |
| C3 | Symlink race: canonicalize `ws/link`, then swap it to `~/.ssh`, then `read ws/link/id_ed25519` | violation — helper's `open` denied |
| C4 | Symlink write: `ws/out → /etc/passwd`, `write ws/out` | violation |
| C5 | `curl`, `nc`, `python -c "socket…"`, DNS lookup | `Violation{kind:"network"}` |
| C6 | `vim`/`less` PTY, Python multiprocessing, `git worktree` outside cwd | works / violation as configured |
| C7 | Script calling `sudo`, `su`, `systemctl` | violation, not a policy denial |
| C8 | Connect to docker.sock, gpg-agent, `$SSH_AUTH_SOCK`, X11/Wayland socket | `Violation{kind:"socket"}` |
| C9 | Environment leak: `env`, `sh -c 'echo $ANTHROPIC_API_KEY'`, `os.environ`, `/proc/self/environ` | none of the values present; `passthrough` entry matching `envDeny` rejected at config load |
| C10 | Happy path: write inside cwd and `$TMPDIR`, read project files, run `git status` | works, zero violations |

C3/C4 and the `read`/`grep`/`find` variants of C2 cannot pass until step 6; they are
written now and marked `todo` so the suite documents the gap the status line reports.

**Verified by:** the suite itself runs against a deliberately broken `NoopBackend` and
fails every row — proving the tests can fail.

### Step 4 — `seatbelt` backend and the `bash` override

- `SeatbeltBackend` wraps SRT per the step-0 decision; `run()` spawns through `ChildEnv`
  only (never `process.env`), in its own process group, honours `signal` and `timeout`
  the way pi's `createLocalBashOperations` does (`bash.ts:88`), and maps kernel denials
  to `Violation[]`.
- `createEnclaveBashOperations(backend, compiled)` returning `BashOperations`.
- Extension entry: `pi.registerTool(createBashTool(cwd, { operations }))` with
  re-declared `promptSnippet` / `promptGuidelines` describing the violation format;
  `pi.on("user_bash", () => ({ operations }))`.
- Violations are appended to tool output as a fenced `enclave-violation` block and to
  `details`, so the model sees *why* a command failed.

**Verified by:** conformance rows C1 (`bash`), C2 (`bash`), C5–C10 green on macOS.

### Step 5 — `bwrap` backend

Same shape as step 4 on Linux. Expect platform-specific work on: `/proc/self/environ`
(C9), `--die-with-parent` so the helper is reaped, and the network namespace for `off`
mode (verify SRT does not rely on its proxy being reachable).

**Verified by:** the same rows green on `ubuntu-latest` in CI.

### Step 6 — `pi-enclave-fs` helper

A small Node script (shipped in the package, started by `backend.run` once per compiled
profile, long-lived) speaking length-prefixed JSON over stdio:

```
→ { id, op: "readFile" | "access" | "writeFile" | "mkdir" | "stat" | "readdir"
         | "exists" | "glob" | "grep", ...args }
← { id, ok: true, result } | { id, ok: false, violation: Violation } | { id, ok: false, error }
```

- `glob` shells out to `fd`, `grep` to `rg --json`, both **from inside the helper** so the
  binaries run under the profile.
- `FsClient` in the pi process: request/response multiplexing, per-call timeout, restart
  on helper crash (with the crash logged as an audit-worthy event for Phase 2).
- Helper denials are recognised by `EACCES`/`EPERM` from the kernel and reported as
  `Violation`, never retried in-process.

**Verified by:** protocol unit tests with a fake helper; C3 and C4 now pass on both
backends.

### Step 7 — File tool overrides

- `read`, `edit`, `write`, `find`, `ls`: `pi.registerTool(createXTool(cwd, { operations }))`
  where each `*Operations` delegates to `FsClient`. `find` supplies `glob` so pi never
  spawns `fd` (`find.ts:225`).
- `grep`: copy `grep.ts` into `src/tools/grep.ts`, keep pi's argument handling, output
  formatting and renderers, replace the `spawn(rgPath …)` block (`grep.ts:177-226`) with
  `FsClient.grep`. Track the copied file's upstream hash so baseline bumps flag drift.
- Remove the "L2 narrowed to shell execution" caveat from the status line once this lands.

**Verified by:** C2 `read`/`grep`/`find` variants green; pi's own tool tests ported for the
re-implemented `grep` to catch formatting regressions.

### Step 8 — Commands, status, diagnostics

- `registerCommand("enclave")` with `status` (probe report, backend, mode, violation
  counts) and `backend` (compiled profile dump — the Seatbelt SBPL / bwrap argv).
- Status-line footer: `enclave: seatbelt · workspace-write · net off · 3 violations`.
- `/enclave violations`: last N violations this session.

**Verified by:** snapshot test of the status output; manual check in the TUI.

### Step 9 — Matrix sign-off and measurement

- Full conformance suite green on both backends in CI; README's platform matrix rows
  marked 1 link to their test IDs.
- Measure: `read` of a 1 MB file and `grep` over the pi repo via the helper vs. direct,
  on both platforms; record numbers in the README ("read latency is measured in Phase 1").
- Update the README's *Status* box from "no implementation" to "Phase 1 complete,
  Phase 2 in progress" and list known gaps.

## Package layout

```
pi-enclave/
  package.json              # pi.extensions → ./src/index.ts
  src/
    index.ts                # extension entry: probe, register tools, commands
    probe.ts
    config/                 # Phase-1 subset: profile + env passthrough only
    env/child-env.ts
    backend/
      types.ts              # SandboxBackend, Profile, Violation, RunRequest
      seatbelt.ts
      bwrap.ts
      srt.ts                # thin SRT adapter shared by both
    fs/
      helper.ts             # runs inside the sandbox
      protocol.ts
      client.ts             # FsClient
    tools/
      bash.ts               # operations factory
      file-ops.ts           # Read/Edit/Write/Find/Ls operations from FsClient
      grep.ts               # copied + modified from pi c49906e
    commands/enclave.ts
  test/
    conformance/            # describeConformance + scenarios C1–C10
    unit/
  docs/phase-1-plan.md
```

## Risks and how the plan contains them

| Risk | Containment |
|---|---|
| SRT cannot express a Phase-1 guarantee (most likely: unix-socket deny or DNS in `off` mode) | Step 0 finds out first; fallback is generating the Seatbelt profile / bwrap argv ourselves for that one feature while still using SRT for the rest |
| SRT `wrapWithSandbox` assumes one-shot commands; a long-lived helper is awkward | Step 0 checks; fallback is a per-call helper spawn (slower — measured in step 9) |
| Kernel denial is not distinguishable from an ordinary failure | Seatbelt: read the sandbox log; bwrap: inspect `errno` from the helper, and for bash rely on stderr pattern + exit code with `Violation.confidence` flagged — decide in step 0 |
| The copied `grep.ts` drifts from upstream | Stored upstream hash checked in the baseline-bump script |
| `examples/extensions/sandbox` semantics change in a later 0.84.x patch | The baseline is a bounded range; CI installs the exact pi version under test |

## Explicitly out of Phase 1

Policy rules, action lock, circuit breaker, attendance contract, audit log, any reviewer,
egress proxy, Docker backend, Windows, ops profile, and every core change to pi. The
load-order/tool-shadowing check is Phase 2; in Phase 1 pi-enclave simply assumes it is
the last extension to register these tools.
