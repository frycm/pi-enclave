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
   (`sandbox-exec`, `bwrap`, `socat`) are missing, and warns on `rg`/`fd` — pi fetches
   those on demand, so absence from PATH is not a sandbox failure (step 1).

## Work breakdown

Steps are ordered so the riskiest assumption — that SRT delivers the matrix guarantees —
is tested before anything is built on it. Each step names what it produces and how it is
verified.

### Step 0 — SRT capability spike ✅ done

Full write-up: [step-0-srt-findings.md](step-0-srt-findings.md).

**Verdict: SRT is sufficient for Phase 1 on both backends**; pin **`0.0.73`** (not the
`0.0.26` pi's example bundles) and use `wrapWithSandboxArgv`. Every filesystem, network and
socket matrix row is kernel-enforced on macOS/Seatbelt and on Linux/bwrap.

Results that change the steps below:

- **`ChildEnv` composes with SRT for free.** SRT injects its own variables as an
  `env NAME=VALUE …` prefix *inside the argv*, so `spawn` can be handed a strict allowlist
  env: SRT's proxy vars survive, and none of the parent's credentials leak. Verified with
  `ANTHROPIC_API_KEY`, `AWS_SECRET_ACCESS_KEY` and `GITHUB_TOKEN` set in the parent.
- **Violations arrive three ways** — errno (fs helper), kernel log line (bash), proxy
  (network) — so `Violation` needs a `source` field, and `SandboxViolationEvent` is a raw
  log line that must be parsed. **The fs helper needs no log parsing at all**: the errno is
  exact and synchronous.
- **The long-lived helper works on both backends**: 40 ms startup / 0.02 ms per round-trip
  on macOS, 28 ms / 0.08 ms on Linux, enforcement intact. Step 6's design stands; the
  per-call-spawn fallback is not needed.
- **Symlink races are already denied on the resolved path**, so C3/C4 pass through plain
  `bash` — they move from step 6 to steps 4/5.
- **Per-invocation `customConfig`** widens one command without leaking into the next —
  Phase 3's capability retry hatch is confirmed to work.
- **Noise is real, and differs per backend**: benign `sysctl-read` denials on nearly every
  macOS command and 62 spurious `__pycache__` violations from one Python call; 30
  `/dev/shm/sem.*` violations from the same test on Linux, which *succeeded*. A
  `violations.length > 0` check is wrong.
- **PTYs are denied by default** (`allowPty`), and `sudo`/`su` are denied with *no*
  violation event.
- **The backends deny with different errnos** — `EPERM` on macOS, but `EROFS` (writes),
  `ENOENT` (reads, via tmpfs overlay) and `ENETUNREACH` (network) on Linux. A denial is not
  a portable concept, and `ENOENT` cannot be mapped blindly because a missing file and a
  denied file are indistinguishable by errno.
- **On Linux, denied reads emit no violation event at all.** The violation stream cannot be
  a denial detector there.
- **bwrap needs capability-bearing user namespaces**, which `ubuntu-latest` (24.04) blocks
  by default — step 1's CI needs a sysctl, and `probe()` must detect it.

Two README claims need correcting (detail in the findings doc): `network.mode: "off"` is
not kernel-absolute — SRT always starts a reachable localhost proxy that denies HTTP in
userspace — and reads are a **deny-list**, not the allow-list "read-only root" implies.

### Step 1 — Package scaffold ✅ done

Delivered: `package.json` (ESM, `pi.extensions` entry, pi peer range, SRT pinned to
`0.0.73`), `tsconfig`, vitest, biome, [`src/probe.ts`](../src/probe.ts) +
[`src/probe-host.ts`](../src/probe-host.ts), [`src/index.ts`](../src/index.ts),
[`scripts/probe.ts`](../scripts/probe.ts), 28 unit tests, and
[`.github/workflows/ci.yml`](../.github/workflows/ci.yml).

`probe()` is pure with respect to an injected `ProbeEnv`, so the tests exercise the real
decision logic on platforms the test host is not. It checks the pi range (failing on a
newer pi too), Node against SRT's minimum, platform→backend, backend binaries, and the
Linux userns sysctl. The CI Linux job applies
`sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0` and symlinks Debian's
`fdfind` to `fd`.

**Verified beyond the unit tests:**

- `tsc` clean against pi 0.84.2's published types — which corrected two guessed API shapes:
  `registerCommand(name, options)` takes two arguments, and `ctx.ui.notify` is not optional.
- The extension loads in real pi and a turn completes.
- `probe()`'s Linux branch exercised in a container: healthy host, the apparmor
  restriction, and missing `bwrap`/`socat` all produce the right verdict and remediation.

**Two findings for later steps:**

- **`session_start` + `ctx.ui.notify` is not a sufficient channel for a refusal.** Both
  work in `--print` mode, but the message never reaches stdout — invisible in exactly the
  unattended mode where a silent fail-closed is most dangerous. The refusal now goes to
  **stderr at load time**, with the notify kept for interactive users. Phase 2's pending
  approval records and breaker messages need the same treatment.
- **`rg`/`fd` "not on PATH" does not mean "unavailable to pi"** — pi fetches them on demand
  into its own directory. The helper cannot do that fetch (no network), so **step 7 must
  resolve the absolute path outside the sandbox and pass it in**. Until then the check is
  advisory (`warn`, not `fail`).

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
                   source: "errno" | "kernel-log" | "proxy";   // ← from step 0
                   path?: string; host?: string; op: string; backend: string };
```

- `Profile` for Phase 1 is `workspace-write` only: writable roots = `cwd` + `$TMPDIR`,
  read-deny = `$defaults.readDeny` (`~/.ssh`, `~/.aws`, `~/.pi/**/auth*`, …),
  `network: "off"`, no unix sockets.
- `buildChildEnv(processEnv, config)` implements the README's `CHILD_ENV_BASE`,
  `passthrough`, credential deny pattern (applied last), `HOME`/`TMPDIR` rewrite and
  `PATH` filtering. Two things the backend **ignores**: the `env` option pi passes to
  `BashOperations.exec`, and the `env` SRT returns from `wrapWithSandboxArgv` (it is
  `process.env` plus additions — 54 keys including `SSH_AUTH_SOCK`). Both are documented
  in the code. Add `PYTHONDONTWRITEBYTECODE=1` to `CHILD_ENV_BASE`, and note SRT rewrites
  `TMPDIR` to `/tmp/claude` — pi-enclave adopts or overrides it, never assumes the host's.
- **Violation parsing** is per-backend and per-source, with a per-backend default noise
  list (macOS: `sysctl-read`, `__pycache__`; Linux: `/dev/shm/sem.*`) applied before
  anything reaches the status line or the Phase-2 circuit breaker. Kernel-log violations
  are async: the backend needs a defined settle policy before it calls a command's
  violation list complete — the spike used an 800 ms sleep, which is not shippable.
- **`classifyErrno(errno, op, path, profile)`** — the denial errno differs per backend
  (`EPERM` macOS; `EROFS` / `ENOENT` / `ENETUNREACH` Linux), so the mapping is a per-backend
  table, not a check. `ENOENT` on Linux is **ambiguous** — a read-denied path and a missing
  path are indistinguishable — so classification consults the compiled profile's deny list.
  Getting this wrong means either silently missing every Linux write denial, or reporting
  every genuine `ENOENT` as a security violation.
- **The primary denial signal is the operation's own error, never the violation stream.**
  On Linux a denied read produces no violation event, so this is a correctness requirement
  rather than a preference. Violations are supporting evidence for the audit log.

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
| C3 | Symlink race: canonicalize `ws/link`, then swap it to `~/.ssh`, then `read ws/link/id_ed25519` | violation naming the **resolved** path (passes from step 4) |
| C4 | Symlink write: `ws/out → /etc/passwd`, `write ws/out` | violation naming the resolved path (passes from step 4) |
| C5 | `curl`, `nc`, `python -c "socket…"`, DNS lookup | `Violation{kind:"network"}` |
| C6 | `vim`/`less` PTY, Python multiprocessing, `git worktree` outside cwd | works / violation as configured — dev profile sets `allowPty: true` and `PYTHONDONTWRITEBYTECODE=1` |
| C7 | Script calling `sudo`, `su`, `systemctl` | exec denied, not a policy denial — assert on the **exec failure**, not the violation stream (step 0: these produce no violation event) |
| C8 | Connect to docker.sock, gpg-agent, `$SSH_AUTH_SOCK`, X11/Wayland socket | `Violation{kind:"socket"}` |
| C9 | Environment leak: `env`, `sh -c 'echo $ANTHROPIC_API_KEY'`, `os.environ`, `/proc/self/environ` | none of the values present; `passthrough` entry matching `envDeny` rejected at config load |
| C10 | Happy path: write inside cwd and `$TMPDIR`, read project files, run `git status` | works, zero violations |

Only the `read`/`grep`/`find` variants of C2 wait for step 6; they are written now and
marked `todo` so the suite documents the gap the status line reports. C3/C4 pass from
step 4 — step 0 showed Seatbelt evaluates policy against the resolved path, so there is
no check-then-open window to race.

Every scenario also asserts the **noise filter**: a benign `sysctl-read` denial must not
be reported as a violation.

**Verified by:** the suite itself runs against a deliberately broken `NoopBackend` and
fails every row — proving the tests can fail.

### Step 4 — `seatbelt` backend and the `bash` override

- `SeatbeltBackend` calls `wrapWithSandboxArgv(cmd, undefined, customConfig, signal, cwd,
  { commandId, commandText })` and spawns the returned `argv` with our `ChildEnv` — never
  `process.env`, never SRT's returned env. Own process group; `signal` and `timeout`
  handled the way pi's `createLocalBashOperations` does (`bash.ts:88`).
- Violations come from `SandboxManager.getSandboxViolationStore().getViolationsForCommand(id)`,
  correlated by the `commandId` SRT bakes into the SBPL deny message. Use the tool-use id,
  not the command text (SRT compares only the first 100 characters, so long commands
  sharing a prefix cross-attribute).
- `SandboxManager` is a process-global singleton: `initialize()` once per session,
  per-call divergence only via `customConfig`. The backend must not assume two live base
  profiles.
- Audit SRT's **default writable paths** (`/tmp/claude`, `~/.npm/_logs`, `~/.claude/debug`)
  and drop the ones pi-enclave does not advertise — a sandbox that can write
  `~/.claude/debug` is wider than the profile in the status line.
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
- Helper denials go through `classifyErrno` (step 2) and are reported as
  `Violation{source:"errno"}`, never retried in-process. **No log parsing on this path** —
  the errno is exact and synchronous.
- Measured in step 0: **40 ms startup / 0.02 ms per round-trip on macOS, 28 ms / 0.08 ms on
  Linux** over 200 calls, with enforcement (including the symlink case) intact inside the
  helper on both.
- On Linux the helper is **PID 2 in a nested PID namespace**, so it cannot be addressed by
  host PID — lifecycle and restart go through the `spawn` handle, never `kill(pid)`.

**Verified by:** protocol unit tests with a fake helper; the `read`/`grep`/`find` variants
of C2 now pass on both backends.

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
| ~~SRT cannot express a Phase-1 guarantee~~ | **Retired by step 0** on macOS — every matrix row is enforced. Still open for bwrap until CI runs |
| ~~SRT assumes one-shot commands~~ | **Retired by step 0** — the long-lived helper works at 0.02 ms/call |
| ~~Kernel denial indistinguishable from ordinary failure~~ | **Retired by step 0** — errno for the helper, correlated log lines for bash. The residual risk is *noise*, not detection |
| Violation noise makes the breaker and status line useless | Default ignore list from step 0 (`sysctl-read`, `__pycache__`); exit code plus the operation's own error stay the primary signal, violations are evidence |
| Kernel-log violations are async — a command's list may be incomplete when read | Define a settle policy in step 4 and test it; the spike's 800 ms sleep is not shippable |
| ~~bwrap diverges from Seatbelt on a matrix row~~ | **Partly realised in step 0**: every row passes on both, but the *mechanism* diverges (errno, violation presence). Contained by `classifyErrno` and per-backend noise lists, both tested by the shared suite |
| Linux `ENOENT` misclassified — a genuinely missing file reported as a violation, or a denied read reported as absent | `classifyErrno` consults the compiled profile; the conformance suite asserts the classification, not just that the call failed. Both directions get a test |
| bwrap unavailable in the target environment (nested userns, Ubuntu 24.04 sysctl, containers) | `probe()` fails closed with the exact remediation; CI sets the sysctl; Phase 4's Docker backend must record which mode it passed the suite in |
| The copied `grep.ts` drifts from upstream | Stored upstream hash checked in the baseline-bump script |
| `examples/extensions/sandbox` semantics change in a later 0.84.x patch | The baseline is a bounded range; CI installs the exact pi version under test |

## Explicitly out of Phase 1

Policy rules, action lock, circuit breaker, attendance contract, audit log, any reviewer,
egress proxy, Docker backend, Windows, ops profile, and every core change to pi. The
load-order/tool-shadowing check is Phase 2; in Phase 1 pi-enclave simply assumes it is
the last extension to register these tools.
