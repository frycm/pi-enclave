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
  a denial detector there -- and through `bash` specifically, a read denial is *entirely*
  invisible: no event, and an `ENOENT` the shell reports as a missing file. Enforcement
  holds; only reporting degrades. The file tools are unaffected because the helper sees the
  real errno.
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

### Step 2 — `SandboxBackend` interface, `Violation`, `ChildEnv` ✅ done

Pure TypeScript, no OS calls. 67 new tests (95 total), with the three critical behaviours
mutation-checked to prove the tests can fail.

| Module | What it settles |
|---|---|
| [`backend/types.ts`](../src/backend/types.ts) | `SandboxBackend`, `Profile`, `CompiledProfile`, `Violation`, `FsClient`, `SandboxDenied`. `Profile` records the asymmetry SRT imposes: writes are an allow-list, reads a deny-list |
| [`backend/paths.ts`](../src/backend/paths.ts) | Whole-segment containment, so `/opt/secretsbin` is not inside `/opt/secrets` |
| [`backend/errno.ts`](../src/backend/errno.ts) | `classifyErrno` — the per-backend denial table, and the `ENOENT` disambiguation |
| [`backend/violations.ts`](../src/backend/violations.ts) | Per-backend line parsing and noise lists, built from lines captured verbatim in step 0 |
| [`env/child-env.ts`](../src/env/child-env.ts) | `buildChildEnv`, `validatePassthrough`, the credential deny list applied last |

**Decisions worth carrying forward:**

- **An unparseable violation line never becomes a `Violation`.** A fabricated denial is
  worse than a missed log line, which is still in the raw audit either way.
- **`formatViolations` is backend-neutral.** An agent that learns one platform's vocabulary
  would not recognise the other's, so the rendering names the kind and target, never the
  mechanism. Asserted in tests.
- **`EROFS` counts as a denial unconditionally.** A user whose workspace sits on a genuinely
  read-only mount gets a violation rather than a plain error — a legible failure, not a
  dangerous one.
- **`validatePassthrough` refuses loudly** rather than dropping silently: someone who listed
  `FOO_TOKEN` believes it is reaching the sandbox. `buildChildEnv` also strips it, so the
  validation is the diagnostic and not the enforcement.

**Mutation checks** (each reverted after): dropping `EROFS` from the denial set failed 4
tests including cross-backend parity; moving the credential deny list off the end failed
the property test and two others; degrading path containment to a string prefix failed 3
tests across two modules.

### Step 3 — Backend-conformance suite ✅ done

The matrix as executable scenarios, plus the control that keeps them honest.
`npm run conformance:report` prints the table.

| File | Role |
|---|---|
| [`fixture.ts`](../test/conformance/fixture.ts) | The world each scenario runs against; plants secrets and the symlink pair |
| [`scenarios.ts`](../test/conformance/scenarios.ts) | C1–C11, each asserting a security property |
| [`runner.ts`](../test/conformance/runner.ts) | Runs them against any backend, returning results rather than asserting |
| [`noop-backend.ts`](../test/conformance/noop-backend.ts) | Enforces nothing. The falsifiability control |
| [`falsifiability.test.ts`](../test/conformance/falsifiability.test.ts) | Requires every falsifiable denial row to fail unsandboxed |

**Scenarios assert the security property, never the mechanism** — did the secret leak, did
the file get written, did the connection open. Exit codes and violation counts are recorded
as evidence but never used as the verdict, because step 0 proved neither is portable. Every
denied target is a temp directory the test user genuinely could reach: a scenario aimed at
`/etc/passwd` would "pass" unsandboxed purely because the tests do not run as root, which
would make the suite unfalsifiable in exactly the way it exists to prevent.

**The control caught three real defects on its first run:**

- Scenarios shared one fixture, so C4 correctly overwrote its target and silently broke C11,
  which reads the same file. Each scenario now builds its own world.
- **C7** (sudo/su) passed unsandboxed — it was measuring "the test user is not root".
- **C9** (environment) passed unsandboxed — credential isolation is enforced by
  `buildChildEnv` in the pi process, not by the kernel.

C7 and C9 are marked `falsifiableByNoop: false` with a **required** note, and the meta-test
asserts every exemption carries one: an unexplained exemption is indistinguishable from a
scenario someone silenced to get a green run. C9 gets its own control — run it with the raw
parent environment, which is what pi's example and SRT both hand over, and require it to
catch the leak.

The network row's control is guarded by a host-capability probe, so an isolated runner
reports "cannot run this control" rather than "the suite is not falsifiable".

**Steps 4-5 point the same suite at the real backends, where every row must pass.**

### Step 4 — `seatbelt` backend and the `bash` override ✅ done

**Every conformance row passes against the real backend on macOS.** `npm run
conformance:report -- srt` prints the table.

**One backend serves both platforms.** SRT abstracts seatbelt and bwrap behind
`wrapWithSandboxArgv`, and step 0 ran byte-identical code on each — so
[`srt.ts`](../src/backend/srt.ts) is the whole implementation and **step 5 becomes "verify
on Linux" rather than "write a second backend"**. The differences that do matter (errno,
whether an event is emitted) already live in `errno.ts` and `violations.ts`, keyed by name.

Delivered: [`backend/srt.ts`](../src/backend/srt.ts),
[`config/profile.ts`](../src/config/profile.ts), [`tools/bash.ts`](../src/tools/bash.ts),
the `bash` override and `user_bash` routing in [`index.ts`](../src/index.ts),
`/enclave status|backend|violations`.

**Decisions worth carrying forward:**

- **The violation settle policy** replaces the spike's flat 800 ms sleep: poll until the
  count is stable for two reads, capped at 750 ms. Faster when there are none, more
  complete during a burst. The bound is acceptable precisely because violations are
  evidence, never the verdict.
- **SRT's default write paths are denied.** `getDefaultWritePaths()` unions `~/.npm/_logs`
  and `~/.claude/debug` into every profile; a sandbox that can write those is wider than the
  status line claims, and `~/.claude/debug` sits beside configuration steering another agent.
- **A stale `CompiledProfile` now fails closed.** A biome unused-parameter warning surfaced
  a real hazard: `run()` ignored the profile it was handed, because `wrapWithSandboxArgv`
  reads the manager's global state. Holding an older profile would have executed under a
  newer, possibly wider one. Profiles carry a generation and mismatches throw.
- **`/enclave status` states the coverage gap**: L2 covers shell execution only until
  step 6. A status line that overstated the boundary is the one lie this project cannot afford.

**Verified against real pi**, not only in tests — read inside the workspace works, the write
outside is denied and the file never created, network refused, and the `sandbox denied:`
annotation reaches the agent. That run also exposed a benign `SystemConfiguration.configd`
mach-lookup cluttering the line that mattered, now filtered **by name** rather than ignoring
`mach-lookup` as a class, since other mach services are genuinely powerful.

### Step 5 — Verify the backend on Linux ✅ done (with one gap that needs CI)

**Every conformance row passes on Linux/bwrap.** Run with
`PI_ENCLAVE_WEAKER_NESTED=1 npm run conformance:report -- srt` in a privileged container.

**What this verifies and what it cannot.** No container mode on this host gives
capability-bearing nested user namespaces — `--privileged`, `--userns=host` and
`--cap-add=SYS_ADMIN` all fail — so the run uses SRT's `enableWeakerNestedSandbox`. That
mode changes only bwrap's flags and **still runs `apply-seccomp`**, so the filesystem,
network, socket, environment and seccomp-dependent rows are all genuinely exercised. What
it cannot verify is the capability drop itself. That needs a real Linux host: **the CI run
is the remaining gap.**

**Three findings, each from a control rather than from inspection:**

- **`probe()` was checking the wrong thing.** The sysctl was a proxy for the real question
  and gives a false pass exactly where phase 4 will live: inside a container the sysctl is
  *absent* and plain `bwrap` *succeeds*, yet the nested namespace `apply-seccomp` needs
  cannot be created. Both heuristics said "ready" while every command would have failed.
  `probe()` now runs the real chain and reports the actual error.
- **C8 was testing nothing on a host without Docker.** It connected to `/var/run/docker.sock`
  and a fixture path with no listener, so `connect()` failed with `ENOENT` and the row passed
  against a backend that enforces nothing. The Linux noop control reported it immediately.
  The fixture now runs a real listener.
- **The weakening is now a test, not a footnote.** New row **C12** asserts the sandboxed
  process holds no capabilities — precisely what weaker mode gives up, leaving
  `CapEff=000001ffffffffff` and the ability to create mount namespaces. Three escape attempts
  from that position failed, which is not proof none exists. C12 correctly **fails** in the
  container run, so a weakened run reports the difference instead of looking identical to a
  real one.

`weakerNestedSandbox` is an explicit opt-in, **never inferred** — a sandbox that silently
downgraded itself when the host looked awkward would keep saying "enforced" while the
boundary thinned. It surfaces in `/enclave status` and on the report's first line.

### Step 6 — `pi-enclave-fs` helper ✅ done

Delivered: [`fs/protocol.ts`](../src/fs/protocol.ts),
[`fs/helper.mjs`](../src/fs/helper.mjs), [`fs/client.ts`](../src/fs/client.ts), the
`backend.fs()` wiring, five conformance rows (F1–F5), 9 protocol unit tests, and
`npm run bench:fs`.

**Length-prefixed framing, not newline-delimited.** File contents and search results
contain newlines; a framing its own payload can confuse desynchronises mid-session and
returns one file's bytes in answer to another file's request. Binary travels base64 inside
one uniform frame type — the extra third on reads buys away a second frame kind whose
failure mode is exactly what the framing exists to prevent.

**The helper reports errnos, never verdicts.** Only the pi process holds the compiled
profile, and on Linux an `ENOENT` is a denied read or a missing file depending on it.
Classifying in the helper would put that decision on the wrong side of the boundary. F1 and
F4 assert both directions: a denial must be *classified* as one, and a genuine typo must not.

**The suite caught a real secret leak.** `backend.fs()` cached one client per backend while
`compile()` can replace the profile, so a helper started under an earlier profile kept
enforcing it — refusing writes to the new workspace and, worse, permitting reads the new
profile denied. F3 leaked a key through a symlink. A helper is bound to the profile the
kernel applied at `exec` and cannot be updated, so it is now retired when the generation
changes.

**Measured** (exit criterion 5):

| | macOS / seatbelt | Linux / bwrap |
|---|---|---|
| helper startup (once per profile) | 55 ms | 25 ms |
| read 4 KB | 0.067 ms | 0.136 ms |
| read 1 MB | 1.78 ms | 7.17 ms |
| stat | 0.039 ms | 0.093 ms |
| write 4 KB | 0.073 ms | 0.156 ms |

Per-call overhead is far below a spawn, which is why the helper is long-lived rather than
started per operation.

### Step 7 — File tool overrides ✅ done

All six file tools now reach the filesystem through the helper.
[`file-ops.ts`](../src/tools/file-ops.ts) backs `read`, `edit`, `write`, `ls` and `find`;
[`grep.ts`](../src/tools/grep.ts) replaces the one pi will not let us redirect.

**`grep` keeps pi's tool and replaces only `execute`.** Its operations object abstracts the
filesystem walk but the tool spawns `rg` itself, so without this a `grep` over a credential
directory reads it with the user's full privileges whatever profile is in force. Copying
pi's four hundred lines was the alternative; spreading the tool leaves far less to keep in
step on a baseline bump and keeps the schema, renderers and description byte-identical to
the built-in. Context lines go back through the helper too — fetching them in the pi process
would reopen exactly the hole the module closes.

**Operations take a getter, not a client.** Tools register before any profile is compiled,
and a captured client would either fail at load or keep a tool bound to a retired helper
still enforcing an older profile.

**Three things only the real run found:**

- **`rg` and `fd` are resolved in the pi process** and passed in as absolute paths. pi
  downloads them into its own directory, so they are often absent from PATH — and the helper
  has no network to fetch them. This closes the step-1 finding.
- **`fd` 8.x rejects `--no-require-git`**, which pi passes. The helper uses a conservative
  flag set every supported `fd` understands.
- **That unknown flag made `fd` exit 2 with empty stdout, and the helper reported zero
  results** — indistinguishable from "nothing matched", and enough to convince an agent a
  file does not exist. Both search operations now treat exit > 1 as a failure; exit 1 stays
  a real answer, since that is how `fd` and `rg` say "no matches".

Verified on both platforms: reads, listings, globs and searches work; a read of `~/.ssh` is
denied **and reported as a denial rather than a missing file**, which matters most on Linux
where the raw errno is `ENOENT`.

**Known limitation, unchanged from step 0:** a *denied grep* on Linux returns "No matches
found" rather than a denial, because the deny-read tmpfs makes the directory look empty to
`rg`. Nothing leaks; the report is just weaker than it should be.

The status line no longer claims shell-only coverage.

### Step 8 — Commands, status, diagnostics ✅ done

[`commands/enclave.ts`](../src/commands/enclave.ts) renders `/enclave
status|backend|violations` and the footer as pure functions over a state snapshot, so the
surface a user reads is tested against constructed states rather than observed by eye.

**The status line was lying, and the test caught it.** It derived "active" from whether the
probe passed — so a *weakened* run, which legitimately fails the namespace-nesting check,
displayed **NOT ACTIVE while visibly denying reads**. That is the worst configuration to be
wrong in: it invites someone to assume nothing is enforced and act on it. "Active" now comes
from whether a profile compiled. The probe is a startup gate; once a profile is in force,
the compiled profile is the fact.

**Filesystem-helper denials now reach the counter and footer.** Without that wiring the file
tools would enforce silently, making step 7 invisible in the one place anyone looks.

The rule the module follows: **anything that weakens the boundary appears without being
asked for.** `WEAKENED` in the one-line summary and explained in the report; a profile that
has not started; a probe that refused. `status` states what is *not* covered — MCP and
third-party tools run in the pi process — because omitting it would imply total coverage.
`backend` prints the compiled profile verbatim, since anyone checking the sandbox needs the
artefact the kernel was given rather than our description of it.

```
enclave: bwrap · workspace-write · net off · WEAKENED · 1 denied
```

### Step 9 — Matrix sign-off and measurement ✅ done

The README stops being a pure proposal. Its status box separates what is built — the
OS-enforced sandbox — from what is still design, and links the known gaps rather than
leaving a reader to infer coverage from the architecture sections.

**Two claims the spike disproved are corrected in place:** `network.mode: "off"` is not
kernel-absolute (raw sockets and DNS die at the kernel; HTTP reaches a loopback proxy that
refuses it, which is userspace), and reads are a **deny-list**, not the allow-list
"read-only root" implied.

**Phase-1 matrix rows name the scenario that proves them** (C1–C12, F1–F5), with a note on
why scenarios assert the security property rather than exit codes, and on the two rows the
noop control cannot falsify.

**Measured against the same operation done directly in the pi process**, since the multiple
is the part a faster machine will not improve away:

| | macOS / Seatbelt | Linux / bwrap |
|---|---|---|
| profile compile (once per session) | 25 ms | 145 ms |
| helper startup (once per profile) | 62 ms | 24 ms |
| read 4 KB | 0.073 ms · 3.4x direct | 0.146 ms · 20x direct |
| read 1 MB | 1.85 ms · 22x direct | 6.78 ms · 48x direct |
| `grep` over the source tree | *(no `rg` on the host)* | 4.3 ms |

The multiples look alarming; the absolute numbers are what matter. A read costs tens of
microseconds more, and an agent waits on the model by four orders of magnitude more than on
the sandbox.

**Gaps recorded rather than smoothed over:** MCP tools are unsandboxed, a denied read
through `bash` is invisible on Linux, weaker nested mode leaves capabilities, CI has not run
on a real Linux host, `rg`/`fd` must be on PATH, and only one profile can be in force.

---

## Phase 1: done, with one thing outstanding

Steps 0–9 are complete. 188 tests, green on macOS and in a privileged Linux container;
`tsc` and biome clean.

**Exit criteria:**

| # | Criterion | State |
|---|---|---|
| 1 | Phase-1 matrix rows pass as automated tests | ✅ both backends |
| 2 | All seven tools and `user_bash` go through the backend | ✅ |
| 3 | Denials reach the model as a structured `Violation` | ✅ — with the Linux `bash`-read gap recorded |
| 4 | `/enclave status` and `backend` work; status line shows backend and mode | ✅ |
| 5 | Helper latency measured and recorded | ✅ above and in the README |
| 6 | `probe()` fails closed | ✅ — and now checks namespace nesting functionally |

**Outstanding: the CI run on a real Linux host.** Everything was verified on macOS and in a
privileged container, and the container cannot verify the capability drop (C12) because no
container mode on this host gives capability-bearing nested user namespaces. That is the one
claim in the matrix still resting on inference rather than a passing test.

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
