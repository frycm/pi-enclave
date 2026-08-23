# Phase 2 implementation plan — Policy, lock, breaker, state

**Outcome (from the README):** deterministic auto mode, usable offline with no reviewer at
all — `rules.deny` / `rules.ask` plus the sandbox, `review.trigger` pinned to `boundary`,
every crossing an `ask`.

**Baseline:** `@earendil-works/pi-coding-agent` `>=0.84.2 <0.85.0`, reference commit
`c49906e`. Local checkout `frycm/pi` is at `v0.84.2` (`914cf1472`); every file reference
below was verified there and spot-checked against the installed `dist` types.

**Builds on:** the Phase-1 sandbox core ([phase-1-plan.md](phase-1-plan.md)). Nothing in
this phase touches the backend interface; L2 is finished and this phase puts L1, the lock,
the breaker, L4 and the state machinery around it.

## Verified integration facts

Each fact was checked in the pi source, not assumed. The last column is what it does to the
plan; the next section lists the places where it contradicts the README.

| Fact | Where | Consequence |
|---|---|---|
| `tool_call` handlers run in extension load order, then registration order; the **same `event` object** goes to every handler; `block` short-circuits; a non-blocking result *replaces* (not merges) the previous | `src/core/extensions/runner.ts:932-953` | One handler, registered once. A later extension's mutation of `event.input` is the hazard the lock exists for |
| `event.input` **is** the `validatedArgs` object that `execute` receives — `structuredClone` once at validation, then no copy anywhere down the chain | `agent-loop.ts:618-674`, `agent-session.ts:491`, `validation.ts:318`, `tool-definition-wrapper.ts:17-19` | Deep-freezing `event.input` *is* the action lock: a later handler's write throws, the throw is **not caught** in `emitToolCall`, and `prepareToolCall` turns it into an error result — the tool never runs. Fails closed |
| `toolCall.arguments` (the unvalidated original) is a different object and is what `tool_execution_start` reports | `agent-loop.ts:492-497, 680-687` | The lock covers what executes, not what renders; the audit record carries the canonical form |
| In the default parallel mode, a batch's `tool_call` events fire **strictly sequentially and all complete before any tool in the batch executes**; blocking one does not affect siblings | `agent-loop.ts:489-554` | pi-enclave sees every argument of a batch before any side effect. But a call prepared *before* the breaker trips still executes afterwards — see step 4 |
| `terminate: true` is honoured only on a blocked call, and the agent stops after the batch only if **every** finalized result in the batch set it | `ToolCallEventResult` `types.ts:1071-1080`; `agent-loop.ts:581-583, 634-641` | A breaker trip must mark every subsequent block in the batch `terminate`, and `ctx.abort()` is still needed for the already-prepared calls |
| `tool_result` exists and can rewrite `content`/`details`/`isError` but cannot block or terminate | `types.ts:914-973, 1090-1095` | Used to append the breaker's steering text to the result the model sees; never relied on for enforcement |
| A `tool_call` handler that throws aborts that call with an error result | `runner.ts:940-949`, `agent-session.ts:480-499` | Every unexpected failure in the gate is a denial by construction |
| `input` event carries raw **pre-expansion** text and `source: "interactive" \| "rpc" \| "extension"` (+ `streamingBehavior`); slash commands are dispatched before it fires; `before_agent_start` sees the *expanded* prompt; `message_start` sees the stored message | `types.ts:831-847`; `agent-session.ts:1116-1164, 1233` | Guardian's three-tier provenance matcher ports unchanged. `sendUserMessage` from any extension arrives as `source: "extension"` and is never direct |
| `turn_start { turnIndex }` / `turn_end { turnIndex, message, toolResults }` bracket one assistant message and its tool results | `types.ts:727-740` | A **batch is a turn**. Batch collapsing keys on `turnIndex` and finalizes in `turn_end`; no session-branch walk needed |
| `pi.appendEntry(customType, data)` is synchronous, returns no id, and the session file is **not written until the first assistant message** | `types.ts:1317`; `session-manager.ts:1014-1041, 1122-1135` | Session entries persist the breaker and lock table across resume; pending records and the audit log never rely on them and live in the extension's own directory |
| Resume reads back via `ctx.sessionManager.getEntries()` filtered on `type === "custom"`; `getSessionId()`, `getSessionFile()` (undefined for ephemeral sessions) | `session-manager.ts:190-205, 1007-1013, 1301` | State keyed by session id; an ephemeral session gets no pending records (it cannot be resumed) |
| `ctx.ui.confirm(title, message, { timeout, signal })` and `ctx.ui.input(title, placeholder, { timeout, signal })` exist; **timeout and cancel both resolve to the default** (`false` / `undefined`) and are indistinguishable from the return value | `types.ts:96-148`; `interactive-mode.ts:2481-2540`; `rpc-mode.ts:90-131` | Deny either way, which is the contract. A pi-enclave-owned `AbortSignal` distinguishes them for the audit record only |
| `ctx.mode ∈ {"tui","rpc","json","print"}`; `hasUI` is `true` for tui **and rpc**, `false` for json/print where `confirm` returns `false` immediately | `types.ts:305`; `runner.ts:235-266, 443-445`; `print-mode.ts:75-78` | Confirms the README: `hasUI` cannot mean "a human is present". Print mode denies every `ask` by construction |
| `pi.getAllTools()` returns `ToolInfo[]` with `sourceInfo.path` naming the registering extension; built-ins are `<builtin:name>` | `types.ts:1337-1340, 1576-1578`; `source-info.ts:6-12`; `agent-session.ts:2482-2495` | Tool ownership **is** observable: the load-order check is "is `bash` ours?" |
| Across extensions the **first-loaded extension's tool wins** for a given name; later extensions cannot override it. Extension tools always override built-ins | `runner.ts:451-461`; `agent-session.ts:2490-2495` | An extension that registers `bash` *before* pi-enclave silently disables the sandbox; one that registers it *after* is ignored. The README row has the direction backwards |
| There is **no API to list loaded extensions or `tool_call` handlers**; only `getAllTools()` and `getCommands()` (duplicates suffixed `:1`, `:2` in load order) expose load order indirectly | `runner.ts:447-449` (not reachable from `pi`) | A foreign `tool_call` handler cannot be detected; the freeze makes one loaded after us harmless, and one loaded before us is inside the trusted-extension boundary |
| Project `.pi/extensions` are loaded only when the project is trusted (`~/.pi/agent/trust.json`, `defaultProjectTrust`, `--approve`); `ctx.isProjectTrusted()` is readable; a `project_trust` handler may answer | `trust-manager.ts:29-95`; `package-manager.ts:2375-2412`; `types.ts:332, 519-541` | "Untrusted extension loaded" cannot happen — pi already refuses. The real hazard is a **trusted** project whose `.pi/extensions` the sandboxed agent can write to; that is what the check targets |
| **pi 0.84.2 has no MCP support.** No dependency, no setting, no tool namespace | exhaustive grep; `docs/usage.md:304` | "MCP tools" means "tools from other extensions". The allowlist keys on tool name + `sourceInfo.path`, with no `mcp__` convention to special-case |
| `pi enclave …` **cannot be a pi subcommand** — the subcommand set is closed (`install/remove/update/list/config/auth`) and any other bare word becomes a prompt | `cli/args.ts:229-231, 250-257`; `package-manager-cli.ts:189-199` | Out-of-session commands ship as a package `bin` (`pi-enclave`); every one is mirrored as `/enclave …` in-session |
| `registerCommand(name, { handler(args: string, ctx) })` — `args` is the raw remainder string | `types.ts:1175-1181, 1259` | `/enclave` stays one command with a sub-verb parser, as in Phase 1 |
| `ctx.abort()` aborts the current agent run; `pi.sendMessage(…, { deliverAs: "steer" })` is fire-and-forget and requires a streaming turn | `types.ts:336, 1301-1315`; `agent-session.ts:1437-1471` | Breaker trip = block + terminate + abort, then a `nextTurn` custom message naming the outcome (steer is meaningless once the run is aborted) |

### What the facts change, relative to the README

These are corrections to carry into the README in step 8, listed here so nobody implements
the wrong thing from the older text:

1. **Tool shadowing is a "before", not "after", problem.** pi's registry is first-extension-wins
   across extensions. The check is *ownership*: at `session_start`, every one of the seven
   tools must report pi-enclave's own `sourceInfo.path`; otherwise refuse. An extension that
   registers `bash` after us is ignored by pi and needs no handling. A foreign `tool_call`
   handler loaded after us cannot mutate a frozen input, and one loaded before us is within
   the trusted-extension boundary the threat model already accepts.
2. **Parallel batch termination needs an execute-time check.** Because all of a batch's
   `tool_call` events complete before any execution, a call prepared before the trip cannot
   be un-prepared by blocking. pi-enclave's own tools therefore consult the breaker **again
   at execute time** (inside the operations objects it owns) and refuse if it opened since
   the call was locked; `ctx.abort()` covers the rest. Tools pi-enclave does not own are
   the residual — and they are denied in auto mode anyway.
3. **Batches are turns.** `turn_end` carries the batch's `toolResults`, so outcome collapsing
   keys on `turnIndex` rather than on guardian's session-branch walk.
4. **`pi enclave …` is `pi-enclave …`.** A `bin`, plus `/enclave …` in-session. The README
   command table is rewritten with both spellings.
5. **"MCP" is "other extensions' tools".** The allowlist semantics are unchanged; the
   vocabulary is corrected until pi has MCP.
6. **The "untrusted repo-local extension" row becomes "project-scope extension present".**
   pi will not load an untrusted one; what pi-enclave refuses is a *trusted* project that
   has `.pi/extensions` entries, because the agent can write them. Detected from the
   directory and from `sourceInfo.scope === "project"` on any tool or command.
7. **Guardian has no canonical snapshot, hash, or execute-once.** Its lock is the freeze
   alone. The canonical action, the hash and the per-session execute-once table are new
   design in this phase, and the README's "port as-is" for `tool-input-lock.ts` applies to
   the freeze only.

## Exit criteria

Phase 2 is done when, on both backends, in CI:

1. The Phase-2 rows of the platform matrix pass as automated tests (the **P** scenarios in
   step 8), each with a control that fails when the mechanism it tests is disabled.
2. `merge(a, b) ⊑ a` holds under a property test for every field in the monotonic table,
   and every project-file violation rejects the whole file with a diagnostic naming the
   field.
3. Every `tool_call` passes through exactly one gate that canonicalizes, evaluates L1,
   locks, and records — and a tool not in `tools.allow` is denied.
4. With `reviewer.model: "none"`, every L1 `ask` and every capability request reaches L4:
   a `confirm` with timeout when attended, a pending record plus `terminate` when not.
5. A pending record survives a crash, is refused when tampered with, and resumes only under
   an equal-or-narrower profile.
6. The audit log chains, `pi-enclave audit verify` detects truncation and edits, and
   redaction is asserted for every credential shape in the README table.
7. `/enclave status` and the footer say which of L1/L4 are active, the attendance mode
   actually in force, and the breaker state.

## Work breakdown

Steps are ordered so that the piece everything else depends on — the canonical action and
the gate — exists before any policy is written against it, and so that every step leaves
`main` shippable: Phase 1 behaviour is the floor at all times.

### Step 1 — Configuration: schema, sources, `$defaults`, the monotonic fold

Produces `src/config/schema.ts`, `src/config/sources.ts`, `src/config/merge.ts`,
`src/config/defaults.ts`, and replaces `createDevProfile` with the loader.

- **Schema.** The full user-global shape from the README (profiles, `sandbox`, `rules`,
  `review`, `tools`, `reviewer`, `breaker`, `attended`, `audit.retention`,
  `sandbox.env.passthrough`), parsed and validated by hand — no schema library; the
  validation *is* the trust boundary and must be readable. Unknown keys are errors, not
  warnings. `reviewer.model` is required and in this phase must be the literal `"none"`;
  any other value reports "reviewer support arrives in Phase 3" and refuses to start. With
  `"none"`, any non-empty `review.*` prose list is a config error and `review.trigger` is
  forced to `boundary`, exactly as the README states.
- **Sources and fold order:** `defaults → ~/.pi/agent/enclave.json → PI_ENCLAVE_* →
  .pi/enclave.local.json → .pi/enclave.json`. Project files are read only when
  `ctx.isProjectTrusted()`; otherwise they are reported as ignored, as automode does.
- **`$defaults` splicing** ported from automode's per-section accumulator, with one change:
  a malformed list is a rejection, not "keep defaults" — a fail-conservative default hides
  the typo that caused it.
- **The fold** is a pure function over the per-field partial orders in the README table.
  It never clamps. The first field that fails the order rejects the whole file with the
  field path, the offending value, and the bound it exceeded. The four prose lists and
  `rules.skipReview`, `reviewer`, `backend`, `sandbox.env` reject the file on *presence*
  below user-global. `review.trigger` accepts a move right only. Environment variables are
  three exact names; any other `PI_ENCLAVE_*` is an error, `PI_ENCLAVE_ATTENDED` accepts
  only `off`, and `PI_ENCLAVE_PROFILE` must name a user-global profile that is ⊑ the
  default one.
- **Property test** (fast-check, new dev dependency): for random `a`, `b` in the schema,
  `merge(a, b)` either rejects or yields `r ⊑ a`; and `merge(a, a) = a`. Plus a
  mutation check per field: weaken one comparator and the property must fail.
- **Rendering:** `rules defaults [--readonly]` and `rules config` as pure functions over
  the merged result, each entry tagged `builtin | user_global | env | project_local |
  project_shared`. `rules critique` is Phase 3.

Verified by unit tests against fixture files for each row of the configuration-sources
table, by the property test, and by the Phase-2 matrix rows on config rejection (P4, P5,
P6 in step 8).

### Step 2 — The canonical action

Produces `src/policy/canonical.ts`, `src/policy/shell.ts`, `src/policy/paths.ts`,
`src/policy/match.ts`.

- **`CanonicalAction`**: `{ tool, input, cwd, argv[] | segments[], paths: { reads[],
  writes[] }, capability?, hash }`. The hash is SHA-256 over a stable serialization (sorted
  keys, resolved paths, the capability if any, the profile name). This is the object the
  lock stores, the audit log records, the pending record persists, and Phase 3 sends to
  the reviewer — so its shape is fixed here and exported.
- **Shell tokenizer**, from automode's two-pass lexer: quote-aware segment split on `;`,
  newline, `|`, `&&`, `||`; redirect extraction; env-assignment skip. Extended so that the
  structural markers the README's read-only classifier will need are *recorded*, not
  parsed: `$(`, backticks, `<(`, `eval`, `xargs`, `sh -c`, heredocs and an unbalanced
  quote set `confident: false`. Phase 2 uses that flag in one place — a non-confident
  parse matches every `ask` rule whose tool is `bash` — and Phase 3 uses it for the
  mutating classification. Each simple command becomes `{ name, args, redirects }`.
- **Path resolution** from automode's `resolvePathForPolicy`: realpath of the nearest
  existing ancestor plus the missing tail, so write targets that do not exist yet still
  resolve, and both the typed and the resolved form are matched. File tools contribute
  their path directly; shell commands contribute every argument that looks like a path
  plus every redirect target (the write-target heuristic, which treats an unknown
  command's path-like arguments as writes — "unknown means mutating").
- **Pattern matcher** ported from automode: `tool(argument pattern)` with a single-wildcard
  `*`, case-insensitive, linear-time, 4 KiB pattern / 1 MiB input limits, and the
  asymmetric overflow policy — oversized input *matches* `deny` and `ask`, never
  `skipReview`. For `bash` the pattern is matched against **each simple command** of the
  canonical form, not the raw string, which is the one semantic change from automode and
  the reason `rm -rf *` in a `deny` list also catches `echo ok && rm -rf /`.
- **`protectedPaths`** match globs against every resolved write path, in-tree as relative
  paths and out-of-tree by segment suffix, as automode does.
- **L1 evaluation**: `deny > ask > skipReview`, returning every matched rule with its
  source so the audit record can name both sides of an overlap.

Verified by unit tests built as a table of `(command, expected segments, expected paths,
confident)` — including the README's conformance cases for substitutions, pipelines with
one mutating member, redirections and typo-squatted subcommands — and by golden hashes
that fail if the serialization changes. The matcher's tests are adapted from automode's
suite with attribution.

### Step 3 — The gate and the lock

Produces `src/gate/gate.ts`, `src/gate/lock.ts`, `src/gate/ownership.ts`,
`src/gate/tools.ts`; wires one `pi.on("tool_call")` in `index.ts`.

- **One handler, one path.** Canonicalize → L1 → lock → allowlist → decision. The handler
  is registered in the extension factory before any tool, and its entire body is wrapped
  so that any exception becomes `{ block: true, reason }` with the exception in the audit
  record — pi would already fail the call on a throw, but a deliberate block carries the
  diagnosis to the model.
- **Lock** = guardian's `assertJsonLike` + recursive `Object.freeze` + non-writable
  `event.input`, ported with attribution, **plus** a per-session table `hash →
  { toolCallId, state: locked | executed | consumed }`. pi-enclave's own operations objects
  (`bash`, the file tools, `grep`'s `execute`) receive the `toolCallId` and check the table
  before doing anything: not locked → refuse; already executed → refuse. That is the
  execute-once property; for tools pi-enclave does not own it cannot hold, which is one
  more reason they are allowlisted rather than trusted.
- **Ownership check** at `session_start`: `pi.getAllTools()` must report pi-enclave's own
  `sourceInfo.path` for all seven tools. Any other path — a built-in, another extension —
  refuses auto mode and names the offender. This replaces the README's "registers after"
  row with the direction pi actually has.
- **Project-extension check**: if `isProjectTrusted()` and `<cwd>/.pi/extensions` is
  non-empty, or any tool or command reports `sourceInfo.scope === "project"`, refuse. The
  reason is in the diagnostic: the sandboxed agent can write that directory. Accepted
  residual: a project extension that registers only a `tool_call` handler before us is
  invisible; the README already lists in-process extensions as the outer ring.
- **Tool allowlist**: a `tool_call` for a name not in `tools.allow` is blocked with a
  reason that names the list. In this phase `reviewed: true` entries are treated as
  `ask` (there is no reviewer), `readOnly: true` entries pass L1 like the built-in read
  tools. An entry may pin `source` to a `sourceInfo.path` so a same-named tool from
  elsewhere does not inherit the grant.
- **Refusal semantics.** "Auto mode refuses to start" means: the gate blocks every
  `tool_call` with the startup diagnostic, the operations objects refuse as in Phase 1,
  the refusal goes to **stderr at load** (the Phase-1 finding about `--print`), and the
  footer says `REFUSING ALL TOOLS (<reason>)`. There is no degraded mode.

Verified by unit tests with a fake `ExtensionAPI` that replays recorded `tool_call`
sequences (a small harness, `test/harness/fake-pi.ts`, reused by every later step), a test
that mutates `event.input` from a second handler and asserts the `TypeError` and the
blocked result, and a test that calls `operations.exec` for a hash the table has not seen.

### Step 4 — Provenance and the circuit breaker

Produces `src/gate/provenance.ts`, `src/gate/breaker.ts`.

- **Provenance** is guardian's tracker ported as-is: `input` → pending queue,
  `before_agent_start` → confirm against expanded text, `message_start` → record
  `{ source, timestamp, sha256, rawText? }` via `appendEntry`, with the quarantine rule
  for queued steer/follow-up messages. Nothing reads it for authorization until Phase 3;
  in this phase it has one consumer — the breaker resets on a *direct* message, not on
  any message — and a conformance test that an `extension`-sourced message never yields a
  record.
- **Breaker**: guardian's counters (3 consecutive, 10 of the last 50 batches), with a
  batch being a turn. Adverse outcomes: L1 deny, allowlist deny, `ask` resolved to deny
  (timeout, cancel, unattended), lock failure, and a sandbox violation on a retried hash.
  Outcomes accumulate per `turnIndex` and collapse to one boolean in `turn_end`.
- **Trip** = `{ block: true, terminate: true }` for this and every further call in the
  batch, `ctx.abort()`, and a `nextTurn` custom message telling the agent the *outcome* is
  off limits. The steering text is also attached through `tool_result` to the blocked
  results so the model sees it in context, not only next turn.
- **Execute-time re-check**: the operations objects consult the breaker before running
  (fact 2 above); a call locked before the trip and executed after it is refused, audited
  as `blocked_after_trip`.
- **Persistence**: each turn's collapsed outcome and each lock-table transition is an
  `appendEntry`; `session_start` with `reason: "resume" | "fork"` rebuilds both from
  `getEntries()`. A bypass never persists because none exists.

Verified by unit tests on the counters, by the fake-pi harness replaying a three-call
batch where the second call trips (P2: all three blocked or refused, `terminate` on every
block, abort called once, one batch outcome in the audit), and by a resume test that
reconstructs the breaker from entries and asserts the next call is blocked.

### Step 5 — State directory, audit log, retention

Produces `src/state/dir.ts`, `src/state/audit.ts`, `src/state/redact.ts`; the
`pi-enclave audit [verify]` command and `/enclave audit`.

- **State directory** `~/.pi/agent/enclave/` (or under `PI_CODING_AGENT_DIR`, matching
  where pi keeps `auth.json`): created `0700`, verified on every open — mode, owner, not a
  symlink — and refused otherwise. It is added to the default `readDeny` list and the fold
  rejects any profile that makes it writable.
- **Audit log** `audit/<session-id>.jsonl`, `0600`, `O_APPEND`; records carry `seq`,
  `prevHash`, `ts`, `kind`, `sessionId`, `turnIndex`, and a kind-specific body: decision
  records (canonical hash, L1 matches with sources, verdict, attendance), violations,
  lock transitions, breaker outcomes, attendance changes, pending-record lifecycle, config
  load (with the effective config hash), refusals. Writes go through one serialized queue
  so `seq` and `prevHash` cannot interleave.
- **Redaction** runs on every record before serialization: argument values under a
  `readDeny` path, the credential shapes in the README table, and `write`/`edit` bodies
  become `<redacted:sha256:…>`. Only the `pending` record kind carries the full canonical
  action, and it is written to the pending file, not the log.
- **`verify`** re-chains a file and reports the first broken `seq`/`prevHash`, and whether
  the last line is complete. **Retention** deletes session files older than 30 days or
  beyond 200 MB at session start; no in-session rotation.
- Phase 1's violation counter and `/enclave violations` now read from the log rather than
  from the in-memory array, so the two cannot disagree.

Verified by unit tests with a fake clock and a temp home: chain verification on a
truncated file, on an edited middle line, and on a file with a torn final line; redaction
assertions per credential shape, including a key split across a `write` body and a
`bash` argument; refusal on a `0644` directory and on a symlinked one.

### Step 6 — Attendance contract

Produces `src/escalate/attendance.ts`, `src/escalate/handshake.ts`,
`src/escalate/confirm.ts`; `pi-enclave attend-secret`.

- **Mode resolution** at `session_start`: `tui` requires `ctx.mode === "tui"` and
  `process.stdin.isTTY`; `rpc` requires `ctx.mode === "rpc"` and a passed handshake; `off`
  is always satisfiable. A declared mode whose preconditions fail at start **refuses auto
  mode** (tui) or **degrades to off for the session** (rpc, as the README specifies) and
  the footer shows the mode in force, never the one configured.
- **Handshake** exactly as specified: 256-bit secret at `<state>/attend.secret` (`0600`),
  `ctx.ui.input("pi-enclave attendance <nonce>", "<nonce>", { timeout: 10_000 })`,
  expected `base64(HMAC-SHA256(secret, nonce || sessionId))`, `timingSafeEqual`, one
  attempt. `attend-secret` writes the file and prints nothing but the path; the secret is
  read from the file by the operator, never printed.
- **Confirm**: `ctx.ui.confirm(title, rendered canonical action, { timeout:
  confirmTimeoutMs, signal })` where the signal is pi-enclave's own so the audit record can
  say `timeout` vs `declined`; both are denies. The rendered action is the canonical form
  — argv, cwd, resolved write paths, capability — never the raw string, so a command with
  an embedded newline cannot hide a second command below the fold.
- **Re-check on every escalation**: TTY still present, RPC still connected (a rejected
  `confirm` promise counts as disconnected). Loss degrades to `off` semantics for the rest
  of the session and is audited; nothing ever degrades toward attended.
- `json` and `print` modes resolve to `off` whatever is configured, and say so.

Verified by unit tests with a fake UI context for each cell of the outcome matrix's
Phase-2 columns, a handshake test with a correct MAC, a wrong MAC, a replayed nonce, a
missing file and a timeout (P9), and a test that `tui` with no TTY refuses.

### Step 7 — Pending-approval records and resume

Produces `src/escalate/pending.ts`, `src/escalate/resume.ts`; `pi-enclave approve <nonce>`
and `/enclave approve <nonce>`.

- **Write path**: `<state>/state/<session-id>/pending/<nonce>.json`, directory `0700`,
  written to `.tmp`, `fsync`, `rename`; body = full canonical action, the profile snapshot,
  the effective config hash, `sessionId`, session file path, nonce, `createdAt`,
  `expiresAt` (24 h), `requiresHuman` for host-exec requests (which in this phase, with
  `hostExec: "never"` the only value, are denied outright and recorded for the audit
  trail). Refused on read if mode, owner, or a symlink is wrong, if the nonce in the body
  differs from the filename, or if expired (and then deleted).
- **Approve** renders the canonical action and asks in *that* terminal (a `readline`
  prompt in the `bin`, `ctx.ui.confirm` in-session). On yes: rename to `approved/`, then
  the checks: re-canonicalize and compare the hash; re-run L1 under the *current* config
  (a rule added since denies); recompile the *current* profile and require `current ⊑
  snapshot` under the fold's order; refuse on any wider field or on a config-hash change
  in a field the order does not cover. Then execute once under the current profile through
  the same operations objects (the lock table gets the hash with state `approved`), rename
  to `consumed/`, audit every transition. A second `approve` of the same nonce is a no-op
  with an audit entry.
- **Out-of-session execution** needs a backend: the `bin` compiles the current profile with
  `SrtBackend` exactly as `session_start` does and disposes it afterwards. The result is
  printed and appended to the originating session as a custom entry so the next resume
  can show it; it is not injected as a tool result, because the turn that asked for it is
  over.
- **Crash safety** (P3): a `.tmp` left behind is ignored; a record in `approved/` with no
  `consumed/` counterpart on the next `approve` is reported, not re-run.

Verified by unit tests for each row of the pending-record table, the stale-resume matrix
(P11: narrower config executes without the removed grant; wider or uncovered change
refuses and leaves the record pending), tamper cases (P10: edited body, `0644`, reused
nonce), and an end-to-end test through the `bin` against the real backend on both
platforms.

### Step 8 — Policy conformance suite, commands, status, README sign-off

Produces `test/policy/scenarios.ts` + runner, the `bin/pi-enclave.ts` entry, the `/enclave`
verbs, and the README update.

- **P rows**, one per Phase-2 matrix row, each asserting the security property through
  the fake-pi harness and, where a row needs the kernel (P11's execution), the real backend:

  | Row | Matrix row | Control that must fail |
  |---|---|---|
  | P1 | Load order / tool shadowing | ownership check disabled |
  | P2 | Parallel batch termination | execute-time re-check disabled |
  | P3 | Crash / recovery | atomic rename replaced by direct write; chain verify skipped |
  | P4 | Project-local widening rejected | fold comparator for the field weakened |
  | P5 | Prose lists below user-global rejected | presence check removed |
  | P6 | `review.trigger` raise accepted / lower rejected | order reversed |
  | P7 | `deny` ∧ `skipReview` → denied, both named | precedence swapped |
  | P8 | `ask` ∧ `skipReview` → L4 | precedence swapped |
  | P9 | `rpc` without handshake, TTY lost | degrade-to-off removed |
  | P10 | Tampered pending record | mode/owner/nonce checks removed |
  | P11 | Stale resume | ⊑ check removed |

  The falsifiability meta-test from Phase 1 is reused: every P row names its control and
  the suite asserts each control actually fails, so a row cannot pass vacuously.
- **Commands**: `/enclave status | backend | violations | rules defaults|config | audit
  [verify] | approve <nonce> | pending` and the `bin` with `rules`, `audit`, `approve`,
  `pending`, `attend-secret`. `on`/`off` are not implemented (see decisions below).
- **Status line** grows `L1 · L4:<mode in force> · breaker n/3` and the refusal states;
  `status` lists the effective profile name, config sources used and rejected, attendance
  mode configured vs in force, tools allowlisted and denied, and the coverage note.
- **README**: move Phase 2 to "implemented", apply the seven corrections above, replace
  the Phase-2 matrix rows' `—` with P ids, and add a "Phase 2 status" section in the
  style of the Phase 1 one: built, cost (gate latency per call, measured), known gaps.

Verified by the P suite green on both platforms in CI with the meta-test, and by a manual
run against real pi in all four modes (`tui`, `rpc` with a scripted client that does the
handshake, `print`, `json`) recorded in this document as step 8's verification, as Phase 1
did for its real-pi runs.

## Package layout after Phase 2

```
pi-enclave/
  bin/pi-enclave.ts           # rules | audit | approve | pending | attend-secret
  src/
    index.ts                  # probe, config load, gate, tools, commands
    config/
      schema.ts               # hand-written validation; unknown key = error
      sources.ts              # five sources, trust-gated project files
      defaults.ts             # $defaults for every list, default readDeny moved here
      merge.ts                # the fold; pure; property-tested
      render.ts               # rules defaults | config
    policy/
      canonical.ts            # CanonicalAction + hash (shape shared with Phase 3)
      shell.ts                # tokenizer with confidence flag
      paths.ts                # resolve-through-nearest-ancestor, glob matching
      match.ts                # wildcard matcher, L1 evaluation, precedence
    gate/
      gate.ts                 # the one tool_call handler
      lock.ts                 # freeze + hash table + execute-once
      ownership.ts            # tool ownership, project-extension check
      tools.ts                # allowlist
      provenance.ts           # ported from guardian
      breaker.ts              # turn-keyed batches, execute-time re-check
    escalate/
      attendance.ts  handshake.ts  confirm.ts  pending.ts  resume.ts
    state/
      dir.ts  audit.ts  redact.ts  retention.ts
    backend/ env/ fs/ tools/ probe*.ts   # unchanged from Phase 1
    commands/enclave.ts       # extended
  test/
    harness/fake-pi.ts        # records/replays ExtensionAPI events and UI dialogs
    policy/                   # P1–P11 + falsifiability meta-test
    unit/                     # per module
    conformance/              # Phase 1, unchanged
  docs/phase-2-plan.md
```

## Risks and how the plan contains them

| Risk | Containment |
|---|---|
| A call prepared before a breaker trip executes after it | Execute-time re-check in every operations object pi-enclave owns (step 4); P2 asserts it and its control proves the check is what holds the row |
| Heuristic shell tokenizer misses a construct and an `ask` rule does not fire | Non-confident parses match every `bash` `ask` rule; the sandbox remains the real control; the tokenizer records the markers Phase 3's classifier needs so the same module grows rather than forks |
| The fold has a comparator bug that lets a project file widen something | Property test over the whole schema plus a per-field mutation check; whole-file rejection means a bug is loud rather than partial |
| A foreign `tool_call` handler loaded before pi-enclave rewrites input | Inside the accepted trusted-extension boundary; documented. Handlers after us are neutralised by the freeze and tested |
| Pending records or the audit log become reachable from inside the sandbox | State directory is in `$defaults` `readDeny`, never a writable root, and the fold rejects any profile that makes it one; a conformance row under the real backend asserts a sandboxed `cat` of a pending record is denied |
| `appendEntry` state is buffered until the first assistant message, so an early crash loses lock/breaker entries | Those entries only matter once a tool has run, which is after the first assistant message; pending records and audit never use session entries |
| Out-of-session `approve` executes with a backend compiled outside a pi session | Same `SrtBackend.compile` path, same profile loader; the end-to-end test runs it on both platforms |
| The `bin` and `/enclave` drift apart | Both call the same pure command functions with different I/O adapters; one test table drives both |
| Gate latency makes every tool call slower | Measure per-call gate cost in step 8 (canonicalize + L1 + lock + audit write); the audit write is the only I/O and is queued, not awaited before the decision |
| `review.trigger`, `readOnly` classification and the reviewer are absent, so `ask` is the only escalation and sessions may be interrupted often | This is the stated Phase-2 outcome: deterministic mode. The default `rules.ask` list stays small (`git push *`, `gh pr create *`, protected paths) so unattended runs are not denied on routine work |

## Explicitly out of Phase 2

The reviewer and everything that only exists for it: `review.*` prose rendering,
`review.trigger` values other than `boundary`, the read-only classification table,
`rules critique`, `backend.extend` and the capability retry hatch's reviewed path (a
capability request in this phase is an `ask`), the eval corpus. The egress proxy, Docker
backend, ops profile and `hostExec: "human"`. The core changes to pi (the plan works on
upstream 0.84.2 without them).

## Decisions settled before step 1

All three were confirmed by the project owner; they are requirements, not options.

1. **`PI_ENCLAVE_AUTO=off` never removes the sandbox.** The README's wording — "refuses to
   enter auto mode at all (CI smoke runs without a sandbox)" — would remove L2, the one
   layer the monotonic rule says nothing may remove. `off` therefore disables **L1 and L4
   only**: the gate passes everything, the breaker and escalation are dormant, and the
   Phase-1 sandbox stays in force. The status line shows `L1 off`. A CI host that genuinely
   cannot sandbox already fails `probe()` loudly, which is the honest failure. There is no
   runtime `/enclave on|off` toggle: a switch that changes the trust model mid-session is
   exactly what the lock and the audit log exist to prevent. The README's command list is
   corrected to match.
2. **`tools.allow` entries may pin `source`** to a `sourceInfo.path`, so a same-named tool
   registered by a different extension does not inherit the grant. An addition to the
   README schema.
3. **Capability requests are an `ask` in deterministic mode**, not a deny: attended gets a
   confirm, unattended gets a pending record. `backend.extend` is pulled forward from
   Phase 3 for the **`write` capability only** — step 0 already confirmed SRT's
   per-invocation `customConfig` does this — and `read` and `host` stay Phase 3/4.
