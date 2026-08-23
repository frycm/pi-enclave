# Phase 2 implementation plan — Policy, lock, breaker, state

**Outcome (from the README):** deterministic auto mode — usable offline with no reviewer at
all. `rules.deny` / `rules.ask` plus the sandbox, `review.trigger` pinned to `boundary`,
every boundary crossing an `ask`. No model decides anything in this phase.

**Baseline:** unchanged from Phase 1 — `@earendil-works/pi-coding-agent` `>=0.84.2 <0.85.0`,
verified against the pinned `0.84.2` package in `node_modules`. File references below are to
that package (`dist/**.d.ts` for types, `docs/**.md` for documented behaviour), because that
is what CI installs and what the extension actually runs against.

Phase 1 built the boundary. Phase 2 builds the thing that decides what is allowed to reach
it, and — this is the whole difficulty — has to do so from inside an extension API that
offers no ordering guarantees and re-validates nothing.

## Verified integration facts

Each was checked in the pinned package, not assumed. The first three are the ones that shape
the design; the rest remove guesswork from individual steps.

| Fact | Where | Consequence |
|---|---|---|
| `tool_call` returns `{ block, reason, terminate }`, `event.input` is **mutable**, later handlers see earlier mutations, and **no re-validation happens after a mutation** | `dist/core/extensions/types.d.ts:779-790`; `docs/extensions.md:761-766` | An L1 verdict in a `tool_call` handler is **not** an enforcement point. Whatever pi-enclave approves can be rewritten by any handler that runs after it |
| Sibling calls in one assistant message are **preflighted sequentially, then executed concurrently** | `docs/extensions.md:757` | When the breaker opens mid-preflight, later siblings can still be blocked, but earlier ones have already been cleared. The breaker must therefore be consulted a second time, at execution |
| `terminate` "only happens when **every** finalized tool result in the batch sets this to true" | `dist/core/extensions/types.d.ts:786-789` | "Trip the breaker and stop the turn" is only achievable by blocking *and* terminating every remaining call in the batch. One terminating call in three does nothing |
| `pi.getAllTools()` returns `ToolInfo.sourceInfo` with `scope: "user" \| "project" \| "temporary"` and a path | `types.d.ts:1146-1148`; `dist/core/source-info.d.ts:4-10` | The tool allowlist and the shadowing check are both answerable from the registry, rather than by trusting load order |
| Registering a tool with a built-in's name **replaces** it; interactive mode shows a warning | `docs/extensions.md:2053` | An extension loaded after pi-enclave silently takes the sandboxed tool away. The check has to run after loading, at session start |
| `ctx.ui.confirm` returns `false` on timeout **and** on cancel; `input` returns `undefined` | `docs/extensions.md:2524-2528` | "Timeout is a deny" needs no extra machinery — but `false` cannot distinguish "no" from "nobody is there", which is why attendance stays an explicit contract rather than an inference |
| RPC dialog methods carry `timeout`; `input` carries `title` + `placeholder` and answers `{ value }` or `{ cancelled }` | `docs/rpc.md:1164`, `docs/rpc.md:1216-1230` | The attendance handshake fits inside the fixed `extension_ui_request` method set; no custom message type is needed |
| `project_trust` fires **before** project-local extensions load, and only user/global and `-e` extensions participate | `docs/extensions.md:352` | pi-enclave can refuse an untrusted project before an untrusted repo-local extension is loaded into the same process |
| `pi.registerCommand` (slash commands) and `pi.registerFlag` (CLI flags) are the only registration points — **there is no CLI subcommand API** | `types.d.ts:904`, `types.d.ts:911` | `pi enclave approve <nonce>` as the README spells it cannot exist on this baseline. Out-of-session commands ship as pi-enclave's own `bin` |
| **pi has no MCP support at all**: "No MCP. Build CLI tools with READMEs, or build an extension that adds MCP support" | pi `README.md:498` | The recorded gap "MCP tools are unsandboxed" is really "tools *any other extension* registers". The allowlist is still required; the wording is not |
| `pi.appendEntry(customType, data)` persists extension data; `ctx.sessionManager.getEntries()` reads it back on `session_start` | `docs/extensions.md:1444-1462` | Breaker state and approval bookkeeping survive resume through the session file. The audit log is deliberately *not* there — it must outlive and out-scope the session |
| `pi.sendMessage(…, { deliverAs: "steer" })` is delivered after the current turn's tool calls and before the next LLM call | `docs/extensions.md:1389-1410` | The breaker's steer message lands exactly where it is useful: after the batch that tripped it, before the model plans its next move |
| `input` fires on raw pre-expansion text with `source: "interactive" \| "rpc" \| "extension"` | `docs/extensions.md:882-900` | Direct-user provenance is exactly this event, and `source: "extension"` is exactly what must never count as authorization |
| `getAgentDir` and `CONFIG_DIR_NAME` are exported | `dist/index.d.ts:2` | State, audit and config paths follow pi's own layout instead of hardcoding `~/.pi` and `.pi` |

### What these facts change about the design

**The lock is not bookkeeping; it is the enforcement point.** Because `tool_call` mutations
are unordered and unvalidated, a decision made in the handler binds nothing on its own. The
canonical action is hashed in the handler, and the hash is re-derived **inside pi-enclave's
own operations**, where the tool actually executes. A mismatch is a refusal. That turns pi's
documented footgun into a detectable event rather than a silent bypass, and it is the reason
the lock is step 1 rather than an implementation detail of step 5.

**A tool pi-enclave does not own cannot be locked at all.** There is no execution hook for
another extension's tool. So the allowlist is not defence in depth, it is the only defence:
anything not in `tools.allow` is denied at `tool_call`, and an allowlisted tool is either
declared read-only or (from Phase 3) reviewed on every call.

**The breaker needs two checkpoints, not one.** Preflight for the calls that have not been
cleared yet, and execution for the ones that were cleared before the trip.

## Exit criteria

Phase 2 is done when all of the following hold, in CI, on both backends:

1. **Deterministic auto mode runs with no reviewer.** `reviewer.model: "none"` forces
   `review.trigger: "boundary"`; every boundary crossing becomes an `ask`; nothing calls a
   model.
2. **The monotonic merge is a proven property, not a review promise.** `merge(a, b) ⊑ a`
   holds under a property test whose generator is itself falsifiable — it must be shown to
   produce order-violating inputs that the merge rejects.
3. **Every Phase-2 matrix row from the README passes as an automated test**, including the
   four refusal rows (untrusted repo-local extension, shadowed tool, project file touching a
   forbidden key, breaker open) and the parallel-batch row.
4. **The lock holds against a later `tool_call` handler**: a handler registered after
   pi-enclave that mutates `event.input` causes a refusal at execution, with an audit record.
5. **Escalation fails closed in every mode**: `tui` without a TTY, `rpc` without a handshake,
   a timed-out confirm, and a lost precondition mid-session all resolve to deny.
6. **Pending-approval records are single-use, non-replayable and never in the workspace**,
   and a resume under a *wider* profile than the snapshot is refused.
7. **The audit log is tamper-evident and redacted**: `prevHash` chains verify, planted
   credentials never appear in plaintext, and `write`/`edit` bodies are hashed rather than
   stored.
8. **Read-only classification is an allowlist with teeth**: every conformance case in the
   README's list (destructive flags, substitutions, redirections, mixed pipelines, typo-
   squatted subcommands) classifies as mutating.

## Work breakdown

Ordered so the riskiest assumption is tested first. In Phase 1 that assumption was "SRT
delivers the matrix guarantees". Here it is **"these claims are testable at all"** — almost
every Phase-2 row is a statement about how pi behaves around the extension, and none of it
can be verified by unit-testing pi-enclave against itself.

### Step 0 — Can any of this be tested? A pi-session harness

**The risk:** Phase 1's suite could drive the backend directly, because the backend is
pi-enclave's own code. Phase 2's claims are about pi — handler ordering, batch preflight,
`terminate` semantics, tool shadowing, RPC dialogs. A suite that mocks pi would prove that
pi-enclave behaves correctly against pi-enclave's beliefs about pi, which is the failure mode
this project exists to avoid.

**Produces:** a harness that runs a **real `pi` process** with pi-enclave loaded (`-e`), no
network and no real model:

- A **scripted model server** — a loopback HTTP server speaking one of pi's supported provider
  APIs, registered through `pi.registerProvider` from a test-only extension, replaying a
  fixed script of assistant messages and tool calls. Deterministic, offline, no credentials.
- A **driver** over pi's RPC mode (`docs/rpc.md`) that sends input, observes tool execution
  and answers `extension_ui_request` — the same channel the attendance handshake uses, so the
  handshake gets tested through the real protocol rather than a stub.
- **Observation without trust in pi-enclave's own reporting**: what did and did not execute is
  read from side effects on disk (a marker file a blocked command would have written), not
  from pi-enclave's audit log. A suite that asked the accused for its own alibi would be worth
  nothing.

**Verified by:** a control, in the Phase-1 spirit. With pi-enclave's `tool_call` handler
disabled, the marker file appears; with it enabled, it does not. If the control ever stops
failing, the harness has stopped testing anything.

**If the harness proves impractical** (provider surface too large to fake, RPC too awkward to
drive), that is a finding, and the fallback is stated up front: the pi-facing rows drop to
documented manual procedures with recorded transcripts, and every row that *can* be a unit
test still is. What does not happen is those rows quietly becoming assertions about mocks.

### Step 1 — Canonical action, hash and lock

**Produces:** `canonicalize(toolName, input, cwd) → CanonicalAction` — tool, argv (shell
commands tokenized: pipelines, `&&`, `||`, subshells split into simple commands), resolved
absolute paths, the env subset, the requested capability if any, and the profile generation.
`hash(action)` over a stable serialization. A deep-frozen snapshot stored per `toolCallId`,
and verification at execution inside every pi-enclave operations object.

**Verified by:**

- Unit tests for canonicalization: same action from different spellings hashes the same;
  different capability hashes differently (`allow_write=/a` vs `/b` must never share a hash —
  the README's replay case).
- The harness: a second extension registered **after** pi-enclave mutates `event.input` in a
  `tool_call` handler; execution must refuse with a hash mismatch and audit it.
- A falsifiability control: with verification disabled, that same test must pass the mutated
  command through. The mutation is real, not simulated.

### Step 2 — Config schema and the monotonic fold

**Produces:** the config loader and the merge — `defaults → user global → environment →
project local → project shared`, each step required to satisfy `effective ⊑ incoming` under
the per-field partial order in the README, with **whole-file rejection** and a diagnostic
naming the offending field. `$defaults` splicing. The three `PI_ENCLAVE_*` variables and
nothing else. The four prose lists parsed and **rejected below user-global** even though
nothing reads them until Phase 3 — a project file that contains one is rejected whole.

**Verified by:** a property test for `merge(a, b) ⊑ a` over generated configs, plus targeted
cases for each row of the order table. The generator is itself under test: it must be shown
to produce violations (a wider `writableRoots`, a shrunken `readDeny`, a `skipReview` entry in
a project file, `review.trigger` lowered) and the merge must reject each. A property test that
only ever generates valid inputs proves nothing, which is the same trap as an unfalsifiable
conformance row.

### Step 3 — L1: pattern rules, protected paths, read-only classification

**Produces:** matching of `rules.deny` / `rules.ask` / `rules.skipReview` against the
canonical action with the fixed precedence **`deny` > `ask` > `skipReview`**;
`rules.protectedPaths.{deny,ask}` matched against every resolved write target; and the
read-only predicate table — an allowlist keyed on command, subcommand and forbidden flags,
with the structural rules (any redirection, substitution, `eval`, `xargs`, `sh -c`, heredoc,
env-assignment prefix, unknown command, or a parse the tokenizer is not confident about) each
forcing "mutating".

**Verified by:** table-driven tests covering the README's conformance cases —
`git reset --hard`, `gh api -X DELETE`, `find -delete`, `$(…)` in an argument, a pipeline with
one mutating member, a redirection into a writable root, a typo-squatted subcommand — plus the
two overlap cases (`deny` ∧ `skipReview` → denied; `ask` ∧ `skipReview` → asked). Every
fast-pathed action records which predicate matched, and that record is asserted, not just the
verdict: "allowed for the right reason" is the claim.

### Step 4 — Provenance and the attendance contract

**Produces:** direct-user provenance from `on("input")` (raw, pre-expansion, `source` recorded;
`source: "extension"` never counts) — stored now, consumed by Phase 3's fourth precedence
tier. The attendance contract: `tui` requires `ctx.mode === "tui"` **and** a controlling TTY;
`rpc` requires the HMAC handshake over `ctx.ui.input`; `off` denies every `ask`. Mid-session
precondition loss degrades to `off` immediately and never upgrades.

**Produces also:** `pi-enclave attend-secret`, writing a 256-bit secret `0600` under the
extension's state directory, and a constant-time verifier.

**Verified by:** unit tests for the MAC and the file-mode checks; harness tests for the three
outcomes of the handshake (valid, wrong MAC, no response → `off`) driven over the real RPC
`extension_ui_request` channel; and a test that a client which simply ignores the prompt ends
the session unattended rather than attended.

### Step 5 — L4 escalation, pending records, resume

**Produces:** the attended path (`ctx.ui.confirm` with the canonical action, raced against
`confirmTimeoutMs`, timeout = deny) and the unattended path (deny + terminate + a pending
record). Records exactly as specified: `0700`/`0600` under the extension's state directory,
never a writable root; `tmp` + `fsync` + `rename`; full canonical action plus hash; session
binding; 128-bit nonce; `expiresAt`; single use via `pending/ → approved/ → consumed/`.

**Produces also:** `pi-enclave approve <nonce>` in pi-enclave's own bin — the baseline has no
CLI subcommand API, and the session that needs approval is by definition not the session doing
the approving.

**Verified by:** filesystem-level tests — a record with the wrong mode or owner is refused; a
partial write is never observable; a replayed nonce is a no-op with an audit entry; an expired
record is refused and deleted. Resume tests assert both directions of the profile check: a
*narrower* current profile resumes, a *wider* one is refused with the record left in
`pending/`.

### Step 6 — Circuit breaker, steer, audit log

**Produces:** the breaker (3 consecutive adverse outcomes in a turn, or 10 in the last 50
batches; a parallel batch collapses to one outcome), evaluated at **both** checkpoints from
the integration facts — preflight and execution. On opening: block and `terminate` **every**
remaining call in the batch (the only way pi honours early termination), plus a steer message
naming the denied *outcome* rather than the command. Resets on the next direct user input.

**Produces also:** the audit log — JSONL under the extension's own directory, `O_APPEND`,
`seq` + `prevHash`, redaction before writing (readDeny-matching values, credential-shaped
strings, `write`/`edit` bodies → `<redacted:sha256:…>`), per-session files, retention on
session start, and `pi-enclave audit verify`.

**Verified by:** unit tests for the counters and the batch collapse; a harness test for the
three-call batch where the second call trips the breaker — asserted on marker files, so
"no call from that batch executed after the trip" is measured rather than reported; chain
tests that detect truncation and edits; and a redaction test that plants credentials (the
Phase-1 fixture already does this) and greps the whole log for them.

### Step 7 — Tool allowlist, shadowing and trust refusals

**Produces:** denial of any tool not in `tools.allow`; `readOnly: true` / `reviewed: true`
declarations, with `reviewed` meaning "always escalate" while there is no reviewer; the
shadowing check at session start (`pi.getAllTools()` — if `bash` or any file tool is not
pi-enclave's, auto mode refuses to start); and participation in `project_trust` so an
untrusted project's extensions never load into the same process.

**Verified by:** harness tests with a second extension that (a) registers its own `bash` after
pi-enclave and (b) registers an unlisted custom tool. Both must end in a refusal that names
the offending source path from `sourceInfo`, not a generic error.

### Step 8 — Commands, status, and the README corrections

**Produces:** `/enclave rules defaults|config|critique-stub`, attendance and breaker state in
the status line, and pi-enclave's own bin for the out-of-session commands (`approve`,
`audit verify`, `rules defaults|config`, `attend-secret`).

**Produces also**, because Phase 2 is where they stop being harmless:

- The README says `pi enclave …` for six commands the baseline cannot register. Corrected to
  the bin, with the core change (a CLI subcommand hook) added to the list of proposals.
- The README's "MCP tools are unsandboxed" gap is rewritten as what it actually is: pi has no
  MCP; tools registered by *other extensions* are the uncovered surface, and the allowlist is
  what covers them.

### Step 9 — Matrix sign-off, CI and measurement

**Produces:** the Phase-2 rows as executable tests with their ids in the README matrix
(continuing the `C`/`F` scheme with a `P` series), CI running the harness on both platforms,
and one measurement the README will have to live with: the added per-tool-call latency of
canonicalization, matching and hashing, reported against Phase 1's numbers.

**Verified by:** CI green on macOS and Linux, and the falsifiability control from step 0 still
failing when enforcement is removed.

## What this phase deliberately leaves for later

The reviewer itself, the prose rulebook's *interpretation*, the eval corpus and
`rules critique`'s model call (Phase 3); the egress proxy and Docker backend (Phase 4); the
ops profile and the privileged broker (Phase 5); Windows; and any `hostExec` path — the
profile field is parsed and the pending record can carry `requiresHuman`, but `never` stays
the only value a profile may hold in this phase.

## Package layout additions

```
pi-enclave/
  bin/
    pi-enclave.ts             # approve | audit | rules | attend-secret
  src/
    policy/
      canonical.ts            # canonicalize + hash
      lock.ts                 # frozen snapshots, execution-time verification
      rules.ts                # deny / ask / skipReview, protectedPaths
      readonly.ts             # the predicate table
    config/
      schema.ts               # the whole config shape
      merge.ts                # the monotonic fold and its partial order
      sources.ts              # defaults, user, env, project local, project shared
    attend/
      contract.ts             # modes, preconditions, degradation
      handshake.ts            # HMAC over the RPC input channel
    state/
      pending.ts              # records: write, approve, resume, expire
      breaker.ts
      audit.ts                # JSONL, chain, redaction, verify
  test/
    harness/                  # scripted model server + RPC driver (step 0)
    policy/                   # matrix rows P1..Pn
```

## Risks and how the plan contains them

| Risk | Containment |
|---|---|
| A later `tool_call` handler rewrites what pi-enclave approved | The lock is verified where pi-enclave executes, not where it decides (step 1), and the mismatch is a tested case rather than a hoped-for absence |
| A tool pi-enclave does not own executes unpoliced | Denied unless allowlisted; allowlisted means declared read-only or always-escalate. The gap is named in the status line, as in Phase 1 |
| The breaker opens too late to stop a batch already in flight | Two checkpoints (preflight and execution), and the batch row is asserted on marker files rather than on pi-enclave's own account of what it blocked |
| `terminate` silently does nothing because one sibling did not set it | Every remaining call in a tripped batch is blocked *and* terminating; the harness test fails if any of them executes |
| The property test passes vacuously | The generator must be shown to produce order violations that the merge rejects — the same falsifiability discipline as the conformance suite |
| The shell tokenizer is a heuristic, and heuristics leak | "Unknown means mutating", structural rules that force mutating on any construct the tokenizer cannot reason about, and conformance cases for each. A real parser is a v2 swap that does not change the rule format |
| Pending records are the one place a human decision is persisted | Never in the workspace; mode and owner checked on read; atomic write; nonce; expiry; single use; resume re-checks policy *and* the profile order. Each is a test, not a convention |
| The audit log becomes a second copy of the secrets it is meant to witness | Redaction before writing, hashes instead of values, and a test that plants credentials and greps the log |
| The harness is heavy and turns flaky, so it gets skipped | Kept to the rows that genuinely need a real pi; everything else stays a unit test. A skipped harness row must fail the suite rather than pass quietly |
| Phase 2 lands a config surface that Phase 3 then has to change | The four prose lists are parsed, ordered and rejected below user-global *now*, so Phase 3 adds a consumer rather than a schema |
