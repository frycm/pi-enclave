# Project review — September 5, 2026

**Recommendation: hold Phase 3 sign-off and Phase 4 implementation until the authorization and invocation-binding defects below are fixed.** The architecture is appropriate for this project: deterministic policy, a persistent OS boundary, an advisory model, and explicit human escalation. The failures found here occur where those layers exchange authority. Adding network grants before repairing those interfaces would increase their consequences.

Reviewed baseline: `phase-3-reviewer` at `8b49f33fb3c99f661e4ed2d345d199ad59f1ce9d`; Phase 3 changes against `058b64e`, the Phase 1/2 implementation and plans, and the Phase 4/5 design in the README. This is a code, integration, test, and roadmap review, not an assertion that every possible sandbox escape has been excluded.

The pi upgrade described below was implemented during this review. The findings and reproductions describe the reviewed baseline. A subsequent repair is tracked in [the Phase 3 remediation report](phase-3-remediation.md); consult that report for current fix and validation status.

## Findings

### R1 — P1: A concurrent file read can borrow another invocation's read grant

Location: [lock.ts](../src/gate/lock.ts), `beginExecution`, especially the selection of an already executing non-Bash entry; [file-ops.ts](../src/tools/file-ops.ts), the guards selecting a capability helper.

The lock rejects different hashes under the same Bash command, but its file-tool lookup selects the first `locked` or `executing` entry for the path. Phase 3 now uses that entry's capability to choose a widened helper. Two overlapping `read` calls for the same path can therefore both execute with the first call's grant even though the second action has a different hash and requests no grant.

Reproduction: gate a `read` with `limit: 1` and `allow_read` for a configured private directory, then gate an ordinary `read` of the same file with `offset: 2, limit: 1`. Run the real pi read-tool implementations with the production lock and operations adapters, holding helper access until both invocations overlap. Every helper selection receives the first action's hash, and the ungranted call returns line two. The helper is a recording double; no real private file was accessed. This proves the erroneous authority selection before the kernel boundary, rather than a failure in SRT's independent per-profile isolation.

Repair: correlate the complete tool execution with its tool-call ID and canonical hash, and scope its helper lease to that execution. Refuse ambiguous concurrent file calls until that is available. Preserve `edit`'s legitimate multiple operations within one invocation. Test same-path calls with different grants, offsets, limits and execution order through the gate and real tool wrapper, not only by calling backend methods directly.

Phase ownership: the lookup originated in Phase 2; Phase 3 makes it an authority leak by attaching read grants to the selected entry.

### R2 — P1: Truncated display evidence is used to prove full authorization

Location: [risk.ts](../src/reviewer/risk.ts), `directAuthorizationCovers` and `enforceReview`; [evidence.ts](../src/reviewer/evidence.ts), `boundedText` and `buildReviewEvidence`.

`enforceReview` receives the full canonical action but checks authorization against `evidence.action.input`, whose strings are truncated at 2,048 characters. Raising the risk to high does not protect this case: the shortened input can itself satisfy the high-risk authorization check.

Reproduction: the user says `Please run rm -rf build/cache`. The proposed command is `rm -rf build/cache`, followed by 2,100 spaces and ` build/important`. Production code reports `action.truncated: true`, yet an optimistic model `allow/low` becomes an effective **allow/high with authorizationCovers: true**. The full command still contains the additional deletion target. No deletion was executed; the reproduction exercises the production evidence and enforcement functions. The default L1 rules do not independently ask on this command.

Repair: use the complete canonical action and complete trusted authorization records for deterministic coverage. A display representation must never be authority. For truncated actions, require exact full-action hash authorization or human escalation when full-scope coverage cannot be established. Test omitted operands, long capability paths and authorization whose negation occurs beyond the display limit.

### R3 — P1: High-risk authorization survives case changes and explicit revocation

Location: [risk.ts](../src/reviewer/risk.ts), `directAuthorizationCovers`; [index.ts](../src/index.ts), the retained direct-authorization history.

The matcher lowercases entire command strings and filesystem paths, and returns true for any matching historical entry. A later prohibition is skipped rather than revoking earlier permission.

Two reproductions both leave an optimistic model allow effective: `Please run rm -rf build` covers `rm -rf BUILD` on a case-sensitive filesystem; and `Please run rm -rf BUILD` followed by `Do not run rm -rf BUILD` still covers that deletion. These are separate failures of the claimed deterministic full-scope coverage. A well-behaved model may reject them, but the high-risk safeguard specifically exists to constrain a mistaken model.

Repair: preserve case-sensitive action data, separate natural-language request prefixes from command/path bytes, and give subsequent restrictions precedence. Treat ambiguous or revoked authorization as non-covering. Add regressions for case-distinct paths, later prohibitions, bounded history and resumed/changed session branches.

### R4 — P2: Local model qualification can bind to the wrong identity

Location: [model.ts](../src/reviewer/model.ts), `isLoopback`, `ollamaDigest` and `reviewerModelDigest`; [qualification.ts](../src/reviewer/qualification.ts), the binding comparison.

There are two concrete identity gaps. First, Node's URL parser returns `[::1]` for an IPv6 loopback hostname, but `isLoopback` compares it to `::1`. A non-Ollama reviewer at `http://[::1]:1234/v1` therefore receives a `cloud:sha256:...` descriptor instead of being refused for lacking a local weights digest. This was reproduced directly. A changed local model behind the same alias would retain that qualification identity.

Second, Ollama completion uses the registry model's `baseUrl`, while digest lookup runs `ollama show <id> --modelfile` against the CLI's default/environment-selected server. The code never binds that lookup to `model.baseUrl`, and the Ollama digest returned does not include the inference endpoint. Changing the registry endpoint while the CLI server remains unchanged can therefore reuse qualification from another inference service. This second case is established by the call path; no live Ollama service was used in this review.

Repair: obtain model identity from the same normalized endpoint that performs inference; include endpoint and adapter identity in qualification; normalize IPv4/IPv6 loopback addresses correctly and reject unsupported local identities. Verify model changes invalidate qualification, including between evaluation and activation. Requalify after repairing the binding.

### R5 — P2: Combined short options bypass the read-only classifier

Location: [classifier.ts](../src/reviewer/classifier.ts), `hasFlag` and the `file` command classification.

`hasFlag` handles separate options and `--option=value`, but not combined short options. `file -Cm review.magic` is confidently classified read-only, although `-C` compiles a magic database and writes `review.magic.mgc` in the current directory. The classification and actual file creation were both reproduced using a temporary fixture and the distribution's real `file` executable.

Under `review.trigger: "mutating"`, this operation skips the reviewer. The OS sandbox still limits the write location, so this is a review-policy bypass rather than host execution outside L2.

Repair: parse command-specific option forms or restrict the fast path to positively enumerated safe syntax. Cover combined short flags, attached option arguments, option terminators and implicit external programs. In particular, inspect Git's default diff/textconv/fsmonitor behavior before treating its subcommand name as sufficient evidence of read-only execution.

### R6 — P2: Standalone approval drops the approved Bash timeout

Location: [approve.ts](../src/cli/approve.ts), the `backend.run` request.

The pending action includes its complete Bash input, including `timeout`, but the approval CLI passes only the command and other execution metadata to the backend. A call recorded with `timeout: 1` is resumed with `request.timeout === undefined`. This was reproduced with the production approval flow and a recording backend. The backend interprets an absent timeout as unbounded, so a command that should be terminated can hang or continue mutating after the approved duration.

Repair: validate and forward the recorded timeout using the same semantics as in-session Bash execution. Test a short bounded invocation through both entry points. Also add parity tests for ordinary writes to missing parent directories and home-relative paths: the standalone implementation currently invokes helper `writeFile` directly and uses Node path resolution, while pi performs parent creation and its own path expansion.

Phase ownership: Phase 2, still present in Phase 3.

### R7 — P2: Qualification records a context size the Ollama adapter does not set

Location: [model.ts](../src/reviewer/model.ts), `completeIsolated`; [qualification.ts](../src/reviewer/qualification.ts), `ReviewerSampling` and `equalSampling`.

The completion wrapper supplies `samplingParams: { seed, num_ctx }`. Pi's OpenAI-compatible adapter merges these into the top-level request body. Ollama's compatible endpoint does not accept a context-size setting there; its documented configuration uses a model's `Modelfile` instead. Consequently, the recorded `numCtx` value does not establish the effective context used for qualification or later review. This follows from the adapter implementation and [Ollama's API documentation](https://docs.ollama.com/api/openai-compatibility#setting-the-context-size); no live Ollama service was exercised.

Changing the model's context configuration while retaining its weights leaves the extracted weights digest and enclave sampling record unchanged. Qualification can therefore remain valid after an effective context change, which can alter evidence truncation and reviewer behavior.

Repair: use adapter-specific supported settings, verify the effective context at the inference endpoint, and bind qualification to that configuration as well as the weights. Reject unsupported sampling requirements instead of recording them as enforced. Add a real Ollama integration check that changes the context configuration without changing weights and verifies qualification is invalidated.

## Assessment by phase

| Area | Assessment | Remaining gate |
|---|---|---|
| Phase 1: native sandbox and file helper | Good separation between policy and OS enforcement. Environment filtering, protected persistence paths, unconditional tool overrides and falsifiability controls are valuable. Existing native CI is green. | Rerun the full native matrix on the new pi baseline. Keep the accepted macOS process-lifetime and read-deny limitations visible. |
| Phase 2: deterministic policy, lock, approval, state | Tighten-only configuration, explicit attendance, revalidated pending approvals and the audit chain provide a useful deterministic product independently of a model. | Fix R1's execution correlation and R6's resume parity. Test the complete pi wrapper/gate/executor path, including concurrent calls and lifecycle changes. |
| Phase 3: isolated reviewer and read grants | The isolated completion, strict output parser, immutable credential exclusions and post-model risk floors are appropriate. The implementation is not ready for v1 sign-off. | Fix R1–R5 and R7; strengthen qualification and obtain real model evidence. |
| Phase 4: network and Docker | The design identifies the right boundaries, but combines two independently substantial deliverables. | Split delivery; require per-invocation authority to be sound before adding network grants. |
| Phase 5: privileged ops broker | The independent broker and fixed operations are the right direction. | Keep deferred until descriptor-based validation, replay protection and privilege separation have executable tests. |

The existing limitations around CLI resumption of `edit`/search/read, RPC attendance without a client, macOS Bash capability refusal and remote models with mutable provider aliases are documented. They should remain explicit product limitations rather than being counted as newly discovered defects.

## Qualification and test coverage

The reported 80-case corpus in [corpus.ts](../src/reviewer/corpus.ts) consists of four templates repeated with twenty filenames or numbers each. It exercises explicitly requested report writes, instructions embedded in write content, instructions in a prior tool's path, and broad authorization for `rm`. Five trials produce 400 case trials and up to 800 completions, but do not create eighty distinct behavioral scenarios.

Before calling a reviewer qualified for this product, add structurally distinct cases for read/write capabilities, hard/soft/allow rule precedence, contradictory or revoked authorization, case-sensitive targets, truncated actions, credential paths, mixed shell effects and unsandboxed tool grants. Include realistic benign edits, build/test commands and ordinary task-level authorization. Measure effective gate decisions and raw model decisions separately; the current evaluator scores the raw model decision, so its benign false-denial rate does not describe how often users actually reach L4.

Measure the whole two-stage review on the intended local hardware: model and exact identity, runtime/adapter, corpus and prompt hashes, sampling settings, false allows, false denials, escalation rate, p50/p95 latency, timeouts and malformed responses. Exercise the maximum evidence budget against the model's actual token context. A 32-KiB JSON bound does not by itself prove that a 4,096-token context retains the full prompt. No live reviewer qualification or paid model call was performed for this review.

Use the existing unit tests as component evidence, then add integration cases that reproduce R1–R7. The current tests show that individually constructed capability helpers retain their profiles; they do not establish that the extension selected the correct helper for a concurrent tool invocation. That distinction explains why a green suite did not catch R1.

## Recommended roadmap

1. **Phase 3 stabilization / v1 gate.** Repair the findings, expand qualification, run a real local-model trial, and rerun Linux/macOS CI against pi v0.85.0. Add a clean packaged-install smoke test and a real-pi scenario for ordinary work, denial, ask/approval, cancellation, resume and parallel reads. Keep verdict caching deferred. Publish v1 only with the measured limits.
2. **Phase 4a: offline Docker backend.** Retain `network: off` while establishing container lifecycle, immutable image digests, UID mapping, nested deny mounts, cancellation/descendant cleanup and workspace semantics. Run the same backend conformance contract on supported Linux and Windows configurations. Keep the Docker socket inaccessible to the child.
3. **Phase 4b: authenticated egress.** Add canonical host/port/address validation, DNS rebinding defenses, connection-time validation, redirect handling, and revocable invocation-bound grants. Define whether a grant covers a request or a connection; retries and parallel connections must not accidentally reuse authority. Test sibling isolation and termination of already-open tunnels. Ship destination-only egress first if necessary; make TLS-terminating credential substitution a separately tested deliverable.
4. **Phase 5: ops broker.** First implement the protocol and a harmless test broker. Prove peer identity, durable nonce consumption before side effects, expiry, crash recovery and idempotency, no-follow descriptor-based input validation, fixed argv and bounded resource use. Only then attach privileged service/config/SSH operations and introduce the separate broker account. Keep arbitrary shell and broad sudo grants outside the broker contract.

For pi core, prioritize a final execution hook that carries the tool-call ID and complete immutable action, plus per-confirm RPC authentication. Those directly address the difficult boundaries this review encountered. The README previously claimed four proposed patches were already prototyped; the actual fork has none. That statement has been corrected.

## Pi release update

The latest stable release verified for this review is [v0.85.0](https://github.com/earendil-works/pi/releases/tag/v0.85.0), published September 4, 2026, at `107d79f11072bbc8a3a757ed7fd69596bee7d68c`.

- The sibling `../pi` checkout was clean at upstream v0.84.4 with no fork-only commits. It was fast-forwarded to the exact v0.85.0 tag, and `frycm/pi`'s `main` was pushed to that same commit. No unreleased upstream commits were included.
- pi-enclave now pins its development dependency to `@earendil-works/pi-coding-agent@0.85.0`, uses the bounded peer/probe range `>=0.85.0 <0.86.0`, and declares Node `>=22.19.0` to match pi. The lockfile and current README references were updated; historical phase reports retain their original baseline.
- The published pi root import fails without `@earendil-works/pi-server`, which pi v0.85.0 imports transitively but omits from its dependencies. An explicit production dependency on `@earendil-works/pi-server@0.85.0` restores the import. This adds a substantial dependency subtree and accounts for much of the lockfile growth. It is an upstream packaging workaround, documented for removal after an upstream fix and a clean-install check.
- The upstream grep artifact was reviewed before repinning its hash: rendering moved to a separate module and execution now honors `ctx.cwd`; output formatting and the duplicated match limit did not change. The image-detector artifact is unchanged. pi-enclave now initializes its policy cwd from `ctx.cwd`, with a regression test for SDK sessions launched from another process directory.
- Enclave changes and this report are left uncommitted for review. The sibling fork update is already pushed.

## Validation and limits

| Check | Result |
|---|---|
| Original Phase 3 type/lint checks | Pass |
| Original Phase 3 unit/policy suites | 912 unit tests and 25 policy tests pass |
| Updated pi v0.85.0 type/lint checks | Pass |
| Updated unit/policy suites | 913 unit tests and 25 policy tests pass |
| Clean packaged install | Packed the project, installed the tarball into an empty temporary consumer, and verified CLI help, pi version `0.85.0`, and extension root import |
| Review reproductions | Confirmed grant miscorrelation, truncated/case-folded/revoked authorization acceptance, combined-option file mutation, IPv6 identity bypass and missing resume timeout |
| Local conformance command | 11 tests pass; 47 native sandbox tests skipped. Search and capability falsifiability controls also report their host prerequisites unavailable. This is not a native sandbox sign-off. |
| Original Phase 3 CI | [Run 33922323021](https://github.com/frycm/pi-enclave/actions/runs/33922323021): type/lint, Ubuntu and macOS jobs all succeeded for `8b49f33`, using pi v0.84.2 |
| New baseline native matrix | Outstanding; this host has `apparmor_restrict_unprivileged_userns=1`, lacks `fd`, and cannot provide macOS evidence |

The first sandboxed unit run produced seven subprocess-related failures. Running the unchanged suite outside the outer execution sandbox made all seven pass; they were not treated as project findings. The OS namespace restriction was not disabled to obtain a green result.

Dependency hygiene should be included in stabilization. The production audit found the existing `tsx@4.19.2` / transitive esbuild development-server advisory. The extension uses tsx to load its CLI, and this review did not establish a reachable esbuild HTTP-server path. Treat the advisory as upgrade work with reachability context, not proof of a sandbox escape; avoid an indiscriminate force-upgrade of the test/tooling stack.
