# Phase 3 review remediation

This change repairs R1–R7 from the [September 5 project review](project-review-2026-09-05.md) and updates the supported baseline to pi v0.85.0. The original review remains a record of the vulnerable baseline.

| Finding | Repair | Regression evidence |
|---|---|---|
| R1: grant borrowed by another file invocation | All owned tools bind call ID, complete input, tool and cwd before executing. Async invocation scope selects only that action; completion, cancellation, direct input and session reset invalidate it. Write parent creation is guarded too. | Real pi read wrappers through the production gate overlap in both orders; only the granted call succeeds. Changed inputs, IDs, cwd, replay, reset, cancellation and pre-mkdir breaker checks refuse. Real edit, write and directory-listing controls still work, including immediate-child metadata without borrowing another ls invocation. |
| R2: truncated evidence authorizes a full command | Deterministic enforcement receives full trusted authorization and the canonical action separately from prompt evidence. | Hidden deletion operands and a negation after 2,048 characters now ask. Full exact long-command and full-hash authorization remain valid. |
| R3: case folding and revoked permission | Executable data is compared byte-for-byte with complete request grammar. Only the newest direct instruction can authorize high risk; in-flight review and queued execution reject superseded instructions. Active tree navigation restores the current branch. | Case-distinct targets, revoked or conditional permission, and revocation during completion refuse. A new explicit authorization after revocation remains valid. Capability permission cannot authorize unrelated Bash effects. |
| R4: wrong local model identity | Identity comes from the auth-resolved inference endpoint, preserving proxy prefixes. Ollama binds its complete manifest and runtime, rather than the CLI server's first weights digest. The checked endpoint/auth snapshot is the one used for inference; checks also surround every completion stage. | A local HTTP protocol fixture proves correct routing, authentication, endpoint/config invalidation, mid-call mutation refusal and redirect refusal. Loopback encodings are rejected for unsupported local adapters. Real pi registry optional metadata is covered. |
| R5: combined-option mutation skips review | `file` uses a positive safe-syntax table; short clusters and unknown options cannot hide compilation. Git commands with configurable external programs receive review. | `file -Cm`, attached/abbreviated/unknown options and configured-program Git commands classify as mutating. Ordinary file inspection and other safe readers retain the fast path. |
| R6: approval loses execution timeout | Shared validation enforces pi's finite positive seconds/range contract; both Bash entry points forward the timeout. Standalone writes use the canonical target and create its parent. | Valid fractional and maximum timeouts reach the backend unchanged; invalid timeouts refuse before transition. Relative, home-relative and file-URL writes create the intended parent. |
| R7: context setting is not enforced | Ollama uses native `options.num_ctx`, then checks loaded context and manifest via `/api/ps`. Remote context is explicitly provider-managed; unsupported sampling adapters refuse. Qualification schema v2 invalidates old records. | Protocol tests reject unchanged-weight models with the wrong loaded context; requests contain the native options and isolated messages, with no tools or session history. |

## Validation

- Syntax/types/imports: `npm run check` passes.
- Full local suites: 967 unit tests and 25 policy tests pass on the final candidate.
- Focused regression suites exercise the original triggers and legitimate controls listed above. The original exploits no longer produce an allow or borrowed grant in those paths.
- Local conformance: 11 passed, 47 native cases skipped because `fd` is missing and AppArmor denies capability-bearing user namespaces. The host policy was not weakened.
- Linux/macOS CI passed on candidate `5cb03468b6e258b636c061229a38338616cbc97e`: [run 33952802405](https://github.com/frycm/pi-enclave/actions/runs/33952802405), including typecheck/lint and both native test/conformance jobs. PR #7 was then squash-merged as `a1f431b72216e441b1f82c0f053bbc6a6154f04a`.

## Remaining release evidence

No live Ollama model qualification was run on this host: Ollama and a reviewer model are not installed. The native adapter has protocol-level integration evidence, which does not establish a model's security performance or latency. The existing corpus's limited scenario diversity and live hardware qualification remain v1 release work. Merging the implementation does not declare an arbitrary model qualified; runtime still refuses without its matching local qualification record.

The sibling `frycm/pi` fork remains exactly upstream v0.85.0 at `107d79f11072bbc8a3a757ed7fd69596bee7d68c`. The explicit `pi-server@0.85.0` dependency is an upstream packaging workaround. The clean packaged-install smoke test from the baseline update passed.
