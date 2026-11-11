# Pi 1.5 API adoption

Phase 4a adopts four APIs from the pinned pi 1.5.2 release, following the
[baseline dependency upgrade](pi-1.5-upgrade.md).

## Sandboxed streaming reads

Pi's text reader receives `createReadStream` alongside enclave's existing file
operations. Opening and reading the file remain inside the sandboxed helper;
there is no host filesystem fallback. This lets pi stop at its own text output
limit without buffering the entire file or hitting the helper's 32 MiB whole-file
ceiling. Images, edits and pi's unusual-range fallback still use the bounded
whole-file operation.

Helper protocol 3 uses a client-generated stream identifier and pull requests
of at most 64 KiB. A stream pins its helper and file descriptor. Renaming the
pathname cannot switch the descriptor to a different file. Regular files stop
at their initial size; this bounds concurrent appends, not concurrent overwrites.
Zero-sized special files read until EOF. Nonblocking opens avoid trapping the
helper on a repository FIFO. The helper limits open streams to 32 and reclaims
idle descriptors after 30 seconds.

The invocation's exact approved action selects one base helper or one temporary
capability helper for the entire stream. Action-lock checks occur before opening
and between chunks. A reset or breaker trip prevents subsequent data delivery;
no sibling invocation acquires the grant. Cancellation also interrupts helper
startup and lease acquisition, closes a paused stream, and disposes a temporary
helper that arrives after cancellation. EOF, early return, errors and cancellation
close descriptors; cleanup cannot start a replacement helper.

## Reviewer measurements

Each isolated review creates a fresh local pi telemetry context. Authorization
and decision attempts record stage, attempt number, outcome, duration and optional
first-output timing. Audit entries of kind `reviewer` contain those measurements
and the canonical action hash. Prompts, completions, credentials and provider
error messages are excluded from spans and measurements. No telemetry exporter
or network destination is configured.

Qualification reports add optional p95 authorization, decision and first-output
latencies. OpenAI-compatible transports observe the first nonempty text delta.
The existing non-streaming Ollama transport observes its first validated response,
so that timing is not a first-token measurement. Existing qualification thresholds,
sampling, retry budget and the shared timeout for each two-stage attempt remain
the same.

## Advisory tool reachability

Tools that declare `reachesTools(input)` contribute bounded metadata to reviewer
evidence, decision audit entries and human approval reasons. The declaration is
evaluated on a clone of the input. Pi's overmatching words resolve against current
tool and namespace names; raw script words are not copied into the metadata.
At most 32 tool names are recorded. Invalid or throwing declarations are marked
unknown, and excessive declarations or results are marked truncated.

This is untrusted display evidence. It cannot authorize a tool, lower risk or
stand in for checks on an actual child call. Empty declarations do not prove
that a script has no effects. The authorization and decision prompts state those
rules explicitly. Prompt and evidence schema versions advance to 2, changing the
prompt hash and requiring reviewer requalification for the deployed model and
rulebook.

## Permission-blocked approvals

Attended TUI approvals use `ui.custom` with `blocked.kind: "permission"`. The
program-status message is static and contains no action data. The dialog shows
the terminal-safe canonical action, defaults to Deny, uses pi's configured select
keybindings and requires all pages to have been displayed before Approve once
can succeed. Reflow resets that review progress. Small terminals require resizing
before approval is possible.

Timeout, cancellation, component disposal and disconnected clients refuse the
action. An affirmative response arriving after the deadline also refuses it.
Existing attendance checks, pending records and invocation-bound grant semantics
remain in force. Authenticated RPC attendance continues to use `ui.confirm`;
unattended sessions do not open a dialog.

## Validation

Regression coverage includes the installed pi read tool on a 40 MiB file,
descriptor cleanup, cancellation during startup and lease acquisition, paused
consumers, invalid wire chunks, helper retirement, action reset and breaker
revocation, and native isolation of simultaneous base and capability streams.
Backend qualification exercises streaming success and denial inside its existing
file-helper rows, and the helper/corpus identity changes invalidate old backend
qualifications.

Reviewer tests cover retry and timeout measurements, late output and sensitive
exception exclusion. Reachability tests cover bounded metadata and retained child
denials. Dialog tests exercise pagination with queued input, configured keys,
reflow, cancellation, disposal, timeout, RPC fallback and canonical-action display.
Native Linux/macOS and Docker/Podman CI remain required before merge. No live
reviewer qualification or paid provider request is part of this change.

Local validation: typecheck and lint pass; the full native macOS suite passes
1,124 tests with seven platform/engine skips. The native probe is ready, all 11
policy rows and their controls pass, and all 29 native conformance rows pass
(including C12's explicit Linux-only exemption on macOS).
