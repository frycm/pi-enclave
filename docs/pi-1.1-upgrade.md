# Pi 1.1 migration review — October 7, 2026

Target: stable upstream [v1.1.0](https://github.com/earendil-works/pi/releases/tag/v1.1.0),
commit `abe508e1b89912adde45528136c3221eb69acdd7`. The previous baseline was v0.85.0,
`107d79f11072bbc8a3a757ed7fd69596bee7d68c`; upstream reports 545 intervening commits.
This is a focused compatibility and trust-boundary review, not an exhaustive audit of pi.

The subsequent [dependency upgrade](dependency-upgrade.md) records the refreshed
sandbox runtime and toolchain, additional Java environment protection, and updated validation.

## Changes and resulting behavior

| Area | Upstream change / verified behavior | Enclave response |
|---|---|---|
| Tool interception | Session-level agent hooks now own interception. `ctx.executeTool()` runs nested calls through validation and the same before/after hooks, with distinct child IDs and `parentToolCallId`. | Retain complete-input invocation binding. Test the installed session's actual nested pipeline with the production gate and owned write wrapper. |
| Handler integrity | `emitToolCall` still shares one event, short-circuits a block and propagates handler exceptions into a failed call. The validated input reaches execution. | Retain deep freezing and execute-time hash checks; a later child-input mutation fails before filesystem operations. |
| Scheduling | Parallel batches prepare all calls before execution; a sequential tool changes the batch to per-call preparation. Nested calls may overlap and carry independent IDs. Termination still requires every finalized result to request termination. | Retain per-invocation grants, execute-time breaker checks, and abort at turn end. Conservative third-party sibling withholding remains. |
| Tool exposure | MCP, `codemode`, PowerShell, deferred tools and `+name`/`-name` loadout modifiers are available. Inactive deferred tools may still be callable. | Keep the seven owned tools unchanged. New tools are denied by default, including deferred nested calls; pi's loadout is not an enclave grant. |
| Reviewer API | Direct pi-ai adapters require a branded, normalized transcript; system instructions live in a leading system message. | Normalize a fresh system/user transcript without tools or session history. Keep the checked endpoint/auth snapshot and bounded sampling. Increment transport identity to 3, invalidating previous qualification records. |
| Reviewer registry | ModelRegistry is now a facade over ModelRuntime. Its find/auth facade remains usable. | Preserve endpoint/auth identity checks; real registry and local HTTP protocol tests pass. No live model is declared qualified. |
| Resume history | Nested invocation records are persisted on a parent tool result as `nestedCalls`; oversized arguments can be omitted. | Restore available child inputs only as untrusted context. Never treat child metadata, tool output, errors or omitted arguments as authorization. |
| Credentials | MCP OAuth state is stored separately in `<agent-dir>/mcp-auth.json`. Server configuration may include literal headers and environment secrets. | Deny reads of live/default MCP OAuth and configuration files, plus project `.pi/mcp.json`. Built-in credential denials cannot become grantable. Existing profile lowering also denies writes to these paths. |
| File tools | Installed grep artifact is byte-identical to the v0.85.0 pin; its limit and formatting remain unchanged. The image detector adds BMP support at the same 4,100-byte sniff size. | Keep sandboxed grep semantics; update the MIME artifact pin and continue importing pi's detector on helper-provided bytes. Real edit/write/ls and concurrent read-binding regressions pass. |
| Packaging | v1.1 no longer imports the undeclared pi-server dependency from its root. | Remove the v0.85 packaging workaround; pin pi-ai and development pi to 1.1.0 and accept `>=1.1.0 <1.2.0` in peer/probe checks. Node minimum remains 22.19.0. |
| TUI/RPC and direct Bash | Fullscreen is now the TUI default. Explicit mode/attendance, user_bash operations, input provenance, confirm and abort APIs remain usable. | Keep explicit attendance and sandboxed direct Bash. RPC attendance still requires a client implementing enclave's handshake. |

Reviewed upstream sources at the target tag:

- [`agent-session.ts`](https://github.com/earendil-works/pi/blob/v1.1.0/packages/coding-agent/src/core/agent-session.ts): tool hooks, nested execution, registry construction and callable exposure.
- [`extensions/runner.ts`](https://github.com/earendil-works/pi/blob/v1.1.0/packages/coding-agent/src/core/extensions/runner.ts): ownership precedence, shared events, context and user Bash.
- [`agent-loop.ts`](https://github.com/earendil-works/pi/blob/v1.1.0/packages/agent/src/agent-loop.ts): validation, parallel/sequential scheduling and termination.
- [`codemode/index.ts`](https://github.com/earendil-works/pi/blob/v1.1.0/packages/coding-agent/src/extensions/codemode/index.ts) and [`mcp/index.ts`](https://github.com/earendil-works/pi/blob/v1.1.0/packages/coding-agent/src/extensions/mcp/index.ts): built-in registration and privileged services.
- [`mcp/oauth.ts`](https://github.com/earendil-works/pi/blob/v1.1.0/packages/coding-agent/src/extensions/mcp/oauth.ts) and [`mcp/config.ts`](https://github.com/earendil-works/pi/blob/v1.1.0/packages/coding-agent/src/extensions/mcp/config.ts): credential and configuration storage.
- [`ai/utils/transcript.ts`](https://github.com/earendil-works/pi/blob/v1.1.0/packages/ai/src/utils/transcript.ts), [`openai-completions.ts`](https://github.com/earendil-works/pi/blob/v1.1.0/packages/ai/src/api/openai-completions.ts) and [`model-registry.ts`](https://github.com/earendil-works/pi/blob/v1.1.0/packages/coding-agent/src/core/model-registry.ts): reviewer transcript, sampling, authentication and endpoint resolution.

## Limits of the extension boundary

Codemode's nested tool calls are gated, but its `models.classify()` and
`models.generateImages()` calls are credentialed services outside L2 and do not emit
child tool calls. Granting codemode is therefore a privileged grant to the complete
script. It remains denied by default; the migration does not automatically authorize it.

MCP startup, transport connection, OAuth and server-side tool execution are outside
enclave's OS sandbox. A tool denial does not prevent pi from starting or connecting to a
configured server. Configuration and extensions remain trusted startup inputs. MCP tool
source pins identify the registering extension, normally `builtin:mcp`, rather than a
server executable, URL or immutable identity. Do not interpret a source pin as endpoint
attestation. Built-in MCP resource tools and tool_search also remain denied by default.

No final immutable tool-call hook, generalized OS execution wrapper or per-confirm RPC
authentication was found. The existing core proposals remain relevant. The sibling pi
fork has no custom patches and can advance to the exact stable tag by fast-forward.
The Phase 4a container draft is independent of this upgrade; its rebase follows merge.

## Validation

- `npm run check`: typecheck and lint pass.
- Unit suite: 980 passed, including 12 new credential/nested-execution cases and a nested-history regression.
- Policy suite: 25 passed.
- Local conformance: 11 passed, 47 skipped. This host lacks `socat` and `fd`; the startup probe refuses rather than relaxing its requirements. This is not native sandbox sign-off.
- Clean tarball install: passed in an empty consumer with pi 1.1.0; CLI help and extension import both succeeded without pi-server. The check job now repeats that smoke test.
- Native Linux/macOS CI: required on the upgrade PR before merge.
- No live Ollama qualification or paid provider call was performed. Run reviewer qualification again after upgrading, because transport identity changed.

Historical September review/remediation reports retain their original baseline and
results. This report and the API baseline describe the upgrade candidate.
