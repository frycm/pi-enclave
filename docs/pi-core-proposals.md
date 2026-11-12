# pi core proposals: upstream discussion drafts (#29)

Drafts for discussions at [`earendil-works/pi`](https://github.com/earendil-works/pi), one per
proposal from the [core changes](../README.md#core-changes-to-propose-to-pi) list. Each is
meant to be posted as it stands, before any patch is offered upstream: a patch upstream does
not take is carried and re-tested on every release.

Status, November 12, 2026: **none posted.** Posting is the maintainer's call; once a
discussion is open, link it from the README table and from #29.

Checked against pi `v1.5.2` (`b4afddd`) and upstream `main` at `9b88b94`. Paths are in
`packages/coding-agent/src/core/` unless they say otherwise.

---

## 1. An execution-boundary hook for tools

**Problem.** `tool_call` decides before a tool runs, not at the moment it runs.

1. In the default parallel mode, `executeToolCallsParallel` (`packages/agent/src/agent-loop.ts`)
   prepares every call of an assistant message, running `beforeToolCall` for each, before any
   of them executes. A permission extension whose state changes during the batch cannot act
   on that change. Example: a denial circuit breaker that opens on the second call of three.
   The third call was admitted before the breaker opened, and nothing asks again.
2. `event.input` is the object `execute` receives (`ToolCallEventResult` documents in-place
   mutation as the way to rewrite arguments). An extension that keeps a reference can change
   the arguments after another extension approved them. The durable harness's specification
   (`packages/durable/docs/suspendable/spec.md` at `v1.5.2`) says the same about `beforeTool`:
   "An approval binds to the arguments it saw: a later `beforeTool` that replaces them can make
   a call run with arguments nobody approved."

**What a permission extension does today.** pi-enclave deep-freezes `event.input` so that a
later mutation throws, binds its own tools' operations to the approved call through
`AsyncLocalStorage` and re-checks from inside `execute`, and, for tools it does not own,
keeps them out of any batch where an earlier call could open the breaker, because it has no
way to re-check them.

**Proposal.** `pi.wrapToolExecution(wrapper)`, returning an unregister function:

```ts
pi.wrapToolExecution(async (call, next, ctx) => {
  // call: { toolName, toolCallId, parentToolCallId?, sourceInfo?, input }
  if (!stillAllowed(call)) throw new Error("Refused at execution");
  return next();
});
```

- Runs after every `tool_call` handler allowed the call, immediately before the tool, for
  every tool (built-in, extension, SDK, MCP) and for calls made through `ctx.executeTool()`.
- `call.input` is a deep-frozen copy taken after the `tool_call` handlers, and it is the
  object `execute` receives. Without wrappers nothing is copied or frozen.
- Wrappers chain in extension load order; the first is outermost. `next()` runs once.
- A throw refuses the call and becomes its error result; a result returned without `next()`
  replaces the tool's.
- agent-core gets the matching `AgentLoopConfig.wrapToolExecution(context, execute, signal)`.

**What it does not do.** In-process tools still run with pi's privileges. It is a reliable
decision point, not a sandbox.

**Prototype.** [`frycm/pi#1`](https://github.com/frycm/pi/pull/1), one commit on `v1.5.2`, with
tests in agent-core and a session-level suite. pi-enclave uses it behind a feature probe and
keeps its current behaviour on unpatched pi.

**Open questions for upstream.** Whether wrappers should also see `assistantMessage`; whether
freezing should be opt-in per wrapper rather than implied by having one; how this maps onto
the durable harness's `wrapTool` decorators, which wrap a tool by name rather than every
execution.

---

## 2. Provenance on stored user messages

**Problem.** A permission extension needs to know whether a user message was typed by a
person, came over RPC, or was sent by an extension (`pi.sendUserMessage`). The `input` event
has `source`, but the stored user message does not, and prompt templates and skills expand the
text in between. pi-enclave's `ProvenanceTracker` therefore matches `input`,
`before_agent_start` and `message_start`, and when the expanded text does not match it assumes
the newest pending input is the one that expanded.

**Example.** A person types `/fix`, which expands to a template. The stored user message holds
the expansion only. Whether that message may authorize "force-push this branch" depends on
the tracker having seen the `input` event and paired it with the right `before_agent_start`.

**Proposal.** Store `source` (`interactive | rpc | extension`) and the pre-expansion text on
user message entries, and pass both on `message_start`.

**Would remove** the tracker and its heuristic in pi-enclave, and give any permission
extension correct authorization evidence. An RPC host such as pi-huginn would want one more
distinction (a message a person typed in the client versus one its own agent generated), which
an optional client-supplied origin label on RPC prompts would cover.

---

## 3. A typed permission request

**Problem.** An extension that asks "may this tool call run?" has `ctx.ui.confirm`, a boolean
question. A headless or RPC client cannot tell it from any other confirm, so it cannot render
the call, show its hash, or answer by policy. In print and json modes every extension defines
its own unattended answer. And an answer cannot be bound to the action: pi-enclave
authenticates the RPC channel once with an HMAC handshake over `ctx.ui.input`, which binds the
channel but not each answer.

**Proposal.** A permission request in the UI and RPC protocol: tool name, canonical
description, action hash, timeout and default answer, an optional `challenge` on the request
and `proof` on the response, and a defined answer in print and json modes. pi can then report
"blocked on permission" uniformly in every mode.

**Would remove** pi-enclave's per-mode fallbacks and replace the channel handshake with a MAC
over each action hash. Best designed together with an RPC client that answers these (pi-huginn).

**Related upstream work.** The durable harness (`packages/durable`, unreleased for the coding
agent) parks a call at a `beforeTool` gate until a signal arrives, with an approval example.
A permission request for the coding agent should have the same shape, so that one design
serves both.

---

## 4. A spawn hook for stdio MCP servers

**Problem.** An MCP stdio server is a child process that pi spawns directly
(`packages/mcp/src/transports/stdio.ts`). A sandbox extension can wrap `bash` with
`spawnHook`, but not a server process, so MCP tools can only be allowlisted or denied.
`pi.registerMcpServer` does not help: a server of the same name in `mcp.json` takes
precedence.

**Proposal.** A hook that receives a stdio server's command, arguments, environment and
working directory before spawn and may return replacements, like `BashSpawnHook`.

**Would allow** pi-enclave to start MCP servers inside its sandbox profile: writes to the
workspace only, no network unless granted, an environment built from an allowlist. HTTP
servers are a network-policy question and out of scope here.

---

## 5. Smaller items, raised when the occasion arises

- **A batch-level stop from `tool_call`**, such as `{ block: true, abortBatch: true }`.
  `terminate` ends the run only when every result in the batch sets it, so a breaker calls
  `ctx.abort()` and sends a follow-up message instead. Mostly covered by item 1.
- **Pinned-endpoint model calls and model identity.** `ModelRegistry` re-resolves base URL and
  auth on each call, so a caller that checked a model's identity cannot be sure the call goes
  to the same endpoint. A call against a resolved endpoint snapshot, and a stable identity for
  local models (weights digest, runtime version, context size), would serve any reviewer or
  classifier.
- **Trust over context files.** `AGENTS.md`, `CLAUDE.md` and `AGENTS.override.md` load
  whatever the project-trust answer is (`loadProjectContextFiles` in `resource-loader.ts`).
  Either an extension veto over context files, or a `project_trust` event that lists the
  resources about to load, would let an extension refuse instructions planted in a writable
  workspace.
