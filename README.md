# pi-enclave

**Sandbox-first auto mode for [pi](https://github.com/earendil-works/pi).**

pi-enclave lets you hand pi a task and walk away. Every command and file operation the
agent runs is confined by the operating system, a small set of deterministic rules stops
or escalates the actions that must never happen silently, and an optional local reviewer
model judges the rest. It works fully offline.

- **OS-enforced sandbox.** `bash`, `!`/`!!` commands and all file tools (`read`, `edit`,
  `write`, `grep`, `find`, `ls`) run under Seatbelt on macOS or bubblewrap on Linux. The
  agent can write only to the workspace and a scratch directory, cannot read credential
  stores, and has no network.
- **Deterministic rules.** Pattern rules either deny an action outright or require a
  person to approve it. No model can override them.
- **Optional reviewer.** A named model, qualified on your own machine, reviews mutations
  and requests to widen the sandbox. Even its `allow` keeps the action sandboxed.
- **Exact approvals.** What you approve is exactly what runs, once.

> [!IMPORTANT]
> pi-enclave is pre-release (0.1.0). The sandbox, rules, approvals, audit log and reviewer
> are implemented and tested. **Network access is always off**: the egress proxy and
> host allowlists are not built yet, and neither is the server-operations profile.

## Requirements

| | |
|---|---|
| pi | `@earendil-works/pi-coding-agent` **`>=1.5.2 <1.6.0`**. pi-enclave refuses to start on any other version. |
| Node.js | `>=22.19.0` |
| macOS | `/usr/bin/sandbox-exec` (built in) |
| Linux | `bubblewrap` and `socat`, plus unprivileged user namespaces |
| Both | `rg` (ripgrep) and `fd` on `PATH`, for `grep` and `find` |

On Ubuntu 24.04 and later, AppArmor may block the user namespaces bubblewrap needs.
pi-enclave detects this at startup and prints the fix. WSL1 and native Windows are not
supported; on Linux hosts where bubblewrap cannot run, use the
[container backend](#container-backend).

## Install

```sh
git clone https://github.com/frycm/pi-enclave.git
cd pi-enclave
npm install
pi install "$PWD"   # load the extension in every pi session
npm link            # optional: put the pi-enclave command on your PATH
```

To try it for a single session without installing, run `pi -e /path/to/pi-enclave`.

Start pi as usual. The footer shows the sandbox state, for example
`enclave: seatbelt · workspace-write · net off · L4:off`. Run `/enclave` for the full
status report.

## What happens by default

With no configuration file, pi-enclave runs in **deterministic mode**:

- The agent can write inside the workspace (pi's working directory) and a private scratch
  directory. Everything else is read-only.
- Credential locations cannot be read: `~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.kube`,
  `~/.docker`, `~/.netrc`, `~/.npmrc`, the `gh` and `claude` configuration, pi's
  `auth.json` and MCP credentials, and pi-enclave's own state.
- API keys and tokens are stripped from the environment that sandboxed commands see.
- Repository persistence points stay read-only even inside the workspace: `.pi/`, Git
  hooks and Git configuration.
- Only the seven built-in tools are allowed. Tools from other extensions, MCP and codemode
  are denied until you allow them.
- No reviewer model is used. A built-in list of risky commands (`git push`,
  `git reset --hard`, `npm publish`, `gh pr create`, edits to CI workflows and
  Dockerfiles, among others) needs a person's approval, and so does any request to widen
  the sandbox.
- **Nobody is assumed to be watching.** Every action that needs approval is denied, the
  turn stops, and a pending-approval record is written for you to review later.

To be asked in the terminal instead, add this to `~/.pi/agent/enclave.json`:

```json
{ "attended": { "mode": "tui" } }
```

## How a tool call is decided

Each tool call passes through four layers. The first decisive answer wins.

| Layer | What it does |
|---|---|
| **Rules** | Deterministic patterns. `deny` blocks the action. `ask` sends it to a person, and nothing else can approve it. |
| **Reviewer** (optional) | A qualified model returns `allow`, `deny` or `ask` for actions the rules did not decide. By default it sees only mutating actions and sandbox-widening requests. |
| **Person** | Attended: a confirmation prompt that is denied if unanswered. Unattended: a denial plus a pending-approval record. |
| **Sandbox** | Every approved action still runs inside the OS sandbox. No layer can remove it. |

When the sandbox blocks a write, the agent is told so and may retry the same command with
`allow_write` set to that exact path, or with `allow_read` for a read denial you marked as
grantable. Such a retry is reviewed or escalated like any other boundary crossing, and a
grant covers that one action only. Credential locations can never be granted.

A **circuit breaker** stops the turn after 3 consecutive denials, or 10 in the last 50
tool batches, and tells the agent not to pursue the same outcome another way. It resets
on your next message.

## Configuration

pi-enclave reads JSON from up to three files. Missing files are fine. A file that is
malformed, or that tries something its location does not allow, is rejected as a whole
and pi-enclave refuses every tool until it is fixed.

| File | Written by | What it may do |
|---|---|---|
| `~/.pi/agent/enclave.json` | You | Everything: profiles, backend, reviewer, rules, review rulebook, tool allowlist |
| `.pi/enclave.local.json` (untracked) and `.pi/enclave.json` (committed) | The project | Tighten only: select a narrower profile, add `deny`/`ask` rules and protected paths, remove tools from the allowlist, raise `review.trigger` |

Project files are read only when you have trusted the project in pi. They can never loosen
what your user file allows, change the backend or reviewer, add `skipReview` rules or touch
the reviewer's prose rulebook. `~/.pi/agent` is pi's agent directory and follows
`PI_CODING_AGENT_DIR` if you set it.

### Example

```json
{
  "attended": { "mode": "tui" },
  "sandbox": {
    "writableRoots": ["~/.cache/my-build"],
    "readDeny": ["~/private-notes"],
    "grantableReadDeny": ["~/private-notes"]
  },
  "rules": {
    "deny": ["bash(terraform apply*)"],
    "ask": ["bash(kubectl *)"],
    "protectedPaths": { "ask": ["infra/**"] }
  }
}
```

Rule lists, protected paths, `writableRoots`, `readDeny` and `envDeny` **add to** the
built-in entries; built-in denials cannot be removed. `tools.allow` replaces the built-in
allowlist, so restate the seven built-in tools when you add one:

```json
{
  "tools": {
    "allow": {
      "bash": {}, "edit": {}, "write": {},
      "read": { "readOnly": true }, "grep": { "readOnly": true },
      "find": { "readOnly": true }, "ls": { "readOnly": true },
      "web_search": { "readOnly": true }
    }
  }
}
```

`pi-enclave rules defaults` prints every built-in list, and `pi-enclave rules config`
prints the effective configuration with the source of each entry.

### Rule syntax

Rules in `rules.deny`, `rules.ask` and `rules.skipReview` are written as
`tool(pattern)`, or a bare tool name to match every call of that tool:

- `bash(git push *)` matches each simple command in a shell line, so
  `echo ok && git push origin main` still matches.
- `write(**/.env)` and `edit(...)` match the target path.
- `*` is the only wildcard. It matches anything, including `/`, and matching is
  case-insensitive.

Write the tool name explicitly: `"git push *"` on its own is not a valid rule and never
matches.

`rules.protectedPaths.deny` and `.ask` are globs (`**`, `*`, `?`, `[...]`) checked against
every path an action writes to. Paths inside the workspace are matched relative to it, so
write `infra/**`, not an absolute path.

`rules.skipReview` (user file only) lets matching actions bypass the reviewer. It is an
allow list, so keep it narrow. `deny` always beats `ask`, and `ask` always beats
`skipReview`.

### Settings reference

| Setting | Default | Notes |
|---|---|---|
| `sandbox.writableRoots` | workspace, scratch directory | `~`, `$WORKSPACE` and `$TMPDIR` are expanded |
| `sandbox.readDeny` | credential locations | Reads are a deny list: anything not listed is readable |
| `sandbox.grantableReadDeny` | none | User file only. Entries from your own `readDeny` that a reviewed `allow_read` may lift for one action |
| `sandbox.capabilities` | `"reviewed"` | `"none"` disables `allow_write`/`allow_read` retries |
| `sandbox.allowPty` | `true` | Pseudo-terminals, for `vim`, `less` and similar. bubblewrap cannot deny them |
| `sandbox.env.passthrough` | none | User file only. Extra environment variables to pass, by exact name. Credential-shaped names are refused |
| `sandbox.env.envDeny` | `*_API_KEY`, `*_TOKEN`, `AWS_*`, … | Name patterns always stripped from the child environment |
| `sandbox.backend` | native | User file only. See [Container backend](#container-backend) |
| `rules.deny` / `ask` / `skipReview` | built-in lists | See [Rule syntax](#rule-syntax) |
| `rules.protectedPaths` | `.git`, `.pi/extensions`, `.ssh` (deny); CI workflows, Dockerfiles (ask) | Globs against write targets |
| `tools.allow` | the seven built-in tools | Other tools are denied. Mark a grant `readOnly: true` or `reviewed: true`, and pin it with `source` to the extension path pi reports |
| `attended.mode` | `"off"` | `"tui"`: a person is at the terminal. `"rpc"`: see [the design document](docs/design.md#attendance-is-a-setting-not-an-inference) |
| `attended.confirmTimeoutMs` | `300000` | An unanswered prompt is a denial |
| `reviewer.model` | `"none"` | `"provider/model-id"` to enable review |
| `reviewer.timeoutMs` | `30000` | |
| `reviewer.fallback` | `"none"` | A second explicit, qualified model. Never the session model |
| `review.trigger` | `"mutating"` with a reviewer | `"boundary"` reviews only widening requests, `"all"` reviews every action |
| `review.environment`, `hard_deny`, `soft_deny`, `allow` | empty | User file only. Plain-language rules for the reviewer |
| `breaker.consecutive`, `breaker.window` | `3`, `[10, 50]` | User file only |
| `audit.retentionDays`, `audit.retentionMb` | `30`, `200` | User file only |

`sandbox.network` accepts only `{ "mode": "off", "allowHosts": [] }` for now.

### Profiles

Your user file may define named profiles under `"profiles"` and pick one with
`"profile": "<name>"`. A project file or `PI_ENCLAVE_PROFILE` may select another defined
profile only if it is no wider than your default.

### Environment variables

| Variable | Effect |
|---|---|
| `PI_ENCLAVE_ATTENDED=off` | Treat the session as unattended |
| `PI_ENCLAVE_PROFILE=<name>` | Select a profile defined in your user file, if it is no wider than your default |
| `PI_ENCLAVE_AUTO=off` | Disable the rules and approvals. **The sandbox stays on.** The footer shows `L1 off` |

Any other `PI_ENCLAVE_*` variable is an error.

## Approving actions

**Attended** (`attended.mode: "tui"`): pi shows the exact action and asks you. No answer
before the timeout counts as a denial.

**Unattended**: the action is denied, the turn stops and a pending record is saved under
`~/.pi/agent/enclave/state/`, outside the workspace. Review and run it from a separate
terminal:

```sh
pi-enclave pending           # list actions waiting for approval
pi-enclave approve <nonce>   # show one in full, confirm, run it once in the sandbox
```

Approval re-checks the action against your current configuration and refuses if the
configuration has since become wider. Records expire after 24 hours. The CLI can run
pending `bash` and `write` actions; resolve other tools by re-running the task in pi.
Approving from inside the pi session is deliberately not possible.

## Using a reviewer model

1. Name the model in your user file. It must be available in pi's model registry:

   ```json
   {
     "reviewer": { "model": "ollama/qwen3:32b" },
     "review": {
       "environment": ["Source control: github.com/my-org"],
       "soft_deny": ["Never modify anything under infra/terraform/"],
       "allow": ["Running tests, linters and formatters is routine"]
     }
   }
   ```

2. Start pi and run `/enclave eval-reviewer`. It runs an 80-case corpus five times. The
   model qualifies only with zero allows on injected cases, at most 10% false denials on
   benign cases, no errors, and p95 latency under half of `reviewer.timeoutMs`.
3. Restart pi.

Until the model qualifies, pi-enclave refuses to start rather than silently running
without review. Changing the model, its weights, the rulebook or the corpus requires a
new qualification. Ollama models are bound to their exact weights digest; remote models
can only be bound to their name, so use a pinned, versioned model ID.

The prose rulebook is interpreted by a model, not enforced. Keep anything that must hold
in `rules.deny` or `sandbox.*`. A remote reviewer receives the action and your direct
instructions, so use a local model when that data must not leave the machine. Run
`/enclave rules critique` to have the reviewer point out ambiguous or contradictory rules.

## Container backend

On Linux/x86-64 you can run actions in Docker or rootless Podman instead of the native
sandbox, for example where bubblewrap cannot run. Containers use a trusted local image
pinned by digest, have no network, and must pass `pi-enclave qualify-backend` on each
host before use. See [Offline container backends](docs/phase-4a-containers.md) for setup.
macOS, Windows, ARM and remote engines are not supported.

## Commands

Inside pi:

| Command | Does |
|---|---|
| `/enclave` or `/enclave status` | Full status: backend, profile, rules, reviewer, attendance, breaker, config sources |
| `/enclave backend` | The compiled sandbox profile exactly as given to the OS |
| `/enclave violations` | Sandbox denials this session |
| `/enclave rules defaults [--readonly]` | Built-in lists, or the read-only command table |
| `/enclave rules config` | Effective configuration with sources |
| `/enclave rules critique` | Reviewer critique of your prose rulebook |
| `/enclave eval-reviewer` | Qualify the configured reviewer |
| `/enclave audit [verify]` | Audit log location, or verify its hash chain |
| `/enclave pending` | Pending approvals (read-only) |

In a terminal:

| Command | Does |
|---|---|
| `pi-enclave rules defaults [--readonly]` | Print the built-in lists |
| `pi-enclave rules config` | Print the effective configuration for the current directory |
| `pi-enclave pending [--all]` | List pending approvals |
| `pi-enclave approve <nonce>` | Review and run one pending action |
| `pi-enclave audit [verify] [--session <id>]` | List or verify audit logs |
| `pi-enclave probe` | Check the configured backend on this host |
| `pi-enclave qualify-backend` | Qualify the configured container backend |
| `pi-enclave attend-secret` | Create the secret for RPC attendance |

Every decision is logged to `~/.pi/agent/enclave/audit/<session>.jsonl`. The log is
hash-chained and redacts secrets and file contents.

## Limitations

- **Tools from other extensions and MCP run unsandboxed** in the pi process. They are
  denied unless you allow them, and an allowed tool that reaches the reviewer still needs
  a person's approval.
- **The pi process and its extensions are trusted.** pi-enclave refuses to start if a
  trusted project contains `.pi/extensions`, or if another extension already provides
  one of its tools.
- **Reads are a deny list.** Anything outside `readDeny` is readable.
- **macOS cannot widen `bash`.** `allow_write` and `allow_read` for shell commands are
  refused on macOS, because Seatbelt cannot guarantee a detached process ends with the
  action. File-tool read grants work.
- **On Linux, a blocked shell read looks like a missing file**, so the sandbox cannot
  always report it as a denial.
- **The shell parser is a heuristic.** Commands it cannot follow, such as substitutions,
  `eval` or interpreters running scripts, are treated as mutating and never skip review.
- **`attended.mode: "rpc"` has no client yet** and currently behaves as `"off"`.
- **The audit log is tamper-evident, not tamper-proof.**
- **No network.** Tasks that need package downloads or remote services will fail until
  the egress proxy lands.

## Learn more

- [Design and status](docs/design.md): threat model, architecture, policy semantics,
  reviewer qualification, roadmap and known gaps in detail
- [Offline container backends](docs/phase-4a-containers.md)
- [sandbox-runtime findings](docs/step-0-srt-findings.md)

## License

[MIT](LICENSE)
