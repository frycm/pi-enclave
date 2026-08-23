# Step 0 — SRT capability spike: findings and decisions

**Question the spike had to answer:** can `@anthropic-ai/sandbox-runtime` deliver the
Phase-1 platform-matrix guarantees, or must pi-enclave generate profiles itself?

**Answer: SRT is sufficient for Phase 1 on macOS.** Every filesystem, network and socket
row of the matrix is enforced by the kernel, and two design questions the plan left open
(long-lived helper, per-invocation capability widening) both resolve in our favour. Three
findings change the design; two change claims in the README.

| | |
|---|---|
| SRT version tested | **0.0.73** (pi's bundled example pins 0.0.26 — nine months of API behind) |
| Platform tested | macOS 15 (`darwin` 25.6.0), Seatbelt backend |
| Not tested | Linux / bwrap — no Linux host and no running container runtime available. Deferred to CI (step 1) |
| Spike code | `scratchpad/srt-spike/` — throwaway, not committed |

## Decisions

1. **Pin SRT `0.0.73`**, not the 0.0.26 the pi example uses. 0.0.73 adds the three things
   the design needs: `wrapWithSandboxArgv`, `SandboxViolationStore` with per-invocation
   attribution, and per-call `customConfig`.
2. **Use `wrapWithSandboxArgv`, never `wrapWithSandbox`.** It returns `{ argv, env }`, so
   the backend spawns a real argv instead of re-parsing a shell string. `wrapWithSandbox`
   returns a single string that must be run through `bash -c`, which adds a quoting layer
   for no benefit.
3. **`SandboxBackend.run` passes our own `ChildEnv` to `spawn`, and ignores the `env` SRT
   returns.** Verified below — this is safe and requires no cooperation from SRT.
4. **`Violation` carries a `source` discriminator.** Denials arrive by three different
   mechanisms with three different shapes; one parser cannot serve all of them.
5. **The `bash` violation parser must filter noise** before reporting anything.
6. **`allowPty: true`** in the Phase-1 dev profile (see finding 7).
7. **Keep SRT's proxy running even in `off` mode**, and document `off` as "no host is
   allowlisted", not "no socket exists" (see finding 6).

## Findings that change the plan

### 1. `ChildEnv` composes with SRT for free — step 2 gets simpler

SRT returns `process.env` plus its own additions (54 keys, including `SSH_AUTH_SOCK`,
`ANTHROPIC_BASE_URL` and every `CLAUDE_CODE_*` var). Passing that to `spawn` would leak
exactly what the README's env section forbids.

But SRT injects its own variables as a literal `env NAME=VALUE …` prefix **inside the
argv**, not through the returned env object. So the backend can pass a strict allowlist
env to `spawn` and SRT's variables still arrive:

```
ChildEnv passed to spawn:  PATH HOME USER LOGNAME SHELL TMPDIR PYTHONDONTWRITEBYTECODE
Visible inside sandbox:    33 vars — all proxy vars, SANDBOX_RUNTIME, TMPDIR=/tmp/claude,
                           GIT_SSH_COMMAND, GIT_CONFIG_PARAMETERS … present
Leaked secrets:            none
```

With `ANTHROPIC_API_KEY`, `AWS_SECRET_ACCESS_KEY` and `GITHUB_TOKEN` set in the parent,
none appeared in `env` output inside the sandbox. **`buildChildEnv` needs no SRT-specific
logic** — it builds the allowlist, hands it to `spawn`, and SRT's argv does the rest.

Note SRT already rewrites `TMPDIR` to `/tmp/claude`. pi-enclave should either adopt that
path or override it; it must not assume `$TMPDIR` is the host's.

### 2. Violations arrive three ways, not one — `Violation` needs a `source` field

| Source | Shape | Reliability |
|---|---|---|
| **errno** (fs helper) | `EPERM` / `EACCES` from the syscall | Exact. Structured. The operation and path are known to the caller |
| **kernel log** (bash) | `bash(22824) deny(1) file-write-create /private/…` — a raw log line via `log stream`, correlated by a base64 `commandId` baked into the SBPL deny message | Good, but text. Async — needs a drain window before the violations for a command are complete |
| **proxy** (network) | `deny network-outbound example.com:443 (host is not on the allow list)` | Good, but userspace, not kernel |

`SandboxViolationEvent` is `{ line, command?, encodedCommand?, timestamp }` — **just a
log line**. The structured `Violation` in the plan must be parsed out of it, per backend.

**Consequence for the fs helper (step 6): it does not need log parsing at all.** `EPERM`
from `open`/`readdir` is a better signal than any log line, and it is synchronous with the
call. Log parsing is only needed for `bash`, where the failing syscall is invisible to us.

**Noise filter is mandatory.** Nearly every command emits
`deny(1) sysctl-read kern.iossupportversion`, which is benign. Python multiprocessing
emitted **62** violations, all of them `__pycache__` writes into Python's own install
directory. A naive "`violations.length > 0` means denied" is wrong and would make the
status line and circuit breaker useless. SRT's `ignoreViolations` config is the intended
mechanism; pi-enclave ships a default noise list and treats the exit code plus the
operation's own error as the primary signal.

**Gap: `sudo` and `su` are denied with no violation event at all.** They fail with
`Operation not permitted` and exit non-zero, but nothing reaches the store. The matrix row
"script that calls `sudo` → violation, not a policy denial" therefore cannot be asserted
on the violation stream alone; assert on the exec failure instead.

### 3. The long-lived sandboxed helper works, and is fast — step 6 is unblocked

The plan flagged "SRT may assume one-shot commands" as a risk with a slower fallback. It
does not. A Node helper started via `wrapWithSandboxArgv` and kept alive on stdio:

```
helper ready                      40ms
200 JSON round-trips              4ms total → 0.02ms/call
enforcement inside the helper     read ws/ok.txt          OK
                                  read ~/.ssh/id_ed25519  DENY EPERM
                                  read ws/link→~/.ssh     DENY EPERM
                                  write outside ws        DENY EPERM
                                  readdir ws              OK
```

Per-call overhead is negligible; the cost is the 40ms startup, once per session. The
`FsClient` design in step 6 stands as written.

### 4. Symlink cases pass in Phase 1, not Phase 6 — the kernel resolves them

The plan marked C3 (symlink read race) and C4 (symlink write) as `todo` until the fs
helper landed. They already pass through plain `bash`, because Seatbelt evaluates the
policy against the **resolved** path:

```
cat ws/link-to-ssh/id_ed25519
  → deny file-read-data /private/var/…/enclave-home-…/.ssh/id_ed25519
echo x > ws/link-to-etc          (→ /etc/hosts)
  → deny file-write-data /private/etc/hosts
```

The violation names the real target, not the path the agent asked for. This is the
strongest single result of the spike: **the TOCTOU argument in the README is correct and
the mitigation is free** — there is no check-then-open window to race because there is no
check, only a kernel decision at `open` time. Both rows move to step 4/5.

### 5. Per-invocation `customConfig` works and does not leak — Phase 3's hatch is real

Passing a widened `filesystem.allowWrite` as `customConfig` to a single
`wrapWithSandboxArgv` call let that one command write outside the workspace; the very next
command under the base profile was denied again. This is exactly the "one-shot profile =
base + one requested capability" mechanism the README specifies for the capability retry
hatch, and it needs no support from us beyond passing the object.

Caveat: `SandboxManager` is a **process-global singleton** (`initialize()` once,
`updateConfig()` to mutate). Concurrent commands under genuinely different base profiles
are not possible; per-call `customConfig` is the only supported divergence. Fine for the
design as written — worth knowing before anything assumes two live profiles.

## Findings that change the README

### 6. `network.mode: "off"` is not what the README implies

The README's v1 cut says **"Strict offline. `network.mode: "off"` is the only mode."**
What SRT actually gives with `allowedDomains: []`:

| Probe | Result |
|---|---|
| raw TCP to `1.1.1.1:80` (python) | **kernel-denied** — `PermissionError` |
| DNS resolution | **blocked** — `gaierror` |
| `nc -z 1.1.1.1 80` | **kernel-denied**, violation recorded |
| `curl https://example.com` | reaches SRT's proxy, gets **403** — denied in userspace |
| connect to `localhost:<proxyPort>` | **reachable** |

So `off` means *no host is allowlisted*, enforced at the kernel for raw sockets and at the
proxy for HTTP. It does **not** mean no network stack: SRT always starts a proxy and the
SBPL explicitly allows `network-outbound` to `localhost:<port>`. That is a userspace
boundary, and the README should say so rather than implying a kernel-absolute offline.
Not a v1 blocker — nothing outside the proxy is reachable — but the wording overclaims.

### 7. Reads are a **deny-list**, not an allow-list

The architecture table says "read-only root, explicit writable roots". The writable-roots
half is exact. The read half is not: SRT's model is `(allow file-read*)` followed by
`(deny file-read* (subpath …))`. Reading a file outside the workspace succeeds unless it
is explicitly denied — confirmed: `cat /tmp/enclave-out-…/secret.txt` returned its
contents.

**SRT cannot express "the agent may only read the workspace".** If pi-enclave ever wants
that, it needs its own profile generation. For Phase 1 the deny-list satisfies every
matrix row, but the README's read-side framing should be corrected to "secrets and
declared paths are denied for reading", which is what it actually is.

Related: SRT's **default** writable paths include `/tmp/claude`, `~/.npm/_logs` and
`~/.claude/debug`, and it auto-denies writes to agent-hijacking config files
(`.bashrc`, `.zshrc`, `.claude/commands`, `.claude/agents`, `.git/hooks`, `.git/config`,
`.mcp.json`, `.vscode`, `.idea`). The auto-denies are welcome and overlap pi-enclave's
protected paths. The default *writable* paths are not ours and must be audited — a
sandbox that can write `~/.claude/debug` is wider than the profile we advertise.

### 8. PTYs are denied by default

`script -q /dev/null echo hi` → `openpty: Operation not permitted`, violation
`deny file-write-data /dev/ptmx`. Anything interactive (`vim`, `less`, `top`) fails.
SRT exposes `allowPty`. The matrix row says "works / violation as configured", so this is
a configuration decision, and for a dev profile the answer is `allowPty: true` — an agent
that cannot run `git log` without `| cat` is going to fight the sandbox constantly.

Separately, set `PYTHONDONTWRITEBYTECODE=1` in `CHILD_ENV_BASE`: without it every Python
invocation tries to write `__pycache__` into read-only install directories, producing
dozens of spurious violations (62 in one `multiprocessing` call).

## Matrix status after the spike (macOS/Seatbelt)

| Row | Result |
|---|---|
| C1 write outside writable root | denied — `file-write-create` |
| C2 read `~/.ssh/id_ed25519` | denied — `file-read-data` |
| C3 symlink read race | **denied on the resolved path** |
| C4 symlink write | **denied on the resolved path** |
| C5 curl / nc / raw socket / DNS | all denied (proxy 403 for HTTP, kernel for the rest) |
| C6 PTY | denied by default; `allowPty` opens it |
| C6 multiprocessing | fails on `__pycache__` writes — fix with `PYTHONDONTWRITEBYTECODE` |
| C6 git in workspace | works |
| C7 `sudo` / `su` | denied — but **no violation event** |
| C8 unix sockets (ssh-agent, arbitrary socket) | denied — `network-outbound /private/var/run/…` |
| C9 env leak | leaks with SRT's env; **clean with `ChildEnv`** |
| C10 happy path | works |

## Open, carried into step 1

- **Everything above is macOS-only.** bwrap must be validated in CI on `ubuntu-latest`;
  `/proc/self/environ` (C9), `--die-with-parent` reaping, and the seccomp violation
  monitor are the Linux-specific unknowns.
- **Log-monitor cost** — `enableLogMonitor: true` spawns a `log stream` subprocess per
  session. Measure its idle CPU before enabling it by default.
- **Violation drain window** — kernel-log violations are async. The spike used an 800ms
  sleep. The backend needs a defined settle policy so a command's violation list is
  complete when reported; guessing a delay is not acceptable in the shipped code.
