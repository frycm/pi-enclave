# Offline container backends

Phase 4a implements an offline container boundary for Linux/x86-64. Native Seatbelt or
bubblewrap remains the default. An explicit Docker/Podman choice, or an `auto` fallback,
requires qualification on the machine that will run it. No reviewer model is needed.

## Configure and qualify

Use a trusted, already-local image containing `/bin/bash`, `/usr/bin/env`, Node 22.19+
or 24+, `rg`, and `fd`. Git and Python are also needed by the shared conformance suite.
Images must not contain secrets or declare `VOLUME` entries. Runtime code never pulls,
builds, or executes a repository Dockerfile. The reviewed CI fixture is
[`docker/Dockerfile.conformance`](../docker/Dockerfile.conformance); its explicit build
fetches trusted public packages and is separate from sandboxed action execution.

Put this in the **user-global** `~/.pi/agent/enclave.json` (or the configured pi agent
directory). Replace the example digest with the ID or repository digest of your local image:

```json
{
  "sandbox": {
    "backend": {
      "kind": "podman",
      "binary": "/usr/bin/podman",
      "image": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
      "readableRoots": []
    }
  }
}
```

The binary must be an absolute canonical regular file. Docker additionally requires
`"socket": "/var/run/docker.sock"` (or another explicit local Unix socket). Docker
contexts, remote endpoints, image tags and ambient engine environment are not used.
For fallback selection use `"kind": "auto", "fallback": "podman"` or `"docker"`,
with the corresponding binary, image and socket. A passing native probe takes precedence
in `auto`; explicit `docker`/`podman` always selects that engine.

Run from the workspace:

```sh
pi-enclave qualify-backend
pi-enclave probe
```

Qualification prints every row and writes a mode-0600 record outside the workspace. Its
identity includes the host, kernel, UID, engine/runtime metadata, immutable image ID,
trusted backend settings and the implementation, helper and corpus source. A change
invalidates the record and requires another successful run. A failed or missing record
refuses session startup and standalone approval execution. Project files, environment
variables and narrower profiles cannot change engine selection or images.

`readableRoots` exposes additional canonical host files or directories read-only, at
the same absolute path. Unmounted host data is absent. Writable roots come from the
existing dev profile. Container `/tmp/claude` is private scratch, never a host bind;
shell scratch lasts one action and base-helper scratch lasts that helper's lifetime.
The image supplies the toolchain, so container PATH is fixed to trusted image locations.

## Boundary and lifecycle

Every shell invocation runs in a fresh container with the host UID/GID, read-only root,
private PID/IPC/cgroup namespaces, no capabilities, no-new-privileges, 256 processes,
512 MiB memory, two CPUs and 128 MiB private `/tmp`. Podman maps the current user with
`keep-id`; rootless or UID-remapped Docker is refused. The engine socket and storage
must remain outside exposed roots. Image entrypoint and environment are replaced by a
fixed `env -i` launcher and the existing credential-filtered child environment.

`--network=none` and a default-deny x86-64 seccomp policy deny socket creation, connect,
network namespaces and io_uring. AF_UNIX `socketpair` is allowed for private subprocess
stdio; external Unix sockets cannot be opened. Credentials stay in the pi parent.
Network modes and `allow_host` grants remain unavailable until Phase 4b.

Nested read denials are empty read-only bind masks; write denials are read-only binds.
Each denial's ancestors are pinned so renaming `.git` or another ancestor cannot reveal
its original contents. Mount inode/type and canonical ancestry are checked before
execution and helper calls. An unsupported layout fails before any action starts:

- Missing, symlinked or nonregular nested denials; aliases reaching an exposed source.
- Host mounts over container runtime paths such as `/`, `/usr`, `/etc`, `/proc` or `/dev`.
- Engine, container-control state or host executables inside agent-writable/exposed roots.
- An absent default project `.pi/mcp.json` is handled by creating a safe `.pi` anchor and
  masking the whole `.pi` directory. Other files under that directory are consequently
  unavailable to the container; existing credential files receive their exact masks.

One-shot write grants create one extra bind for that invocation. A read grant removes
only the exact grantable denial and uses a fresh command container or isolated helper
lease. Base profiles and sibling calls stay unchanged; disposing the lease revokes it.
The existing action lock binds approvals to complete tool inputs and consumes them once.
Mount sources, including write-grant targets, must already exist. To create a new file
outside the workspace, request its existing parent directory as the grant; an exact
missing-file grant refuses instead of creating host content before execution.

A detached trusted supervisor owns create/start/remove. Timeout, abort, input closure,
helper cancellation and parent death close its lifetime channel and trigger forced
container removal, killing descendants that changed process group. A supervisor error
refuses further execution on that backend. The engine and host supervisor are trusted;
stopping the engine or killing both parent and supervisor is outside this lifetime model.

## Qualification and evidence

The versioned local corpus has 14 mandatory rows:

| Row | Evidence |
|---|---|
| Workspace and UID | Host-visible write, host UID, zero capabilities, enforced PID/memory limits |
| Outside writes and symlinks | Outside target stays unchanged through direct and symlink writes |
| Nested read denials | Secret stays hidden through direct, symlink and enumeration reads |
| Protected metadata and rename | `.git` config/hooks stay unchanged, ancestor rename cannot expose them |
| Environment | Host and image secrets are absent |
| TCP, DNS and Unix socket | Real reachable host listener is blocked; socket/DNS calls fail |
| File helper and search | Real read/write, grep and glob succeed within the profile |
| Write grant isolation | Exact approved write succeeds; overlapping sibling remains denied |
| Read grant and helper lease | Exact approved read succeeds, sibling stays denied, revoked lease refuses |
| Timeout descendants | A detached delayed writer is removed before it can write |
| Abort | Cancellation terminates the invocation |
| Parent death | Killing the host process cannot leave a delayed descendant writer |
| Large output and helper cancellation | Two MiB output arrives intact; cancelled search refuses |
| Topology change | Replacing a protected mount source requires recompilation |

`npm run test:container` runs those rows against a selected real engine, then drives the
installed pi 1.1.0 session's nested write/read/bash pipeline and standalone approval
through production backend selection. It also runs the shared native conformance suite.
Missing or symlinked read-denial rows F10/F13/F14 assert compilation refusal instead of
running an action under that unsupported layout. All other shared rows execute.

Local evidence: Linux/x86-64, kernel 7.0.0-30-generic, rootless Podman 5.7.0 with seccomp
and delegated cgroup v2. Docker and Podman have separate Ubuntu CI jobs, each building
the reviewed fixture explicitly and running the real suites. Set
`PI_ENCLAVE_TEST_CONTAINER_ENGINE=docker|podman` and
`PI_ENCLAVE_TEST_CONTAINER_IMAGE=<immutable-local-id>` only for the test process.

macOS/Windows engines, ARM hosts, remote engines, remapped Docker and Podman without
delegated resource controllers are disabled. Enabling another configuration requires
its own host-path, UID, resource, capability and parent-death evidence. Isolated builds
of untrusted repository Dockerfiles remain a separate gate; this implementation only
accepts images selected by the user outside the agent workflow.
