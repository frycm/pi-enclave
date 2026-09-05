# Phase 4a: offline Docker and Podman

Status: first implementation slice, experimental test entry point. Production
extension and standalone approval still select the native backend. This is not
Phase 4 sign-off and does not enable network access or container fallback.

For Ubuntu/macOS prerequisites and test commands, see [local testing with Podman](local-testing.md).

Phase 3's seven findings were repaired and PR #7 merged after native Linux and
macOS CI passed; see [remediation evidence](phase-3-remediation.md).

## Delivered in this slice

- A `SandboxBackend` implementation for a local Linux Docker daemon with seccomp.
  It accepts only an explicitly trusted image already present by immutable image
  ID or repository digest. It resolves the digest to an image ID once, uses
  `--pull=never`, overrides entrypoint/workdir/user, refuses implicit image volumes,
  and never builds an agent project's Dockerfile.
- Explicit host read/write bind roots. Image paths supply everything else; this
  differs from native backends' broad host read visibility. The compiled profile
  also reports private `/tmp` and `/dev/shm`. Bind recursion is disabled so nested
  host mounts cannot silently appear inside a selected root.
- Nested read masks and read-only write-deny mounts, with ancestor mount pins to
  prevent renaming `.git` around its protected hooks/config. Compilation refuses
  missing or symlinked nested deny topology, roots under denied ancestors, runtime
  overlaps, and ambiguous Docker mount syntax. No credential paths are created.
  Mount inode identities are checked before launch and helper calls; a changed
  topology stops execution and requires recompilation.
  Masks are empty and read-only, as on bwrap, so ordinary recursive searches can
  cross protected children without treating them as I/O failures. Direct helper
  access to a masked file/directory reports `SandboxDenied`; a shell read of a
  masked file can return empty bytes. Read masks remain effective inside a
  write-protected directory, and denied image paths are masked too.
- `--network none`, all capabilities dropped, no new privileges, read-only image,
  separate IPC/PID namespaces, and bounded memory/CPU/PIDs. A pinned Moby allowlist
  additionally denies `socket`, `socketcall`, and io_uring. Network isolation alone
  does not protect Unix sockets that happen to sit in a mounted workspace.
- Each Bash invocation has its own container. Explicit create/start/remove avoids
  a cancellation-before-create race. Timeout, abort, unexpected attach-client exit,
  and disposal force-remove owned containers and their volumes. Cleanup errors
  stop the backend. This replaces the proposed session-long `docker exec` shell
  design because per-invocation container removal can reap detached descendants.
- A persistent filesystem helper in a separate container under the same profile,
  using the existing framed protocol and read/write/search adapters. Its trusted
  code is copied to a private directory and mounted read-only. Both shell and
  helper enter through `env -i`, and host credentials are filtered again.
- Host UID/GID execution and an explicit daemon socket. The Docker CLI runs with
  private empty configuration and a minimal environment, so ambient contexts,
  proxy configuration, credential helpers and `DOCKER_HOST` do not select authority.

The Docker contracts follow the official [run reference](https://docs.docker.com/engine/containers/run/),
[bind-mount reference](https://docs.docker.com/engine/storage/bind-mounts/), and
[seccomp documentation](https://docs.docker.com/engine/security/seccomp/).
The vendored Moby policy records its exact provenance and license alongside it.

## Podman adapter

`PodmanBackend` shares the mount compiler, syscall policy, container lifecycle and
filesystem helper with `DockerBackend`. Linux uses the native rootless CLI with
`--remote=false`, explicit keep-id UID/GID mapping, and delegated cgroup v2
CPU/memory/PID controllers. It requires seccomp and refuses rootful engines.

The adapter replaces ambient containers.conf, default mounts and hooks, clears
connection-selection variables and keeps engine configuration/storage outside
all exposed host roots. Podman bind mounts use `bind-nonrecursive`. Extra writable
`/run` and `/var/tmp` mounts are disabled with `--read-only-tmpfs=false`; only the
reported `/tmp` and `/dev/shm` remain writable temporary directories. Cancellation
uses `rm --force --time 0`: Podman's ordinary force-remove grace period allowed a
detached child to keep running in the initial real-engine test.

macOS uses an explicitly named, running rootless Podman machine through its SSH
command transport. Paths must be canonical and inside the shared home. Fresh
host/VM canaries and file hashes check every bind source before launch; a missing
or different share refuses execution. Its private configuration/helper lives
under the shared home, outside the exposed roots. Machine names and shell
arguments are validated/quoted. This path remains pending real Mac qualification.

See Podman's [run reference](https://docs.podman.io/en/stable/markdown/podman-run.1.html),
[removal semantics](https://docs.podman.io/en/stable/markdown/podman-rm.1.html), and
[machine SSH transport](https://docs.podman.io/en/stable/markdown/podman-machine-ssh.1.html).

## Validation

`npm run test:unit` includes mount authority, immutability, retargeting, unsupported
topology and seccomp regressions. The shared Docker/Podman engine tests exercise normal
workspace operations, nested masks, protected metadata and ancestor renames,
symlinks, recursive search, a live mounted Unix socket with an unsandboxed positive
control, TCP/DNS, image and host environment isolation, UID ownership, zero
capabilities, helper behavior, timeout and cancellation with a `setsid` descendant.

To run them on a non-root Linux host with a local rootful Docker daemon:

```sh
# Explicitly build this reviewed test fixture, not an arbitrary project image.
docker build -f docker/Dockerfile.conformance --iidfile /tmp/pi-enclave-image-id docker
PI_ENCLAVE_DOCKER_IMAGE="$(cat /tmp/pi-enclave-image-id)" npm run test:docker
```

The image's base is digest-pinned; package installation happens only in this
explicit fixture build. Execution uses the resulting immutable image ID. Without
`PI_ENCLAVE_DOCKER_IMAGE`, daemon tests are skipped. With it, missing Docker or
unsupported daemon settings fail the tests. CI builds and runs the fixture on
Linux. The development host currently has no Docker CLI/daemon, so local daemon
results must not be inferred from unit-test success.

The rootless Linux run on 2026-09-05 used Podman 4.9.3: all 12 shared
boundary tests passed, including immediate timeout/abort cleanup and observed
cgroup limits. Docker passed the same 12 tests. The unit suite passed 1,000 tests
and the policy suite passed 25. See [CI evidence](https://github.com/frycm/pi-enclave/actions/runs/33958997857).
These results do not qualify Podman 5.7 on the development host or a macOS VM;
both still need their own local run after installation.

## Remaining Phase 4a gates

1. Integrate trusted user-global backend/image selection, probe/status reporting,
   extension startup, and standalone approval; no project-controlled image or
   automatic fallback before qualification.
2. Add invocation-bound read/write capability containers and helper leases with
   cancellation, revocation, concurrent sibling isolation and cleanup evidence.
   The current backend refuses every capability request.
3. Complete the shared native/Docker conformance contract. The current Docker
   suite covers supported topology separately; it does not claim that F10/F13/F14
   (missing or retargeted nested deny paths) execute successfully. Those layouts
   refuse compilation instead of receiving a weaker boundary.
4. Qualify macOS Podman machine execution, Docker Desktop and Windows path semantics.
   Docker still refuses non-Linux hosts and remapped daemons. Podman has a separate
   rootless adapter and Linux CI entry point; its Mac machine path is not yet qualified.
5. Measure helper startup, large-output/cancellation behavior and crash recovery
   when the parent itself is killed. `--rm`/a reaper or another durable ownership
   mechanism is required before unattended production use; normal disposal is
   not evidence for abrupt parent-death cleanup.

Only after these gates should a trusted user-selected Docker/Podman fallback
become part of backend selection. Phase 4b then introduces authenticated, invocation-bound egress with
connection-time validation, DNS/redirect defenses and revocation of live tunnels.
