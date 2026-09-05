# Phase 4a: offline Docker

Status: first implementation slice, experimental test entry point. Production
extension and standalone approval still select the native backend. This is not
Phase 4 sign-off and does not enable network access or Docker fallback.

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

## Validation

`npm run test:unit` includes mount authority, immutability, retargeting, unsupported
topology and seccomp regressions. The Docker-specific daemon tests exercise normal
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
4. Qualify rootless/userns UID mapping, Docker Desktop and Windows path semantics.
   This first runner explicitly refuses non-Linux hosts and remapped daemons.
5. Measure helper startup, large-output/cancellation behavior and crash recovery
   when the parent itself is killed. `--rm`/a reaper or another durable ownership
   mechanism is required before unattended production use; normal disposal is
   not evidence for abrupt parent-death cleanup.

Only after these gates should native → Docker → refuse become the selection
order. Phase 4b then introduces authenticated, invocation-bound egress with
connection-time validation, DNS/redirect defenses and revocation of live tunnels.
