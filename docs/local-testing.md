# Local testing with Podman

Podman support is an experimental Phase 4a backend. The extension and CLI still
select native sandbox-runtime; installing Podman does not activate a production
fallback. Container tests have their own entry point, `npm run test:podman`.
Docker Engine, Docker Desktop, `podman-docker`, Compose and an API socket service
are not needed by this adapter.

## Ubuntu

On the development host (Ubuntu 26.04, user `agents`):

```sh
sudo apt update
sudo apt install podman uidmap passt slirp4netns fuse-overlayfs fd-find ripgrep
# Debian/Ubuntu calls the executable fdfind. A shell alias is insufficient.
# Skip this command if a working fd already exists at this location.
sudo ln -s /usr/bin/fdfind /usr/local/bin/fd

# Run as your normal user, without sudo.
podman info
fd --version
rg --version
```

The repository currently offers Podman 5.7.0 on this host. Podman is available
through Ubuntu's normal repositories; see the [official installation guide](https://podman.io/docs/installation).
`passt`/`slirp4netns` support ordinary rootless image builds; enclave execution
itself uses `--network none` and a syscall filter denying socket creation.

The `agents` account already has 65,536 subordinate UIDs/GIDs in `/etc/subuid`
and `/etc/subgid`, an active `/run/user/1001` and a user D-Bus session. Those do
not need new configuration on this host. No Docker group is required.

On another Linux machine, use a normal login session with subordinate UID/GID
ranges and delegated cgroup v2 CPU, memory and PID controllers. If `podman info`
or the tests fail, keep the complete error. Do not add `sudo`, `--privileged`,
disable seccomp or remove resource limits to make the test pass. The backend
deliberately refuses an unsupported rootless setup. Podman's [rootless documentation](https://docs.podman.io/en/stable/markdown/podman.1.html#rootless-mode)
explains the host prerequisites.

Node.js 22.19 or newer is also needed. Node 24 is already installed on this host.

## macOS

Use your existing Podman installation. For a new installation, Podman recommends
its [official installer](https://podman.io/docs/installation#macos); Homebrew also
provides `brew install podman`. Install the native search tools:

```sh
brew install fd ripgrep
podman machine list
```

Start your existing rootless machine if it is stopped:

```sh
podman machine start podman-machine-default
podman info
```

If there is no machine, create one. This downloads a Linux VM image:

```sh
podman machine init --cpus 2 --memory 4096 --rootful=false --volume "$HOME:$HOME" podman-machine-default
podman machine start podman-machine-default
podman info
```

The explicit home share keeps identical absolute paths on both sides. Keep the
checkout and explicit read roots inside your home directory. Do not recreate or
reset an existing machine just to follow this example. A machine with a different
name can be selected with `PI_ENCLAVE_PODMAN_MACHINE` in the test command below.

The adapter uses `podman machine ssh <name>` to run the native rootless engine
inside that VM. This lets it supply the same controlled Podman configuration and
seccomp file as on Linux, rather than relying on remote API defaults. Before
compilation and each launch, it checks that the VM sees the same bind sources.
The checks briefly create random canary files on the host, including in explicit
read roots and nested bind directories, and remove them afterward. Those
directories must allow this host-side write in this experimental slice.

macOS machine execution still needs a real Mac qualification run. The native
macOS CI job does not prove Podman VM behavior, and GitHub-hosted macOS runners
[do not support nested virtualization](https://docs.github.com/en/actions/reference/runners/github-hosted-runners).

## Build and run the container tests

From the pi-enclave checkout, build the repository's reviewed conformance fixture
explicitly. This build downloads a base image and Debian packages; the sandbox
runtime itself never builds a project's Dockerfile or pulls an image.

```sh
npm ci
podman build -f docker/Dockerfile.conformance --iidfile /tmp/pi-enclave-podman-image-id docker
PI_ENCLAVE_PODMAN_IMAGE="$(cat /tmp/pi-enclave-podman-image-id)" \
  PI_ENCLAVE_PODMAN_BINARY="$(command -v podman)" \
  npm run test:podman
```

For a differently named Mac machine, select its rootless connection for the build
(`podman --connection <rootless-connection-name> build ...`) and add
`PI_ENCLAVE_PODMAN_MACHINE=<machine-name>` to the test environment. Builds and
tests must use the same rootless image store. The adapter uses Podman's normal
storage location; ambient `CONTAINER_HOST`, `PODMAN_USERNS`, `CONTAINERS_CONF` and
custom XDG locations are deliberately ignored.

All 12 boundary tests must pass. They cover file ownership, host-write and secret
denials, symlinks, protected metadata, TCP/DNS/Unix sockets, image/host environment
isolation, capabilities, kernel resource limits, filesystem helpers, timeout and
abort cleanup. Supplying the image makes missing prerequisites a failure. Omitting
it skips the opt-in suite and is not qualification evidence. On macOS the host
Unix listener is across a VM boundary; the suite additionally checks socket()
denial directly, so VM socket forwarding is not mistaken for seccomp evidence.

## Reviewer and native bwrap tests

Ollama is **not needed for Podman tests**. The currently implemented local reviewer
adapter uses Ollama's model identity and context APIs; the existing Unsloth Studio
service is not yet supported by that qualification path.

If you want to run live reviewer qualification now, install Ollama using its
[Linux instructions](https://docs.ollama.com/linux) or
[macOS application](https://docs.ollama.com/macos). On Linux:

```sh
curl -fsSL https://ollama.com/install.sh | sh
sudo systemctl enable --now ollama
```

After the service or Mac application is running:

```sh
ollama pull qwen3:8b
ollama list
```

`qwen3:8b` is a candidate for testing, not an approved reviewer. The exact model
must pass enclave's qualification corpus before it can make named-reviewer
decisions. There is no need to remove Unsloth or run both model servers at once.

Native bwrap testing is separate. This Ubuntu 26.04 host's shipped AppArmor
`bwrap-userns-restrict` profile restricts capabilities in nested namespaces,
blocking sandbox-runtime's `apply-seccomp` helper. Leave host policy unchanged;
Podman testing does not require fixing the native bwrap path. The failure matches
[sandbox-runtime issue 429](https://github.com/anthropics/sandbox-runtime/issues/429).
