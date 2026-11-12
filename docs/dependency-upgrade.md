# Dependency risk — November 2026 (#38)

## Current production audit

`npm audit --omit=dev` on `@anthropic-ai/sandbox-runtime@0.0.82` reports two high-severity
entries for one advisory, and nothing else:

| Advisory | Package | Path | Fix available |
|---|---|---|---|
| [GHSA-mrhx-c7xc-m3w5](https://github.com/advisories/GHSA-mrhx-c7xc-m3w5), "Zod can exhaust memory while validating oversized constrained collections" (`zod <4.6.6`) | `zod@3.25.76` | `@anthropic-ai/sandbox-runtime` declares `zod: ^3.25.0` and imports it in its configuration schema | No |

The `node-forge` advisory recorded in the October upgrade below no longer appears in the
production audit.

## Reachability: not reachable

An availability issue in Zod needs a Zod parse of attacker-sized data. In SRT 0.0.82 only two
modules import Zod, and neither is on pi-enclave's path:

| Module that imports Zod | Parse sites | Started by | Used by pi-enclave |
|---|---|---|---|
| `dist/sandbox/sandbox-config.js` | none; defines the schemas | re-exported by the package index; parsed by `dist/utils/config-loader.js` (`SandboxRuntimeConfigSchema.safeParse`), which only the `srt` CLI calls to read a settings file | No |
| `dist/sandbox/decider-client.js` | `helloSchema` and per-message schemas | `dist/sandbox/proxy-only.js`, started only by `srt-proxy` | No |

pi-enclave imports `SandboxManager` and `getDefaultWritePaths` (`src/backend/srt.ts`) and
resolves the package root for the seccomp helper (`src/probe-host.ts`). The transitive import
closure of `dist/sandbox/sandbox-manager.js` (41 modules) contains none of
`sandbox-config.js`, `config-loader.js` or `decider-client.js` and no `zod` import, so
`SandboxManager.initialize` and `updateConfig` take the object from `toSrtConfig` without
schema validation. Importing the package index loads the schema module as a side effect, but
nothing parses with it. The other `zod` copies in the tree belong to pi's own dependencies
(`@anthropic-ai/sdk`, `openai` under `@earendil-works/pi-ai`), whose Zod helpers pi-enclave
does not call; the reviewer talks to Ollama with plain `fetch`.

Should a later SRT start validating in the manager, the inputs are still bounded:

- The arrays pi-enclave passes (`denyRead`, `allowWrite`, `denyWrite`) come from the folded
  profile. Every configuration file is refused above 1 MiB before it is opened
  (`MAX_CONFIG_BYTES`, `src/config/sources.ts`), and project files are read only in a trusted
  project.
- Model-supplied data adds at most one path per call, as a read or write capability. No
  model-controlled array reaches SRT.
- In SRT's schema the only collection with a size constraint is the MITM `domains` array
  (`.min(1)`), which pi-enclave never sets.

## Mitigation and upgrade condition

- **No `overrides` entry for Zod.** It would change a module the sandbox backend loads to
  silence a path that never runs, and SRT is pinned to an exact version on purpose. Whether
  the `zod/v3` subpath inside Zod 4.6.6 carries the fix was not checked, so an override is not
  known to fix anything either.
- **Guard.** `test/unit/upstream-drift.test.ts` fails if the manager's import closure reaches
  a Zod module, or if pi-enclave imports anything from SRT beyond `SandboxManager` and
  `getDefaultWritePaths`. Either change reopens this assessment.
- **Upgrade condition.** Move to the first SRT release whose dependency range admits a fixed
  Zod, then re-run unit, policy and native conformance on Linux and macOS and the production
  audit.

Residual risk: none on the current call path. The advisory remains in the audit output until
SRT publishes a release with a fixed Zod.

---

# Dependency upgrade — October 8, 2026

This accompanies the pi 1.1 migration in PR #9. All seven outdated direct
dependencies identified in the registry check are now pinned to the agreed versions:

| Package | Previous | Updated |
|---|---|---|
| @anthropic-ai/sandbox-runtime | 0.0.73 | 0.0.79 |
| tsx | 4.19.2 | 4.23.15 |
| @biomejs/biome | 2.3.11 | 2.5.15 |
| @types/node | 22.10.2 | 22.20.5 |
| fast-check | 3.23.2 | 4.10.2 |
| typescript | 5.7.2 | 7.0.2 |
| vitest | 2.1.8 | 5.0.3 |

Node types remain on the Node 22 line, matching the project's minimum runtime.
Both pi packages remain at the latest stable 1.1.0. The Node minimum remains
22.19.0. The lockfile was regenerated from a clean dependency tree so Vitest 5
receives a compatible Vite peer and obsolete vulnerable testing packages disappear.

## Compatibility

TypeScript 7 and fast-check 4 required no compiler configuration or property-test
changes. Vitest 5 runs the existing isolated suites and their mocks with the
existing configuration. Biome's schema was updated and four test files were
reformatted; three equivalent optional-chain guards satisfy its newer lint rules.
The approval tests now use a real temporary home: resolving their synthetic
`/home/u` denial roots during PATH filtering hit macOS automounts and exceeded
Vitest 5's test deadline. The fake-backend tests retain their approval and
environment assertions, without changing production behavior or increasing timeouts.

The published sandbox-runtime 0.0.73 and 0.0.79 artifacts were compared in the
manager, configuration, Linux/macOS wrappers, and seccomp discovery. The manager
API used by enclave remains compatible. Relevant changes include explicit literal
filesystem entries, glob resolution and deny handling, violation attribution,
asynchronous seccomp helper discovery, and optional resolved-address restrictions.
Existing enclave configuration continues to use the supported string entries.
Enclave retains its own credential denials, symlink target resolution, writable
mount pins, child environment filtering, and deny-all network configuration.
SRT now injects Java proxy options and can compose them with the parent's
`JAVA_TOOL_OPTIONS` inside its launch argv, independently of enclave's child
environment. Enclave denies that inherited value through SRT's credential-env
configuration and refuses explicit passthrough of the variable. The native
environment-leak fixture now plants a Java-options sentinel alongside the other
host credentials. Library-generated proxy options may remain, without the host
value. No credential injection or optional resolved-address policy is enabled.
Native Linux/macOS conformance is required on the PR before merge.

## Validation and remaining advisory

- Typecheck and lint: passed, without warnings.
- Unit and policy suites: 1,007 passed (982 unit, 25 policy), including the Java-options regressions.
- Local conformance: 11 passed, 47 skipped because this host lacks sandbox prerequisites.
- Clean packaged installation with pi 1.1.0: CLI help and extension import passed.
- Native CI results are recorded on the PR for its final commit.

The registry audit drops from ten affected package entries (including two critical)
to two high entries, representing one unresolved
[node-forge signature verification advisory](https://github.com/advisories/GHSA-86w9-cpqp-85rv).
Both entries are `node-forge@1.4.0` and its parent sandbox-runtime. The latest
node-forge remains affected; no patched published version was available at the
time of this upgrade. This is also the remaining production audit result.
Reachability of the vulnerable verification operation in enclave was not established.
No sandbox downgrade, advisory suppression, or unreviewed override was applied.

The previous Vitest, tinypool, Vite, esbuild and source-map-js findings are absent
from the regenerated lockfile's audit. Recheck advisories as upstream publishes fixes.
