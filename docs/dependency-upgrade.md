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
