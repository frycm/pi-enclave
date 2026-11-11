# Pi 1.5 and dependency upgrade — November 11, 2026

Target: stable upstream [v1.5.2](https://github.com/earendil-works/pi/releases/tag/v1.5.2),
commit `b4afdddf44e059c67ccf5097e5317d913521b470`, released November 10.
The previous baseline was v1.1.0 at `abe508e1b89912adde45528136c3221eb69acdd7`;
there are 928 intervening commits. The sibling `frycm/pi` checkout and GitHub
fork were fast-forwarded to this exact tag, with no custom patches.

## Dependencies

Every direct dependency was checked against the npm registry. Versions remain
exactly pinned; the peer and startup-probe range is `>=1.5.2 <1.6.0`.

| Package | Previous | Current |
|---|---|---|
| @earendil-works/pi-coding-agent | 1.1.0 | 1.5.2 |
| @earendil-works/pi-ai | 1.1.0 | 1.5.2 |
| @anthropic-ai/sandbox-runtime | 0.0.79 | 0.0.82 |
| @biomejs/biome | 2.5.15 | 2.6.6 |
| vitest | 5.0.3 | 5.1.0 |
| @types/node | 22.20.5 | 22.20.5 (latest Node 22 types) |
| tsx | 4.23.15 | 4.23.15 (already latest) |
| typescript | 7.0.2 | 7.0.2 (already latest) |
| fast-check | 4.10.2 | 4.10.2 (already latest) |

Node remains `>=22.19.0`, matching pi's supported runtime. Node types follow
that runtime rather than exposing Node 26-only APIs to code intended for Node 22.
The lockfile also refreshes transitive dependencies within their declared
ranges. Installation and packaged-install verification disable lifecycle scripts.
Biome's configuration uses the new `preset: "recommended"` spelling, preserving
the recommended rule set.

## Integration changes

- `before_agent_start` now distinguishes user prompts from extension-generated
  custom messages. Only its user variant confirms pending direct-input provenance;
  a custom message cannot consume or become user authorization. The regression
  drives the production extension handlers through this interleaving.
- Pi's grep now obtains context from ripgrep JSON, roots directory globs at the
  search directory and disables ambient ripgrep configuration. Enclave performs
  all of those operations inside its existing sandboxed helper. No matched file
  is reopened to obtain context, and lone carriage returns and base64-encoded
  JSON payloads follow upstream behavior. Match-limit notices require an extra
  match and retain the final selected match's trailing context. The existing
  10,000-match safety ceiling, helper output cap and serialized search lifetime
  remain in force.
- Real-ripgrep parity fixtures compare the helper/formatter with the installed
  upstream tool for context overlap, exact and exceeded limits, directory globs,
  symlinked roots, single-file paths, non-UTF-8 content, long lines and byte
  truncation. The changed grep artifact is repinned after these checks; pi's
  image-detector artifact remains byte-identical.
- Pi's new optional streaming read operation is not installed by the enclave
  adapter. Pi continues to use the supplied sandboxed read operations; it does
  not fall back to a host stream. Existing invocation-binding and native denial
  tests exercise those actual pi wrappers.
- Nested tool interception, execute-time action binding and the isolated
  reviewer transport remain covered by the installed-session and local HTTP
  protocol tests. Reviewer transport identity increments to 4 so qualifications
  from the previous pi-ai adapter cannot survive the dependency change.

The sandbox-runtime artifacts were compared with 0.0.79 in the manager and native
wrappers. Relevant changes include symlink spellings and credential-denial
precedence on macOS, absent-denial mount handling and nested-namespace restrictions
on Linux, and initialization/cleanup changes. Enclave retains explicit write
roots, immutable credential/state denials, credential-filtered child environments,
no network grants and refusal of macOS Bash capability widening. New Windows,
filesystem-disable and proxy features are not exposed by enclave's configuration.

## Audit

Refreshing compatible transitive dependencies updates node-forge to 1.4.3 and
removes its previous audit findings. The remaining audit reports two high entries
for one underlying [Zod collection-validation advisory](https://github.com/advisories/GHSA-mrhx-c7xc-m3w5):
`zod@3.25.76` and its parent sandbox-runtime. Sandbox-runtime 0.0.82 requires
`zod ^3.25.0`; the advisory's patched line is 4.6.6. No cross-major override or
advisory suppression is applied. This dependency advisory is not a finding that
enclave exposes the vulnerable operation to an attacker.

## Validation

- `npm run check`: typecheck and recommended lint rules pass without diagnostics.
- Full native macOS suite: 1,080 tests pass; five platform/fixture cases skip.
- Native probe: ready against pi 1.5.2 and Seatbelt.
- Policy report: all 11 rows pass and every control fails as intended.
- Native conformance report: all 29 rows pass, including the Linux-only
  capability row's explicit macOS exemption.
- Empty-consumer tarball install: CLI help and extension import pass with pi 1.5.2.

Native Linux and macOS CI on the final commit remain required before merge.
No live reviewer
qualification or paid provider request is part of this dependency upgrade.
After upgrading, run reviewer qualification again for the deployed model and
rulebook. Phase 4a remains a separate dependent pull request.
