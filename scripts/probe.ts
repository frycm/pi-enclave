/**
 * Standalone probe runner. Used by CI to fail early and legibly when a host
 * cannot support the sandbox, instead of letting the conformance suite report
 * it as N red rows with no common explanation.
 *
 * Exits non-zero when the probe refuses.
 */
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { formatProbeReport } from "../src/probe.ts";
import { probeHost } from "../src/probe-host.ts";
import { sanitizeVerificationPath } from "./test-path.ts";

sanitizeVerificationPath();

/**
 * Read pi's version from its package.json rather than importing the package:
 * importing pulls in the whole agent, which is far more than a probe needs and
 * would fail for reasons unrelated to the version.
 *
 * pi's `exports` map does not expose `./package.json` (and offers no `require`
 * condition), so neither `require("...package.json")` nor `require.resolve` can
 * reach it. Resolve the ESM entry point instead and walk up to the manifest.
 */
function resolvePiVersion(): string | null {
	try {
		const entry = fileURLToPath(import.meta.resolve("@earendil-works/pi-coding-agent"));
		for (let dir = dirname(entry), i = 0; i < 5; dir = dirname(dir), i++) {
			try {
				const pkg = JSON.parse(readFileSync(join(dir, "package.json"), "utf8")) as {
					name?: string;
					version?: string;
				};
				if (pkg.name === "@earendil-works/pi-coding-agent") return pkg.version ?? null;
			} catch {
				// Not this directory; keep walking up.
			}
		}
		return null;
	} catch {
		return null;
	}
}

const report = probeHost(resolvePiVersion());
console.log(formatProbeReport(report));
process.exit(report.ok ? 0 : 1);
