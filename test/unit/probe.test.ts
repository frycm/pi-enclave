import { describe, expect, it } from "vitest";
import {
	backendForPlatform,
	compareVersions,
	formatProbeReport,
	isVersionAtLeast,
	isVersionInRange,
	NODE_RANGE_MIN,
	PI_RANGE_MAX,
	PI_RANGE_MIN,
	type ProbeEnv,
	parseVersion,
	probe,
	USERNS_SYSCTL_PATH,
} from "../../src/probe.ts";

/**
 * A host where everything is fine. Each test overrides exactly the one thing it
 * is about, so a failure names its own cause.
 */
function healthyEnv(overrides: Partial<ProbeEnv> = {}): ProbeEnv {
	return {
		platform: "darwin",
		nodeVersion: "22.10.0",
		piVersion: PI_RANGE_MIN,
		which: () => "/usr/bin/stub",
		readText: () => null,
		...overrides,
	};
}

const byId = (env: ProbeEnv, id: string) => probe(env).checks.find((c) => c.id === id);

describe("version parsing", () => {
	it("parses plain and v-prefixed versions", () => {
		expect(parseVersion("0.84.2")?.core).toEqual([0, 84, 2]);
		expect(parseVersion("v22.10.0")?.core).toEqual([22, 10, 0]);
	});

	it("captures prerelease and ignores build metadata", () => {
		expect(parseVersion("0.85.0-rc.1")?.prerelease).toBe("rc.1");
		expect(parseVersion("1.2.3+build.5")?.prerelease).toBeNull();
	});

	it("rejects unparseable input rather than guessing", () => {
		for (const bad of ["", "1.2", "next", "0.84.x", "1.2.3.4"]) {
			expect(parseVersion(bad), bad).toBeNull();
		}
	});

	it("orders by core version, then places a prerelease before its release", () => {
		const v = (s: string) => {
			const parsed = parseVersion(s);
			if (!parsed) throw new Error(`unparseable test fixture: ${s}`);
			return parsed;
		};
		expect(compareVersions(v("0.84.2"), v("0.84.10"))).toBeLessThan(0);
		expect(compareVersions(v("0.85.0"), v("0.84.99"))).toBeGreaterThan(0);
		expect(compareVersions(v("1.0.0-rc.1"), v("1.0.0"))).toBeLessThan(0);
		expect(compareVersions(v("0.84.2"), v("0.84.2"))).toBe(0);
	});
});

describe("range checks", () => {
	it("includes the lower bound and excludes the upper", () => {
		expect(isVersionInRange("0.84.2", PI_RANGE_MIN, PI_RANGE_MAX)).toBe(true);
		expect(isVersionInRange("0.84.99", PI_RANGE_MIN, PI_RANGE_MAX)).toBe(true);
		expect(isVersionInRange("0.84.1", PI_RANGE_MIN, PI_RANGE_MAX)).toBe(false);
		expect(isVersionInRange("0.85.0", PI_RANGE_MIN, PI_RANGE_MAX)).toBe(false);
	});

	it("refuses a prerelease of the next minor", () => {
		// Semver puts 0.85.0-rc.1 below 0.85.0, but the bound exists because an
		// unseen minor may change hook semantics, and an rc is exactly that.
		expect(isVersionInRange("0.85.0-rc.1", PI_RANGE_MIN, PI_RANGE_MAX)).toBe(false);
		expect(isVersionInRange("0.85.0-0", PI_RANGE_MIN, PI_RANGE_MAX)).toBe(false);
	});

	it("still admits a prerelease inside the range", () => {
		// Prereleases of a patch we already support carry no unseen minor.
		expect(isVersionInRange("0.84.3-rc.1", PI_RANGE_MIN, PI_RANGE_MAX)).toBe(true);
	});

	it("never admits an unparseable version", () => {
		expect(isVersionInRange("garbage", PI_RANGE_MIN, PI_RANGE_MAX)).toBe(false);
		expect(isVersionAtLeast("garbage", NODE_RANGE_MIN)).toBe(false);
	});
});

describe("probe: pi version gate", () => {
	it("accepts a pi inside the range", () => {
		expect(probe(healthyEnv()).ok).toBe(true);
		expect(byId(healthyEnv(), "pi-version")?.status).toBe("ok");
	});

	it("fails closed on an older pi", () => {
		const check = byId(healthyEnv({ piVersion: "0.84.1" }), "pi-version");
		expect(check?.status).toBe("fail");
		expect(check?.detail).toContain("0.84.1");
	});

	it("fails closed on a NEWER pi, not just an older one", () => {
		// The whole point of a two-sided bound: an unseen minor may change hook
		// semantics, and "probably fine" is not a sandbox guarantee.
		expect(byId(healthyEnv({ piVersion: "0.85.0" }), "pi-version")?.status).toBe("fail");
		expect(byId(healthyEnv({ piVersion: "1.0.0" }), "pi-version")?.status).toBe("fail");
	});

	it("fails closed when the pi version is unknown", () => {
		const report = probe(healthyEnv({ piVersion: null }));
		expect(report.ok).toBe(false);
		expect(byId(healthyEnv({ piVersion: null }), "pi-version")?.remediation).toBeDefined();
	});
});

describe("probe: platform and backend selection", () => {
	it("maps platforms to backends", () => {
		expect(backendForPlatform("darwin")).toBe("seatbelt");
		expect(backendForPlatform("linux")).toBe("bwrap");
		expect(backendForPlatform("win32")).toBeNull();
	});

	it("refuses an unsupported platform and reports no backend", () => {
		const report = probe(healthyEnv({ platform: "win32" }));
		expect(report.ok).toBe(false);
		expect(report.backend).toBeNull();
		expect(report.checks.find((c) => c.id === "platform")?.status).toBe("fail");
	});

	it("skips backend checks entirely when the platform is unsupported", () => {
		const report = probe(healthyEnv({ platform: "win32", which: () => null }));
		expect(report.checks.map((c) => c.id)).not.toContain("backend-binaries");
	});
});

describe("probe: backend prerequisites", () => {
	it("requires sandbox-exec on macOS", () => {
		const env = healthyEnv({ platform: "darwin", which: (b) => (b === "/usr/bin/sandbox-exec" ? null : "/x") });
		const check = byId(env, "backend-binaries");
		expect(check?.status).toBe("fail");
		expect(check?.detail).toContain("sandbox-exec");
	});

	it("requires bwrap and socat on Linux, and names every missing one", () => {
		const env = healthyEnv({ platform: "linux", which: () => null });
		const check = byId(env, "backend-binaries");
		expect(check?.status).toBe("fail");
		expect(check?.detail).toContain("bwrap");
		expect(check?.detail).toContain("socat");
		expect(check?.remediation).toContain("bubblewrap");
	});

	it("warns rather than fails when only the search tools are missing", () => {
		// rg/fd degrade find and grep; they do not weaken the sandbox boundary.
		const env = healthyEnv({ platform: "linux", which: (b) => (b === "rg" || b === "fd" ? null : "/x") });
		const report = probe(env);
		expect(report.ok).toBe(true);
		expect(byId(env, "search-binaries")?.status).toBe("warn");
	});
});

describe("probe: Linux user namespaces", () => {
	const linux = (sysctl: string | null) =>
		healthyEnv({
			platform: "linux",
			readText: (p) => (p === USERNS_SYSCTL_PATH ? sysctl : null),
		});

	it("passes when the AppArmor restriction is off", () => {
		const report = probe(linux("0\n"));
		expect(report.ok).toBe(true);
		expect(byId(linux("0\n"), "linux-userns")?.status).toBe("ok");
	});

	it("fails closed when the restriction is on, with the sysctl remediation", () => {
		// This is the ubuntu-latest (24.04) default and the exact failure the
		// step-0 spike hit: unshare succeeds but the namespace has no capabilities.
		const report = probe(linux("1\n"));
		expect(report.ok).toBe(false);
		const check = byId(linux("1\n"), "linux-userns");
		expect(check?.status).toBe("fail");
		expect(check?.remediation).toContain("kernel.apparmor_restrict_unprivileged_userns=0");
	});

	it("omits the check on kernels without the sysctl", () => {
		expect(probe(linux(null)).checks.map((c) => c.id)).not.toContain("linux-userns");
		expect(probe(linux(null)).ok).toBe(true);
	});

	it("never runs the Linux check on macOS, even if the path somehow reads", () => {
		const env = healthyEnv({ platform: "darwin", readText: () => "1" });
		expect(probe(env).checks.map((c) => c.id)).not.toContain("linux-userns");
		expect(probe(env).ok).toBe(true);
	});
});

describe("probe: Node version", () => {
	it("rejects Node below the sandbox-runtime minimum", () => {
		const report = probe(healthyEnv({ nodeVersion: "18.20.0" }));
		expect(report.ok).toBe(false);
		expect(byId(healthyEnv({ nodeVersion: "18.20.0" }), "node-version")?.status).toBe("fail");
	});

	it("accepts the exact minimum", () => {
		expect(byId(healthyEnv({ nodeVersion: NODE_RANGE_MIN }), "node-version")?.status).toBe("ok");
	});
});

describe("probe: report aggregation", () => {
	it("is ok only when no check failed; warnings do not block", () => {
		const warnOnly = healthyEnv({ which: (b) => (b === "rg" ? null : "/x") });
		const report = probe(warnOnly);
		expect(report.checks.some((c) => c.status === "warn")).toBe(true);
		expect(report.ok).toBe(true);
	});

	it("reports every failure, not just the first", () => {
		const report = probe(healthyEnv({ piVersion: "0.1.0", nodeVersion: "18.0.0", platform: "win32" }));
		const failed = report.checks.filter((c) => c.status === "fail").map((c) => c.id);
		expect(failed).toEqual(expect.arrayContaining(["pi-version", "node-version", "platform"]));
	});

	it("gives every non-ok check a remediation the user can act on", () => {
		const report = probe(healthyEnv({ piVersion: "0.1.0", platform: "linux", which: () => null }));
		for (const check of report.checks) {
			if (check.status !== "ok") expect(check.remediation, check.id).toBeTruthy();
		}
	});
});

describe("formatProbeReport", () => {
	it("leads with the verdict and includes remediations", () => {
		const text = formatProbeReport(probe(healthyEnv({ piVersion: "0.1.0" })));
		expect(text).toContain("REFUSING TO START");
		expect(text).toContain("->");
	});

	it("says ready on a healthy host", () => {
		expect(formatProbeReport(probe(healthyEnv()))).toContain("ready");
	});
});
