/**
 * Startup gate. `probe()` decides whether pi-enclave may run at all.
 *
 * The rule is fail-closed in both directions: an unsupported pi, a missing
 * backend binary, or a kernel that will not give bubblewrap a capability-bearing
 * user namespace all produce `ok: false`, and auto mode refuses to start. A
 * "probably fine" is not a sandbox guarantee -- see the API baseline in README.md.
 *
 * Every check is pure with respect to an injected {@link ProbeEnv}, so the unit
 * tests exercise the real decision logic rather than a mock of it.
 */

/** Inclusive lower bound of the supported pi range. */
export const PI_RANGE_MIN = "0.85.0";
/** Exclusive upper bound. A new minor may change hook semantics the conformance suite has not seen. */
export const PI_RANGE_MAX = "0.86.0";

/** Minimum Node for the pinned pi release (also satisfies sandbox-runtime). */
export const NODE_RANGE_MIN = "22.19.0";

export type CheckStatus = "ok" | "warn" | "fail";

export interface ProbeCheck {
	/** Stable identifier, safe to assert on in tests and to reference in docs. */
	id: string;
	title: string;
	status: CheckStatus;
	/** What was observed. Always populated, including on success. */
	detail: string;
	/** Present whenever `status` is not "ok" and the user can do something about it. */
	remediation?: string;
}

export type BackendName = "seatbelt" | "bwrap" | "docker" | "podman";

export interface ProbeReport {
	/** False if any check failed. Auto mode must refuse to start. */
	ok: boolean;
	platform: string;
	/** The backend that would be used, or null when the platform is unsupported. */
	backend: BackendName | null;
	piVersion: string | null;
	checks: ProbeCheck[];
}

/**
 * Everything `probe()` touches in the outside world. Injected so the decision
 * logic can be tested against every platform and failure mode from any host.
 */
export interface ProbeEnv {
	platform: string;
	nodeVersion: string;
	/** The pi version, or null if it could not be determined. */
	piVersion: string | null;
	/** Resolve an executable on PATH; null when absent. */
	which: (bin: string) => string | null;
	/** Read a file as text; null when it does not exist or cannot be read. */
	readText: (path: string) => string | null;
	/** Host PATH must not let repository-writable entries shadow SRT helpers. */
	pathSafety?: () => { ok: boolean; detail: string };
	/**
	 * Linux only: can this host actually give bubblewrap and the seccomp layer
	 * the capability-bearing namespaces they need?
	 *
	 * Functional rather than inferred. The sysctl below is one cause of failure
	 * but not the only one -- inside a container the sysctl is absent and plain
	 * `bwrap` succeeds, yet the nested user namespace `apply-seccomp` needs
	 * cannot be created. Both heuristics pass there while the sandbox does not
	 * work at all, which is the worst possible outcome for a startup gate.
	 *
	 * Returns null when the check could not be run (no bwrap, not Linux).
	 */
	canNestNamespaces?: () => { ok: boolean; detail: string } | null;
}

// ---------------------------------------------------------------------------
// Version comparison
//
// A dependency-free comparator for the `x.y.z[-prerelease]` versions we care
// about. Semver orders a prerelease before its release, which puts
// `0.86.0-rc.1` *inside* a `< 0.86.0` bound -- the opposite of what the bound
// means here. The upper bound exists because an unseen minor may change hook
// semantics, and an 0.86 release candidate contains exactly those unseen
// changes. So the range check compares the exclusive upper bound on the core
// version alone, ignoring prerelease ordering in that direction.
// ---------------------------------------------------------------------------

interface ParsedVersion {
	core: [number, number, number];
	prerelease: string | null;
}

export function parseVersion(raw: string): ParsedVersion | null {
	const match = /^v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$/.exec(raw.trim());
	if (!match) return null;
	const [, major, minor, patch, prerelease] = match;
	return {
		core: [Number(major), Number(minor), Number(patch)],
		prerelease: prerelease ?? null,
	};
}

/** Returns <0, 0 or >0. Unparseable input is the caller's problem -- parse first. */
export function compareVersions(a: ParsedVersion, b: ParsedVersion): number {
	for (let i = 0; i < 3; i++) {
		const diff = (a.core[i] ?? 0) - (b.core[i] ?? 0);
		if (diff !== 0) return diff;
	}
	if (a.prerelease === b.prerelease) return 0;
	// A prerelease precedes its own release: 1.0.0-rc < 1.0.0.
	if (a.prerelease === null) return 1;
	if (b.prerelease === null) return -1;
	return a.prerelease < b.prerelease ? -1 : 1;
}

/**
 * True when `min <= raw < max`. Unparseable versions are never in range.
 *
 * The upper bound is applied to the core version only: every build of `max`,
 * prerelease or not, is outside the range.
 */
export function isVersionInRange(raw: string, min: string, max: string): boolean {
	const version = parseVersion(raw);
	const lower = parseVersion(min);
	const upper = parseVersion(max);
	if (!version || !lower || !upper) return false;
	const belowUpper =
		compareVersions({ core: version.core, prerelease: null }, { core: upper.core, prerelease: null }) < 0;
	return compareVersions(version, lower) >= 0 && belowUpper;
}

/** True when `raw >= min`. */
export function isVersionAtLeast(raw: string, min: string): boolean {
	const version = parseVersion(raw);
	const lower = parseVersion(min);
	if (!version || !lower) return false;
	return compareVersions(version, lower) >= 0;
}

// ---------------------------------------------------------------------------
// Individual checks
// ---------------------------------------------------------------------------

/**
 * Binaries each backend needs. `fd` and `rg` back the `find` and `grep` tools
 * inside the sandboxed helper; a missing one degrades those tools rather than
 * breaking the sandbox boundary, so they warn rather than fail.
 *
 * Note pi fetches `rg` and `fd` on demand into its own managed directory, so
 * "absent from PATH" does not mean "unavailable to pi". The helper cannot do
 * that fetch itself -- it runs with no network -- so step 7 resolves the
 * absolute path outside the sandbox and passes it in. Until then this check is
 * advisory.
 */
const BACKEND_BINARIES: Record<BackendName, { required: string[]; optional: string[] }> = {
	seatbelt: { required: ["/usr/bin/sandbox-exec"], optional: ["rg", "fd"] },
	bwrap: { required: ["bwrap", "socat"], optional: ["rg", "fd"] },
	docker: { required: ["docker"], optional: [] },
	podman: { required: ["podman"], optional: [] },
};

const INSTALL_HINT: Record<string, { darwin: string; linux: string }> = {
	bwrap: { darwin: "not available on macOS", linux: "apt-get install bubblewrap (Fedora: dnf install bubblewrap)" },
	socat: { darwin: "brew install socat", linux: "apt-get install socat" },
	rg: { darwin: "brew install ripgrep", linux: "apt-get install ripgrep" },
	fd: { darwin: "brew install fd", linux: "apt-get install fd-find" },
};

function installHint(bin: string, platform: string): string {
	const hint = INSTALL_HINT[bin];
	if (!hint) return `install ${bin}`;
	return platform === "darwin" ? hint.darwin : hint.linux;
}

export function backendForPlatform(platform: string): BackendName | null {
	if (platform === "darwin") return "seatbelt";
	if (platform === "linux") return "bwrap";
	return null;
}

function checkPlatform(env: ProbeEnv): ProbeCheck {
	const backend = backendForPlatform(env.platform);
	if (backend) {
		return {
			id: "platform",
			title: "Platform",
			status: "ok",
			detail: `${env.platform} -> ${backend} backend`,
		};
	}
	return {
		id: "platform",
		title: "Platform",
		status: "fail",
		detail: `${env.platform} has no OS-enforced backend in v1`,
		remediation: "macOS and Linux are supported. Windows arrives with the Docker backend in phase 4.",
	};
}

function checkHostPath(env: ProbeEnv): ProbeCheck | null {
	const result = env.pathSafety?.();
	if (!result) return null;
	if (result.ok) {
		return { id: "host-path", title: "Host executable PATH", status: "ok", detail: result.detail };
	}
	return {
		id: "host-path",
		title: "Host executable PATH",
		status: "fail",
		detail: result.detail,
		remediation: "Remove relative and workspace-writable entries from PATH before starting pi-enclave.",
	};
}

function checkPiVersion(env: ProbeEnv): ProbeCheck {
	if (env.piVersion === null) {
		return {
			id: "pi-version",
			title: "pi version",
			status: "fail",
			detail: "could not determine the running pi version",
			remediation: `pi-enclave supports pi >=${PI_RANGE_MIN} <${PI_RANGE_MAX}. Install a pi in that range.`,
		};
	}
	if (isVersionInRange(env.piVersion, PI_RANGE_MIN, PI_RANGE_MAX)) {
		return {
			id: "pi-version",
			title: "pi version",
			status: "ok",
			detail: `${env.piVersion} (supported: >=${PI_RANGE_MIN} <${PI_RANGE_MAX})`,
		};
	}
	// Deliberately fails on newer pi too: a new minor may change handler ordering
	// or tool operation interfaces in ways the conformance suite has not seen.
	return {
		id: "pi-version",
		title: "pi version",
		status: "fail",
		detail: `${env.piVersion} is outside >=${PI_RANGE_MIN} <${PI_RANGE_MAX}`,
		remediation: "Moving the baseline is one PR that re-runs the conformance suite against the new pi.",
	};
}

function checkNodeVersion(env: ProbeEnv): ProbeCheck {
	if (isVersionAtLeast(env.nodeVersion, NODE_RANGE_MIN)) {
		return {
			id: "node-version",
			title: "Node version",
			status: "ok",
			detail: `${env.nodeVersion} (minimum ${NODE_RANGE_MIN})`,
		};
	}
	return {
		id: "node-version",
		title: "Node version",
		status: "fail",
		detail: `${env.nodeVersion} is below the pinned pi minimum ${NODE_RANGE_MIN}`,
		remediation: `Upgrade Node to ${NODE_RANGE_MIN} or newer.`,
	};
}

function checkBinaries(env: ProbeEnv, backend: BackendName): ProbeCheck[] {
	const entry = BACKEND_BINARIES[backend];
	const checks: ProbeCheck[] = [];

	const missingRequired = entry.required.filter((bin) => env.which(bin) === null);
	checks.push(
		missingRequired.length === 0
			? {
					id: "backend-binaries",
					title: `${backend} prerequisites`,
					status: "ok",
					detail: entry.required.join(", "),
				}
			: {
					id: "backend-binaries",
					title: `${backend} prerequisites`,
					status: "fail",
					detail: `missing: ${missingRequired.join(", ")}`,
					remediation: missingRequired.map((bin) => installHint(bin, env.platform)).join("; "),
				},
	);

	const missingOptional = entry.optional.filter((bin) => env.which(bin) === null);
	if (missingOptional.length > 0) {
		checks.push({
			id: "search-binaries",
			title: "Search tools",
			status: "warn",
			detail: `not on PATH: ${missingOptional.join(", ")} -- find/grep need these inside the sandbox, which cannot fetch them`,
			remediation: missingOptional.map((bin) => installHint(bin, env.platform)).join("; "),
		});
	}

	return checks;
}

/** Path to the Ubuntu 24.04+ AppArmor restriction that strips capabilities from user namespaces. */
export const USERNS_SYSCTL_PATH = "/proc/sys/kernel/apparmor_restrict_unprivileged_userns";

/**
 * Ubuntu 24.04+ (and so GitHub Actions' `ubuntu-latest`) ships
 * `kernel.apparmor_restrict_unprivileged_userns=1`, which permits
 * `unshare(CLONE_NEWUSER)` but strips capabilities from the resulting namespace.
 * Both bubblewrap and sandbox-runtime's `apply-seccomp` need capability-bearing
 * user namespaces, so this surfaces as an obscure bwrap or uid_map error at the
 * first command. Detect it here and hand back the one-line fix instead.
 */
function checkLinuxUserns(env: ProbeEnv): ProbeCheck | null {
	const raw = env.readText(USERNS_SYSCTL_PATH);
	// Absent on kernels without the AppArmor restriction -- nothing to report.
	if (raw === null) return null;

	if (raw.trim() === "0") {
		return {
			id: "linux-userns",
			title: "User namespaces",
			status: "ok",
			detail: "apparmor_restrict_unprivileged_userns=0 -- capability-bearing namespaces available",
		};
	}
	return {
		id: "linux-userns",
		title: "User namespaces",
		status: "fail",
		detail:
			`apparmor_restrict_unprivileged_userns=${raw.trim()} strips capabilities from user namespaces; ` +
			"bubblewrap and the seccomp layer both need capability-bearing ones",
		remediation:
			"sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0  " +
			"(or add an AppArmor profile granting userns to bwrap)",
	};
}

/**
 * The functional namespace check.
 *
 * Runs the same chain sandbox-runtime does -- bubblewrap creating a
 * capability-dropped user namespace, then the seccomp helper creating a nested
 * one inside it. Anything that breaks that chain breaks every command, so it is
 * worth one subprocess at startup to say so in a sentence rather than let the
 * first tool call fail with a uid_map error.
 */
function checkNamespaceNesting(env: ProbeEnv): ProbeCheck | null {
	const result = env.canNestNamespaces?.();
	if (!result) return null;

	if (result.ok) {
		return {
			id: "linux-namespace-nesting",
			title: "Namespace nesting",
			status: "ok",
			detail: result.detail,
		};
	}
	return {
		id: "linux-namespace-nesting",
		title: "Namespace nesting",
		status: "fail",
		detail: result.detail,
		remediation:
			"bubblewrap and the seccomp layer both need capability-bearing user namespaces. " +
			"Inside a container this usually means the container itself is nested or unprivileged; " +
			"run pi-enclave on the host, or use a privileged container.",
	};
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

export function probe(env: ProbeEnv): ProbeReport {
	const checks: ProbeCheck[] = [checkPiVersion(env), checkNodeVersion(env), checkPlatform(env)];
	const backend = backendForPlatform(env.platform);

	if (backend) {
		const hostPath = checkHostPath(env);
		if (hostPath) checks.push(hostPath);
		checks.push(...checkBinaries(env, backend));
		if (env.platform === "linux") {
			const userns = checkLinuxUserns(env);
			if (userns) checks.push(userns);
			// Only worth running when the sysctl has not already explained the
			// failure, and only when the binaries it needs are present.
			const alreadyFailed = checks.some((check) => check.status === "fail");
			if (!alreadyFailed) {
				const nesting = checkNamespaceNesting(env);
				if (nesting) checks.push(nesting);
			}
		}
	}

	return {
		ok: checks.every((check) => check.status !== "fail"),
		platform: env.platform,
		backend,
		piVersion: env.piVersion,
		checks,
	};
}

/** Human-readable report for `/enclave status` and for CI logs. */
export function formatProbeReport(report: ProbeReport): string {
	const icon: Record<CheckStatus, string> = { ok: "✓", warn: "!", fail: "✗" };
	const lines = [`pi-enclave probe: ${report.ok ? "ready" : "REFUSING TO START"}`];
	for (const check of report.checks) {
		lines.push(`  ${icon[check.status]} ${check.title}: ${check.detail}`);
		if (check.remediation) lines.push(`      -> ${check.remediation}`);
	}
	return lines.join("\n");
}
