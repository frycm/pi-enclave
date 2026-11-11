/**
 * The real-host {@link ProbeEnv}. Kept apart from `probe.ts` so the decision
 * logic stays free of filesystem and PATH access and can be unit-tested
 * exhaustively from any platform.
 */
import { spawnSync } from "node:child_process";
import { accessSync, constants, readFileSync, realpathSync, statSync } from "node:fs";
import { arch } from "node:os";
import { delimiter, dirname, isAbsolute, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { canonical, isUnder } from "./backend/paths.ts";
import type { ProbeEnv, ProbeReport } from "./probe.ts";
import { probe } from "./probe.ts";

/** Resolve an executable on PATH to the canonical file that will be invoked. */
export function whichSync(bin: string, searchPath = process.env.PATH ?? ""): string | null {
	const candidates = isAbsolute(bin)
		? [bin]
		: searchPath
				.split(delimiter)
				.filter(Boolean)
				.map((dir) => resolve(dir, bin));

	for (const candidate of candidates) {
		try {
			accessSync(candidate, constants.X_OK);
			const resolved = realpathSync(candidate);
			if (!statSync(resolved).isFile()) continue;
			return resolved;
		} catch {
			// Not here, or not executable. Keep looking.
		}
	}
	return null;
}

export interface HostPathSafety {
	ok: boolean;
	detail: string;
}

/** Host programs SRT may start before the sandbox boundary is established. */
function hostRuntimeExecutables(platform: NodeJS.Platform, searchPath: string): string[] {
	const names =
		platform === "linux"
			? ["which", "bwrap", "socat", "rg", "fd", "env"]
			: platform === "darwin"
				? ["which", "log", "rg", "fd", "env"]
				: ["which"];
	const resolved = names.map((name) => whichSync(name, searchPath)).filter((path): path is string => path !== null);
	for (const absolute of ["/bin/bash", ...(platform === "darwin" ? ["/usr/bin/sandbox-exec"] : [])]) {
		const path = whichSync(absolute, searchPath);
		if (path) resolved.push(path);
	}
	// The binary running pi itself, and so pi-enclave: a copy the agent can
	// replace runs everything at the next start (#36). The container backend
	// already checks it.
	resolved.push(process.execPath);
	return [...new Set(resolved)];
}

/**
 * Refuse a selected host executable whose canonical target is agent-writable.
 *
 * One that the profile write-denies is not agent-writable, whatever root it
 * sits below: that is how `sandbox.allowSelfHosting` keeps a Node binary or
 * seccomp helper inside the workspace (#36). Both its spellings must be
 * covered, so a symlink the agent could retarget is not accepted.
 */
export function hostExecutableSafety(
	writableRoots: readonly string[],
	executables: readonly string[],
	writeDeny: readonly string[] = [],
): HostPathSafety {
	const roots = writableRoots.map(canonical);
	const denied = writeDeny.map(canonical);
	const unsafe = executables.filter((path) => {
		const lexical = resolve(path);
		const resolved = canonical(lexical);
		const writable =
			writableRoots.some((root) => isUnder(lexical, root)) || roots.some((root) => isUnder(resolved, root));
		if (!writable) return false;
		const protectedPath = (spelling: string) =>
			writeDeny.some((entry) => isUnder(spelling, entry)) || denied.some((entry) => isUnder(spelling, entry));
		return !(protectedPath(lexical) && protectedPath(resolved));
	});
	if (unsafe.length === 0) return { ok: true, detail: "host executable targets are outside writable roots" };
	return {
		ok: false,
		detail: `host executable resolves into an agent-writable root: ${[...new Set(unsafe)].join(", ")}`,
	};
}

/**
 * Refuse a PATH entry the repository can write before sandbox-runtime touches
 * it. SRT invokes host-side helpers such as `which`, `log` and `socat` through
 * PATH, so filtering only the eventual child environment is too late.
 */
export function hostPathSafety(writableRoots: readonly string[], searchPath = process.env.PATH ?? ""): HostPathSafety {
	const unsafe: string[] = [];
	for (const entry of searchPath.split(delimiter)) {
		if (!entry || !isAbsolute(entry)) {
			unsafe.push(entry || "<empty>");
			continue;
		}
		const lexical = resolve(entry);
		const resolved = canonical(lexical);
		if (
			writableRoots.some((root) => {
				const canonicalRoot = canonical(root);
				return (
					isUnder(lexical, root) ||
					isUnder(root, lexical) ||
					isUnder(resolved, canonicalRoot) ||
					isUnder(canonicalRoot, resolved)
				);
			})
		) {
			unsafe.push(entry);
		}
	}
	if (unsafe.length === 0) return { ok: true, detail: "PATH contains only absolute, non-workspace entries" };
	return {
		ok: false,
		detail: `PATH contains repository-writable or relative entries: ${[...new Set(unsafe)].join(", ")}`,
	};
}

/** Validate both PATH directories and the canonical targets SRT will execute. */
export function hostRuntimeSafety(
	writableRoots: readonly string[],
	searchPath = process.env.PATH ?? "",
	platform: NodeJS.Platform = process.platform,
	writeDeny: readonly string[] = [],
): HostPathSafety {
	const path = hostPathSafety(writableRoots, searchPath);
	if (!path.ok) return path;
	const executables = hostExecutableSafety(writableRoots, hostRuntimeExecutables(platform, searchPath), writeDeny);
	if (!executables.ok) return executables;
	return {
		ok: true,
		detail: "PATH entries and selected host executables are absolute and outside writable roots",
	};
}

export function readTextSync(path: string): string | null {
	try {
		return readFileSync(path, "utf8");
	} catch {
		return null;
	}
}

/**
 * sandbox-runtime's vendor directory name for an architecture, or null where it
 * ships no helper. Mirrors SRT's own mapping: ia32 is deliberately absent,
 * because `socketcall()` multiplexes every socket operation there and the
 * filter cannot see the address family.
 */
export function seccompHelperArch(architecture: string): "x64" | "arm64" | null {
	if (architecture === "x64") return "x64";
	if (architecture === "arm64") return "arm64";
	return null;
}

/** The installed sandbox-runtime package root, or null when it cannot be resolved. */
function srtPackageRoot(): string | null {
	try {
		const entry = fileURLToPath(import.meta.resolve("@anthropic-ai/sandbox-runtime"));
		// dist/index.js -> package root
		return dirname(dirname(entry));
	} catch {
		return null;
	}
}

/**
 * Locate sandbox-runtime's vendored seccomp helper for this architecture.
 *
 * The helper is what blocks `socket(AF_UNIX, ...)` inside the Linux sandbox.
 * When sandbox-runtime cannot find it, it records a warning nobody reads and
 * runs every command without the filter, so a null here must fail the probe
 * rather than pass it (#34).
 *
 * Only the package pi-enclave itself depends on is searched. sandbox-runtime
 * would also fall back to a global npm install, which nothing here has
 * vetted; the resolved path is passed to it explicitly so that fallback is
 * never taken. The canonical path is returned, so the writable-root check sees
 * the file bwrap will actually execute.
 *
 * Resolved from the installed package rather than hardcoded, so a version bump
 * that moves or renames it surfaces as "helper not found" instead of a silently
 * skipped check.
 */
export function resolveSeccompHelper(
	packageRoot: string | null = srtPackageRoot(),
	architecture: string = arch(),
): string | null {
	const name = seccompHelperArch(architecture);
	if (!packageRoot || !name) return null;
	const candidate = join(packageRoot, "vendor", "seccomp", name, "apply-seccomp");
	try {
		accessSync(candidate, constants.X_OK);
		const resolved = realpathSync(candidate);
		return statSync(resolved).isFile() ? resolved : null;
	} catch {
		return null;
	}
}

/**
 * Run the namespace chain sandbox-runtime depends on, and report whether it
 * works.
 *
 * Deliberately executes the real thing rather than inspecting kernel settings.
 * A container can have no AppArmor restriction at all and still refuse the
 * nested user namespace the seccomp helper needs, in which case every heuristic
 * says "fine" and every command fails.
 */
export function canNestNamespaces(
	writableRoots: readonly string[] = [process.cwd()],
	searchPath = process.env.PATH ?? "",
): { ok: boolean; detail: string } | null {
	if (process.platform !== "linux") return null;
	const bwrap = whichSync("bwrap", searchPath);
	if (bwrap === null) return null;
	const executableSafety = hostExecutableSafety(writableRoots, [bwrap]);
	if (!executableSafety.ok) return executableSafety;

	const helper = resolveSeccompHelper();
	// Without the helper there is nothing to nest, and running plain `true`
	// would report a working sandbox that has no Unix-socket filter. The
	// seccomp-helper check states the cause; this one must not contradict it.
	if (helper === null) {
		return { ok: false, detail: "the seccomp helper is missing, so the namespace chain cannot be checked" };
	}
	const inner = [helper, "true"];
	const probe = spawnSync(
		bwrap,
		[
			"--dev",
			"/dev",
			"--ro-bind",
			"/",
			"/",
			"--unshare-user",
			"--unshare-pid",
			"--cap-drop",
			"ALL",
			"--proc",
			"/proc",
			"--",
			...inner,
		],
		{ encoding: "utf8", timeout: 15_000 },
	);

	if (probe.status === 0) {
		return { ok: true, detail: "bubblewrap and the seccomp helper can both create the namespaces they need" };
	}

	const message = `${probe.stderr ?? ""}${probe.stdout ?? ""}`.trim().split("\n")[0] ?? "unknown failure";
	return { ok: false, detail: `the sandbox cannot start here: ${message}` };
}

/**
 * Build a ProbeEnv for this process.
 *
 * `piVersion` is passed in rather than imported: the extension reads pi's
 * exported `VERSION` at load time, and the caller decides what to do when the
 * import itself fails (which is itself a probe failure).
 */
export function hostProbeEnv(piVersion: string | null): ProbeEnv {
	return {
		platform: process.platform,
		nodeVersion: process.versions.node,
		piVersion,
		which: whichSync,
		readText: readTextSync,
		canNestNamespaces,
		seccompHelper: () => resolveSeccompHelper(),
		pathSafety: () => hostRuntimeSafety([process.cwd()]),
	};
}

export function probeHost(piVersion: string | null): ProbeReport {
	return probe(hostProbeEnv(piVersion));
}
