/**
 * The real-host {@link ProbeEnv}. Kept apart from `probe.ts` so the decision
 * logic stays free of filesystem and PATH access and can be unit-tested
 * exhaustively from any platform.
 */
import { spawnSync } from "node:child_process";
import { accessSync, constants, existsSync, readFileSync } from "node:fs";
import { arch } from "node:os";
import { delimiter, dirname, isAbsolute, join } from "node:path";
import { fileURLToPath } from "node:url";
import type { ProbeEnv, ProbeReport } from "./probe.ts";
import { probe } from "./probe.ts";

/** Resolve an executable on PATH. Absolute inputs are probed directly. */
export function whichSync(bin: string): string | null {
	const candidates = isAbsolute(bin)
		? [bin]
		: (process.env.PATH ?? "")
				.split(delimiter)
				.filter(Boolean)
				.map((dir) => join(dir, bin));

	for (const candidate of candidates) {
		try {
			accessSync(candidate, constants.X_OK);
			return candidate;
		} catch {
			// Not here, or not executable. Keep looking.
		}
	}
	return null;
}

export function readTextSync(path: string): string | null {
	try {
		return readFileSync(path, "utf8");
	} catch {
		return null;
	}
}

/**
 * Locate sandbox-runtime's vendored seccomp helper for this architecture.
 *
 * Resolved from the installed package rather than hardcoded, so a version bump
 * that moves or renames it surfaces as "helper not found" instead of a silently
 * skipped check.
 */
function resolveSeccompHelper(): string | null {
	try {
		const entry = fileURLToPath(import.meta.resolve("@anthropic-ai/sandbox-runtime"));
		// dist/index.js -> package root
		const root = dirname(dirname(entry));
		const arches = arch() === "arm64" ? ["arm64"] : ["x64"];
		for (const name of arches) {
			const candidate = join(root, "vendor", "seccomp", name, "apply-seccomp");
			if (existsSync(candidate)) return candidate;
		}
		return null;
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
export function canNestNamespaces(): { ok: boolean; detail: string } | null {
	if (process.platform !== "linux") return null;
	if (whichSync("bwrap") === null) return null;

	const helper = resolveSeccompHelper();
	const inner = helper ? [helper, "true"] : ["true"];
	const probe = spawnSync(
		"bwrap",
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
		return {
			ok: true,
			detail: helper
				? "bubblewrap and the seccomp helper can both create the namespaces they need"
				: "bubblewrap can create a capability-bearing namespace (seccomp helper not found; check is partial)",
		};
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
	};
}

export function probeHost(piVersion: string | null): ProbeReport {
	return probe(hostProbeEnv(piVersion));
}
