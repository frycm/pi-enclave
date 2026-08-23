/**
 * The real-host {@link ProbeEnv}. Kept apart from `probe.ts` so the decision
 * logic stays free of filesystem and PATH access and can be unit-tested
 * exhaustively from any platform.
 */
import { accessSync, constants, readFileSync } from "node:fs";
import { delimiter, isAbsolute, join } from "node:path";
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
	};
}

export function probeHost(piVersion: string | null): ProbeReport {
	return probe(hostProbeEnv(piVersion));
}
