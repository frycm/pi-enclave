/**
 * Files in the workspace that something outside the sandbox loads later (#19).
 *
 * Two kinds, treated differently:
 *
 * - **Agent configuration** that pi itself loads, in the pi process and
 *   outside the sandbox: a `.pi` directory (extensions, `settings.json`,
 *   `mcp.json`) anywhere in the tree, since trust in a directory is inherited
 *   by its subdirectories, and an `.agents` directory (skills). Existing ones
 *   are write-denied at L2 when the profile compiles; new ones are reported by
 *   the tripwire and count against the turn, like a Git hook.
 * - **Project files** that load or run with the user's privileges the next
 *   time the user, their shell or their editor touches the project:
 *   instruction files every agent reads (`AGENTS.md`, `CLAUDE.md`), direnv's
 *   `.envrc`, hook managers, editor tasks. Editing them is ordinary work, so
 *   they are an ask at L1, and the tripwire reports a change without counting
 *   it. They cannot be closed in general: a writable workspace is one whose
 *   build files the agent can edit. The README says so.
 *
 * Names are compared case-insensitively: on a case-insensitive file system
 * (macOS by default) `Agents.md` is the file pi opens as `AGENTS.md`.
 */
import { realpathSync } from "node:fs";
import { basename, dirname } from "node:path";
import { gitPersistenceSurface } from "./git.ts";
import { type EntryKind, type FingerprintBudget, fingerprint, type ScanMatch } from "./scan.ts";

/** Directories pi loads code or configuration from. */
export const AGENT_CONFIG_DIRS: readonly string[] = [".pi", ".agents"];

/** Files and directories loaded or run later by something other than pi. */
export const PROJECT_FILES: readonly string[] = [
	"agents.md",
	"agents.override.md",
	"claude.md",
	".envrc",
	".husky",
	"lefthook.yml",
	"lefthook.yaml",
	".lefthook.yml",
	".lefthook.yaml",
	".pre-commit-config.yaml",
];

export type SurfaceKind = "git" | "agent" | "project";

export function isAgentConfigName(name: string): boolean {
	return AGENT_CONFIG_DIRS.includes(name.toLowerCase());
}

function isProjectFileName(name: string, path: string): boolean {
	const lower = name.toLowerCase();
	if (PROJECT_FILES.includes(lower)) return true;
	return lower === "tasks.json" && basename(dirname(path)).toLowerCase() === ".vscode";
}

/** Whether a walked entry belongs on the agent or project surface. */
export function isAgentSurfaceEntry(name: string, _kind: EntryKind, path: string): boolean {
	return isAgentConfigName(name) || isProjectFileName(name, path);
}

/**
 * Which kind of surface a path reported by {@link persistenceSurface} is on.
 * Anything inside a `.pi` or `.agents` directory is agent configuration, so a
 * `CLAUDE.md` inside `.agents/skills` counts as one.
 */
export function classifySurfacePath(path: string): SurfaceKind {
	const parts = path.split(/[\\/]/);
	if (parts.some(isAgentConfigName)) return "agent";
	const name = parts.at(-1) ?? "";
	if (parts.some((part) => part.toLowerCase() === ".husky") || isProjectFileName(name, path)) return "project";
	return "git";
}

function targetFingerprint(link: string, budget: FingerprintBudget): string {
	let target: string;
	try {
		target = realpathSync(link);
	} catch {
		return "dangling";
	}
	return `${target}=${fingerprint(target, budget)}`;
}

/**
 * The whole persistence surface in one walk: Git's (see
 * {@link gitPersistenceSurface}) plus every agent configuration directory and
 * project file, each fingerprinted with everything below it.
 */
export function persistenceSurface(
	roots: readonly string[],
	options: { maxEntries?: number } = {},
): Map<string, string> {
	const also: ScanMatch[] = [];
	const surface = gitPersistenceSurface(roots, { ...options, alsoMatch: isAgentSurfaceEntry, also });
	const budget: FingerprintBudget = { remaining: 65_536 };
	for (const entry of also) {
		let value = fingerprint(entry.path, budget);
		if (value === undefined) continue;
		// A symlinked `.pi` loads what it points at, so what it points at is
		// what has to stay the same.
		if (entry.kind === "symlink") value += `|${targetFingerprint(entry.path, budget)}`;
		surface.set(entry.path, value);
	}
	return surface;
}
