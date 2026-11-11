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
import { lstatSync, readlinkSync, realpathSync, type Stats } from "node:fs";
import { basename, dirname } from "node:path";
import { canonical, isUnder } from "../backend/paths.ts";
import type { Profile } from "../backend/types.ts";
import { gitPersistenceSurface } from "./git.ts";
import { type EntryKind, type FingerprintBudget, fingerprint, PersistenceScanError, type ScanMatch } from "./scan.ts";

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
 * Every value in {@link persistenceSurface} is prefixed with the kind of the
 * surface that produced it, so a hit is classified by where it came from and
 * not by its path: a repository at `.husky/r/.git` is Git metadata, not a
 * project file.
 */
const KIND_SEPARATOR = "\u0000";
const KINDS: readonly SurfaceKind[] = ["git", "agent", "project"];

/** The kind a {@link persistenceSurface} value was produced by, if it carries one. */
export function surfaceValueKind(value: string): SurfaceKind | undefined {
	const index = value.indexOf(KIND_SEPARATOR);
	if (index < 0) return undefined;
	const kind = value.slice(0, index) as SurfaceKind;
	return KINDS.includes(kind) ? kind : undefined;
}

const UNVERIFIABLE = "unverifiable:";

/** Whether a value says its entry was too large to fingerprint. */
export function isUnverifiableValue(value: string): boolean {
	const index = value.indexOf(KIND_SEPARATOR);
	return value.startsWith(UNVERIFIABLE, index < 0 ? 0 : index + 1);
}

export interface PersistenceSurfaceOptions {
	maxEntries?: number;
	/**
	 * Whether the sandbox cannot write below a canonical path: the compiled
	 * profile write-denies it, or it lies outside every writable root. Such a
	 * directory is recorded by identity only, as a Git directory is, so a
	 * large `.pi` (pi started in a home directory) costs nothing to watch.
	 */
	isProtected?(path: string): boolean;
}

/**
 * {@link PersistenceSurfaceOptions.isProtected} for a compiled profile: a
 * path its `writeDeny` covers, or one outside every writable root.
 */
export function protectedByProfile(profile: Pick<Profile, "writableRoots" | "writeDeny">): (path: string) => boolean {
	const roots = profile.writableRoots.map(canonical);
	const denied = (profile.writeDeny ?? []).map(canonical);
	return (path) => denied.some((deny) => isUnder(path, deny)) || !roots.some((root) => isUnder(path, root));
}

/** Per entry, and for the whole surface, so one huge tree cannot hide the rest. */
const ENTRY_BUDGET = 16_384;
const TOTAL_BUDGET = 262_144;

function entryValue(
	entry: ScanMatch,
	isProtected: (path: string) => boolean,
	total: FingerprintBudget,
): string | undefined {
	let stats: Stats;
	try {
		stats = lstatSync(entry.path);
	} catch (error) {
		if ((error as NodeJS.ErrnoException).code === "ENOENT") return undefined;
		throw error;
	}
	let target: string | undefined = entry.path;
	if (entry.kind === "symlink") {
		try {
			target = realpathSync(entry.path);
		} catch {
			target = undefined;
		}
	}
	const link = entry.kind === "symlink" ? `->${readlinkSync(entry.path)}` : "";
	if (target !== undefined && isProtected(target)) {
		return `protected:${stats.ino}${link}:${lstatSync(target).ino}`;
	}
	const budget: FingerprintBudget = { remaining: Math.min(ENTRY_BUDGET, total.remaining) };
	const start = budget.remaining;
	try {
		const value = fingerprint(entry.path, budget);
		if (value === undefined) return undefined;
		// A symlinked `.pi` loads what it points at, so what it points at is
		// what has to stay the same.
		if (entry.kind !== "symlink") return value;
		return target === undefined ? `${value}|dangling` : `${value}|${target}=${fingerprint(target, budget)}`;
	} catch (error) {
		if (!(error instanceof PersistenceScanError)) throw error;
		// Reported as unverifiable at every check, never passed as unchanged.
		return `${UNVERIFIABLE}${stats.ino}`;
	} finally {
		total.remaining -= start - Math.max(budget.remaining, 0);
	}
}

/**
 * The whole persistence surface in one walk: Git's (see
 * {@link gitPersistenceSurface}) plus every agent configuration directory and
 * project file. One the sandbox can write below is fingerprinted with
 * everything below it; one it cannot is recorded by identity.
 */
export function persistenceSurface(
	roots: readonly string[],
	options: PersistenceSurfaceOptions = {},
): Map<string, string> {
	const also: ScanMatch[] = [];
	const git = gitPersistenceSurface(roots, {
		...(options.maxEntries !== undefined ? { maxEntries: options.maxEntries } : {}),
		alsoMatch: isAgentSurfaceEntry,
		also,
	});
	const surface = new Map<string, string>();
	for (const [path, value] of git) surface.set(path, `git${KIND_SEPARATOR}${value}`);
	const isProtected = options.isProtected ?? (() => false);
	const total: FingerprintBudget = { remaining: TOTAL_BUDGET };
	for (const entry of also) {
		const kind: SurfaceKind = isAgentConfigName(basename(entry.path)) ? "agent" : "project";
		const value = entryValue(entry, isProtected, total);
		if (value !== undefined) surface.set(entry.path, `${kind}${KIND_SEPARATOR}${value}`);
	}
	return surface;
}
