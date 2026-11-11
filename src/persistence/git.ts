/**
 * Where Git keeps configuration and hooks inside the writable roots (#33).
 *
 * Running any Git command in a directory reads that repository's `config`,
 * and `git status` in a superproject also reads every submodule's. A
 * `core.fsmonitor`, `core.hooksPath`, `core.pager`, filter driver or alias in
 * one of those files runs with the user's privileges outside the sandbox. So
 * every Git directory an agent could have written to is part of the
 * persistence surface, not only the workspace root's.
 *
 * This module only finds and fingerprints those paths. It never runs Git:
 * the tree it inspects is the agent's.
 */
import {
	closeSync,
	constants,
	type Dirent,
	lstatSync,
	openSync,
	readdirSync,
	readlinkSync,
	readSync,
	realpathSync,
} from "node:fs";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { type FingerprintBudget, fingerprint, PersistenceScanError, type ScanMatch, scanRoots } from "./scan.ts";

export interface GitEntry extends ScanMatch {
	/**
	 * A directory Git accepts as a repository by its contents rather than its
	 * name (`HEAD` and `objects` and `refs`, or `HEAD` and `commondir`). Git
	 * checks every ancestor of the current directory for that shape, so with
	 * `core.bare = false` and `core.worktree = .` in its config, `git status`
	 * in it or anywhere below it reads that config and runs its hooks.
	 */
	bare: boolean;
}

export interface GitScanOptions {
	maxEntries?: number;
	/** Receives directories nobody running as this user can reach. */
	unscanned?: string[];
}

/**
 * Whether `HEAD` in `dir` is one Git accepts: a symlink into `refs/`, a
 * `ref: refs/...` line or an object id. Git ignores a directory whose HEAD is
 * not, so a build cache that happens to hold files with these names is left
 * alone.
 */
function validHead(dir: string, entry: Dirent): boolean {
	const path = join(dir, "HEAD");
	try {
		if (entry.isSymbolicLink()) return readlinkSync(path).startsWith("refs/");
		if (!entry.isFile()) return false;
		const head = readHead(path);
		return /^ref:\s*refs\//.test(head) || /^[0-9a-f]{40}(?:[0-9a-f]{24})?\s*$/.test(head);
	} catch {
		return false;
	}
}

function isGitDirListing(dir: string, entries: readonly Dirent[]): boolean {
	// Called for every directory walked, so one pass and no allocation.
	let head: Dirent | undefined;
	let objects = false;
	let refs = false;
	let commondir = false;
	for (const entry of entries) {
		if (entry.name === "HEAD") head = entry;
		else if (entry.name === "objects") objects = true;
		else if (entry.name === "refs") refs = true;
		else if (entry.name === "commondir") commondir = true;
	}
	if (!head || !(commondir || (objects && refs))) return false;
	return validHead(dir, head);
}

/**
 * Every Git directory under the roots: each `.git` entry (directory, gitfile
 * or symlink), not descended into, and each directory shaped like a bare
 * repository whatever its name.
 */
export function findGitEntries(roots: readonly string[], options: GitScanOptions = {}): GitEntry[] {
	const bare = new Set<string>();
	const matches = scanRoots(roots, {
		match: (name) => name === ".git",
		matchListing: (dir, entries) => {
			if (!isGitDirListing(dir, entries)) return false;
			bare.add(dir);
			return true;
		},
		...(options.maxEntries !== undefined ? { maxEntries: options.maxEntries } : {}),
		...(options.unscanned ? { unscanned: options.unscanned } : {}),
	});
	return matches.map((match) => ({ ...match, bare: bare.has(match.path) && match.kind === "dir" }));
}

/**
 * The first few kilobytes of a file the agent may control: bounded, never
 * through a symlink, and non-blocking in case it was swapped for a FIFO after
 * it was listed.
 */
function readHead(path: string): string {
	const fd = openSync(path, constants.O_RDONLY | constants.O_NONBLOCK | constants.O_NOFOLLOW);
	const buffer = Buffer.alloc(4096);
	try {
		return buffer.subarray(0, readSync(fd, buffer, 0, buffer.length, 0)).toString("utf8");
	} finally {
		closeSync(fd);
	}
}

/**
 * The directory a gitfile (`gitdir: <path>`) points at, or `undefined` when
 * the file is not one. Only the first line is read, as Git does.
 */
export function readGitfile(path: string): string | undefined {
	const firstLine = readHead(path).split(/\r?\n/, 1)[0] ?? "";
	const match = /^gitdir:\s*(.+?)\s*$/i.exec(firstLine);
	if (!match?.[1]) return undefined;
	return isAbsolute(match[1]) ? match[1] : resolve(dirname(path), match[1]);
}

function isRealDir(path: string): boolean {
	try {
		const stats = lstatSync(path);
		return stats.isDirectory() && !stats.isSymbolicLink();
	} catch {
		return false;
	}
}

function isRealFile(path: string): boolean {
	try {
		return lstatSync(path).isFile();
	} catch {
		return false;
	}
}

function exists(path: string): boolean {
	try {
		lstatSync(path);
		return true;
	} catch {
		return false;
	}
}

/** The surface fingerprinted for one Git directory. */
const METADATA_FILES = ["config", "config.worktree", "commondir"] as const;

/**
 * Path -> fingerprint for every Git persistence path under `roots`:
 *
 * - each `.git` entry itself, and each bare-shaped Git directory (a directory
 *   only by identity, since its other contents change on every commit),
 * - for each Git directory, including gitfile targets, `commondir` targets
 *   and submodule directories below `modules/`: its `config`,
 *   `config.worktree`, `commondir` and the whole `hooks` tree,
 * - each directory the walk skipped because nobody running as this user can
 *   reach inside it, by identity and owner.
 *
 * A path that appears between two calls is a repository or a configuration
 * file the agent created; a fingerprint that changes is one it edited.
 */
export function gitPersistenceSurface(
	roots: readonly string[],
	options: { maxEntries?: number } = {},
): Map<string, string> {
	const surface = new Map<string, string>();
	const budget: FingerprintBudget = { remaining: 65_536 };
	const seen = new Set<string>();
	let moduleDirs = 0;

	const record = (path: string) => {
		const value = fingerprint(path, budget);
		if (value !== undefined) surface.set(path, value);
	};

	const visitMetadata = (dir: string) => {
		let canonical: string;
		try {
			canonical = realpathSync(dir);
		} catch {
			return;
		}
		if (seen.has(canonical) || !isRealDir(canonical)) return;
		seen.add(canonical);
		for (const name of METADATA_FILES) record(join(canonical, name));
		record(join(canonical, "hooks"));
		const commondir = join(canonical, "commondir");
		if (isRealFile(commondir)) {
			const value = readHead(commondir).trim();
			if (value) visitMetadata(isAbsolute(value) ? value : resolve(canonical, value));
		}
		visitModules(join(canonical, "modules"));
	};

	// Submodule names may contain slashes, stored as namespace directories, so
	// a directory below `modules/` is either a Git directory (it has `HEAD`) or
	// a namespace to look inside.
	const visitModules = (container: string) => {
		if (!isRealDir(container)) return;
		surface.set(container, `dir:${lstatSync(container).ino}:[${readdirSync(container).sort().join(",")}]`);
		for (const name of readdirSync(container)) {
			const child = join(container, name);
			if (!isRealDir(child)) continue;
			moduleDirs++;
			if (moduleDirs > 1024) throw new PersistenceScanError(`too many Git submodule directories below ${container}`);
			if (exists(join(child, "HEAD"))) visitMetadata(child);
			else visitModules(child);
		}
	};

	const unscanned: string[] = [];
	const entries = findGitEntries(roots, { ...options, unscanned });
	// A directory nobody here can reach is recorded by identity and owner, so
	// one that later becomes readable shows up: its contents appear as created.
	for (const dir of unscanned) {
		const stats = lstatSync(dir);
		surface.set(dir, `unscanned:${stats.ino}:${stats.uid}:${stats.mode}`);
	}
	for (const entry of entries) {
		if (entry.bare) {
			surface.set(entry.path, `gitdir:${lstatSync(entry.path).ino}`);
			visitMetadata(entry.path);
			continue;
		}
		if (entry.kind === "dir") {
			surface.set(entry.path, `dir:${lstatSync(entry.path).ino}`);
			visitMetadata(entry.path);
			continue;
		}
		record(entry.path);
		if (entry.kind === "file") {
			const target = readGitfile(entry.path);
			if (target !== undefined) visitMetadata(target);
		}
	}
	return surface;
}
