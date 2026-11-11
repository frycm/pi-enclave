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
import { closeSync, constants, lstatSync, openSync, readdirSync, readSync, realpathSync } from "node:fs";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { type FingerprintBudget, fingerprint, PersistenceScanError, type ScanMatch, scanRoots } from "./scan.ts";

/** Every `.git` entry (directory, gitfile or symlink) under the roots. Not descended into. */
export function findGitEntries(roots: readonly string[], maxEntries?: number): ScanMatch[] {
	return scanRoots(roots, {
		match: (name) => name === ".git",
		...(maxEntries !== undefined ? { maxEntries } : {}),
	});
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
 * - each `.git` entry itself (a directory only by identity, since its other
 *   contents change on every commit),
 * - for each Git directory, including gitfile targets, `commondir` targets
 *   and submodule directories below `modules/`: its `config`,
 *   `config.worktree`, `commondir` and the whole `hooks` tree.
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

	for (const entry of findGitEntries(roots, options.maxEntries)) {
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
