/**
 * The bridge between a configured profile and the backend's.
 *
 * The backend's `Profile` (`backend/types.ts`) is deliberately smaller than an
 * `EffectiveProfile`: it carries only what the kernel is told, and knows
 * nothing about rules, review, attendance or the breaker. Keeping the two apart
 * means a configuration change cannot accidentally alter what gets compiled,
 * and that a backend can be tested against a profile nobody configured.
 */

import { spawnSync } from "node:child_process";
import { lstatSync, readdirSync, readFileSync } from "node:fs";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { canonical, isUnder } from "../backend/paths.ts";
import type { Profile } from "../backend/types.ts";
import { buildChildEnv } from "../env/child-env.ts";
import { type DefaultProfileOptions, defaultProfile } from "./defaults.ts";
import type { EffectiveProfile } from "./types.ts";

export { defaultReadDeny } from "./defaults.ts";

interface GitConfigEntry {
	key: string;
	value: string;
}

function gitCommand(workspaceRoot: string, writableRoots: readonly string[], args: readonly string[]): string {
	const result = spawnSync("git", ["-C", workspaceRoot, ...args], {
		encoding: "utf8",
		timeout: 2_000,
		maxBuffer: 1024 * 1024,
		env: buildChildEnv(process.env, { writableRoots }),
	});
	// Some constrained hosts report an EPERM wrapper diagnostic even though the
	// child ran and returned status 0. The process status is authoritative; a
	// real spawn failure has no successful status.
	if (result.status === null && result.error) {
		throw new Error(`pi-enclave: cannot inspect Git persistence paths: ${result.error.message}`);
	}
	if (result.signal || result.status !== 0) {
		const detail = result.stderr.trim() || `git exited with status ${String(result.status)}`;
		throw new Error(`pi-enclave: cannot inspect Git persistence paths: ${detail}`);
	}
	return result.stdout;
}

/** Parse `git config -z --list`, whose records are `key\nvalue\0`. */
function parseGitConfigEntries(output: string): GitConfigEntry[] {
	const entries: GitConfigEntry[] = [];
	for (const record of output.split("\0")) {
		if (!record) continue;
		const separator = record.indexOf("\n");
		if (separator < 0) throw new Error("pi-enclave: Git returned malformed configuration output");
		entries.push({ key: record.slice(0, separator).toLowerCase(), value: record.slice(separator + 1) });
	}
	return entries;
}

/** Parse `--show-origin -z`, which alternates `origin\0key\nvalue\0`. */
function parseGitConfigWithOrigins(output: string): { origin: string; entry: GitConfigEntry }[] {
	const records = output.split("\0");
	if (records.at(-1) === "") records.pop();
	if (records.length % 2 !== 0) throw new Error("pi-enclave: Git returned malformed origin output");
	const entries: { origin: string; entry: GitConfigEntry }[] = [];
	for (let index = 0; index < records.length; index += 2) {
		const origin = records[index];
		const record = records[index + 1];
		if (origin === undefined || record === undefined) throw new Error("pi-enclave: Git origin output is incomplete");
		const [entry] = parseGitConfigEntries(`${record}\0`);
		if (!entry) throw new Error("pi-enclave: Git origin output has an empty entry");
		entries.push({ origin, entry });
	}
	return entries;
}

function resolveConfigPath(value: string, containingFile: string, home: string): string {
	if (value.startsWith("~/")) return resolve(home, value.slice(2));
	if (value.startsWith("~") || value.startsWith("%(")) {
		throw new Error(`pi-enclave: unsupported Git configuration path syntax: ${value}`);
	}
	return isAbsolute(value) ? value : resolve(dirname(containingFile), value);
}

function resolveHooksPath(value: string, workspaceRoot: string, home: string): string | undefined {
	if (value === "/dev/null") return undefined;
	if (value === "") throw new Error("pi-enclave: refusing an empty core.hooksPath");
	if (value.startsWith("~/")) return resolve(home, value.slice(2));
	if (value.startsWith("~") || value.startsWith("%(")) {
		throw new Error(`pi-enclave: unsupported core.hooksPath syntax: ${value}`);
	}
	return isAbsolute(value) ? value : resolve(workspaceRoot, value);
}

/** A bare repository keeps Git metadata directly at the workspace root. */
function isBareGitMetadata(path: string): boolean {
	try {
		const head = lstatSync(join(path, "HEAD"));
		const config = lstatSync(join(path, "config"));
		const objects = lstatSync(join(path, "objects"));
		const refs = lstatSync(join(path, "refs"));
		return (
			head.isFile() &&
			!head.isSymbolicLink() &&
			config.isFile() &&
			!config.isSymbolicLink() &&
			objects.isDirectory() &&
			!objects.isSymbolicLink() &&
			refs.isDirectory() &&
			!refs.isSymbolicLink()
		);
	} catch (error) {
		if ((error as NodeJS.ErrnoException).code === "ENOENT") return false;
		throw error;
	}
}

/** Everything the sandbox is told, and nothing else. */
export function toBackendProfile(effective: EffectiveProfile, workspaceRoot: string): Profile {
	// These paths execute code in the privileged Pi process on a later launch.
	// Keep them read-only in L2 rather than relying on shell-path inference.
	// `.pi` is materialized by the trusted parent because bwrap cannot mount a
	// read-only denial over a path that does not exist yet.
	const projectState = join(workspaceRoot, ".pi");
	const gitDir = join(workspaceRoot, ".git");
	const writeDeny = [projectState, ...effective.sandbox.readDeny];
	const materializeWriteDeny = [projectState];
	const materializeWriteDenyFiles: string[] = [];
	const writableRoots = effective.sandbox.writableRoots.map(canonical);
	const isWritable = (path: string) => writableRoots.some((root) => isUnder(canonical(path), root));
	const validateProtectedFile = (path: string, label: string): boolean => {
		try {
			const stat = lstatSync(path);
			if (!stat.isFile() || stat.isSymbolicLink()) {
				throw new Error(`pi-enclave: ${label} is not a real file: ${path}`);
			}
			if (stat.nlink !== 1) {
				throw new Error(`pi-enclave: ${label} has multiple hard links and cannot be protected safely: ${path}`);
			}
			return true;
		} catch (error) {
			if ((error as NodeJS.ErrnoException).code === "ENOENT") return false;
			throw error;
		}
	};
	let inspectedHookEntries = 0;
	const validateHookTree = (path: string): void => {
		let stat: ReturnType<typeof lstatSync>;
		try {
			stat = lstatSync(path);
		} catch (error) {
			if ((error as NodeJS.ErrnoException).code === "ENOENT") return;
			throw error;
		}
		if (!stat.isDirectory() || stat.isSymbolicLink()) {
			throw new Error(`pi-enclave: Git hooks path is not a real directory: ${path}`);
		}
		for (const entry of readdirSync(path, { withFileTypes: true })) {
			inspectedHookEntries++;
			if (inspectedHookEntries > 1024) throw new Error("pi-enclave: Git hooks trees exceed 1024 entries");
			const child = join(path, entry.name);
			const childStat = lstatSync(child);
			if (childStat.isSymbolicLink()) {
				throw new Error(`pi-enclave: refusing a symlinked Git hook entry: ${child}`);
			}
			if (childStat.isDirectory()) validateHookTree(child);
			else if (!childStat.isFile()) throw new Error(`pi-enclave: refusing a non-file Git hook entry: ${child}`);
			else if (childStat.nlink !== 1) {
				throw new Error(`pi-enclave: Git hook entry has multiple hard links: ${child}`);
			}
		}
	};
	const protectWritableFile = (path: string) => {
		const protectedPath = canonical(path);
		validateProtectedFile(path, "Git configuration");
		if (!isWritable(protectedPath)) return;
		writeDeny.push(path, protectedPath);
		materializeWriteDenyFiles.push(path);
	};
	const protectWritableDirectory = (path: string) => {
		const protectedPath = canonical(path);
		validateHookTree(path);
		if (!isWritable(protectedPath)) return;
		writeDeny.push(path, protectedPath);
		materializeWriteDeny.push(path);
	};
	const protectedGitDirs = new Set<string>();
	const gitConfigSeeds: { path: string; hooksBase: string }[] = [];
	const gitConfigSeedKeys = new Set<string>();
	const seedGitConfig = (path: string, hooksBase: string) => {
		const key = `${canonical(path)}\0${canonical(hooksBase)}`;
		if (gitConfigSeedKeys.has(key)) return;
		gitConfigSeedKeys.add(key);
		gitConfigSeeds.push({ path, hooksBase });
	};
	const protectGitMetadata = (metadataDir: string, hooksBase = workspaceRoot) => {
		const resolved = canonical(metadataDir);
		const hooks = join(resolved, "hooks");
		const config = join(resolved, "config");
		const worktreeConfig = join(resolved, "config.worktree");
		seedGitConfig(config, hooksBase);
		seedGitConfig(worktreeConfig, hooksBase);
		if (protectedGitDirs.has(resolved)) return;
		const stat = lstatSync(resolved);
		if (!stat.isDirectory() || stat.isSymbolicLink()) {
			throw new Error(`pi-enclave: Git metadata is not a real directory: ${metadataDir}`);
		}
		protectedGitDirs.add(resolved);
		validateHookTree(hooks);
		validateProtectedFile(config, "Git configuration");
		validateProtectedFile(worktreeConfig, "Git worktree configuration");
		writeDeny.push(hooks, config, worktreeConfig);
		const metadataWritable = isWritable(resolved);
		if (metadataWritable) {
			materializeWriteDeny.push(hooks);
			materializeWriteDenyFiles.push(config, worktreeConfig);
		}

		// Linked worktrees point at a per-worktree directory whose `commondir`
		// locates the hooks and main config actually used by Git.
		const commonFile = join(resolved, "commondir");
		try {
			const commonStat = lstatSync(commonFile);
			if (!commonStat.isFile() || commonStat.isSymbolicLink()) {
				throw new Error(`pi-enclave: invalid Git commondir file: ${commonFile}`);
			}
			if (commonStat.nlink !== 1) {
				throw new Error(`pi-enclave: Git commondir has multiple hard links: ${commonFile}`);
			}
			writeDeny.push(commonFile);
			const commonValue = readFileSync(commonFile, "utf8").trim();
			if (!commonValue) throw new Error(`pi-enclave: empty Git commondir file: ${commonFile}`);
			protectGitMetadata(isAbsolute(commonValue) ? commonValue : resolve(resolved, commonValue), hooksBase);
		} catch (error) {
			if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
		}
	};

	const submoduleWorktreeRoot = (metadataDir: string): string | undefined => {
		const entries = parseGitConfigEntries(
			gitCommand(workspaceRoot, effective.sandbox.writableRoots, [
				"config",
				"-z",
				"--no-includes",
				"--file",
				join(metadataDir, "config"),
				"--list",
			]),
		);
		const configured = entries.filter((entry) => entry.key === "core.worktree").at(-1)?.value;
		if (configured === undefined) return undefined;
		if (configured === "") throw new Error(`pi-enclave: empty core.worktree in ${metadataDir}`);
		if (configured.startsWith("~/")) return resolve(process.env.HOME ?? "", configured.slice(2));
		if (configured.startsWith("~") || configured.startsWith("%(")) {
			throw new Error(`pi-enclave: unsupported core.worktree syntax: ${configured}`);
		}
		return isAbsolute(configured) ? configured : resolve(metadataDir, configured);
	};
	const protectSubmoduleGitfile = (worktree: string, metadataDir: string) => {
		const gitfile = join(worktree, ".git");
		if (!validateProtectedFile(gitfile, "submodule Git metadata file")) return;
		const firstLine = readFileSync(gitfile, "utf8").split(/\r?\n/, 1)[0] ?? "";
		const match = /^gitdir:\s*(.+?)\s*$/i.exec(firstLine);
		if (!match?.[1]) throw new Error(`pi-enclave: refusing an invalid submodule Git metadata file: ${gitfile}`);
		const target = isAbsolute(match[1]) ? match[1] : resolve(dirname(gitfile), match[1]);
		if (canonical(target) !== canonical(metadataDir)) {
			throw new Error(`pi-enclave: submodule Git metadata file points at an unexpected directory: ${gitfile}`);
		}
		protectWritableFile(gitfile);
	};
	const inferredSubmoduleWorktrees = new Map<string, string>();
	const inspectedSubmoduleWorktrees = new Set<string>();
	let discoveredSubmoduleWorktrees = 0;
	const discoverSubmoduleWorktrees = (parentWorktree: string): void => {
		const resolvedParent = canonical(parentWorktree);
		if (inspectedSubmoduleWorktrees.has(resolvedParent)) return;
		inspectedSubmoduleWorktrees.add(resolvedParent);

		const modulesFile = join(parentWorktree, ".gitmodules");
		let stat: ReturnType<typeof lstatSync>;
		try {
			stat = lstatSync(modulesFile);
		} catch (error) {
			if ((error as NodeJS.ErrnoException).code === "ENOENT") return;
			throw error;
		}
		if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1) {
			throw new Error(`pi-enclave: refusing an unsafe Git submodule manifest: ${modulesFile}`);
		}

		const entries = parseGitConfigEntries(
			gitCommand(workspaceRoot, effective.sandbox.writableRoots, [
				"config",
				"-z",
				"--no-includes",
				"--file",
				modulesFile,
				"--list",
			]),
		);
		for (const entry of entries) {
			if (!entry.key.startsWith("submodule.") || !entry.key.endsWith(".path")) continue;
			if (!entry.value || isAbsolute(entry.value)) {
				throw new Error(`pi-enclave: refusing an invalid submodule worktree path in ${modulesFile}`);
			}
			const worktree = resolve(parentWorktree, entry.value);
			if (!isUnder(canonical(worktree), canonical(workspaceRoot))) {
				throw new Error(`pi-enclave: refusing a submodule worktree outside the workspace: ${worktree}`);
			}
			const gitfile = join(worktree, ".git");
			if (!validateProtectedFile(gitfile, "submodule Git metadata file")) continue;
			const firstLine = readFileSync(gitfile, "utf8").split(/\r?\n/, 1)[0] ?? "";
			const match = /^gitdir:\s*(.+?)\s*$/i.exec(firstLine);
			if (!match?.[1]) throw new Error(`pi-enclave: refusing an invalid submodule Git metadata file: ${gitfile}`);
			const target = canonical(isAbsolute(match[1]) ? match[1] : resolve(dirname(gitfile), match[1]));
			const previous = inferredSubmoduleWorktrees.get(target);
			if (previous !== undefined && canonical(previous) !== canonical(worktree)) {
				throw new Error(`pi-enclave: multiple submodule worktrees point at the same Git metadata: ${target}`);
			}
			inferredSubmoduleWorktrees.set(target, worktree);
			protectWritableFile(gitfile);
			discoveredSubmoduleWorktrees++;
			if (discoveredSubmoduleWorktrees > 256) {
				throw new Error("pi-enclave: Git submodule worktree graph exceeds 256 entries");
			}
			discoverSubmoduleWorktrees(worktree);
		}
	};

	let discoveredSubmoduleDirs = 0;
	const protectSubmoduleContainer = (container: string): void => {
		let stat: ReturnType<typeof lstatSync>;
		try {
			stat = lstatSync(container);
		} catch (error) {
			if ((error as NodeJS.ErrnoException).code === "ENOENT") return;
			throw error;
		}
		if (!stat.isDirectory() || stat.isSymbolicLink()) {
			throw new Error(`pi-enclave: Git submodule metadata is not a real directory: ${container}`);
		}

		for (const entry of readdirSync(container, { withFileTypes: true })) {
			if (!entry.isDirectory()) {
				if (entry.isSymbolicLink()) {
					throw new Error(`pi-enclave: refusing symlinked Git submodule metadata: ${join(container, entry.name)}`);
				}
				continue;
			}
			const candidate = join(container, entry.name);
			const candidateStat = lstatSync(candidate);
			if (!candidateStat.isDirectory() || candidateStat.isSymbolicLink()) {
				throw new Error(`pi-enclave: Git submodule metadata is not a real directory: ${candidate}`);
			}
			discoveredSubmoduleDirs++;
			if (discoveredSubmoduleDirs > 256) {
				throw new Error("pi-enclave: Git submodule metadata graph exceeds 256 directories");
			}
			if (isBareGitMetadata(candidate)) {
				const configuredWorktree = submoduleWorktreeRoot(candidate);
				const inferredWorktree = inferredSubmoduleWorktrees.get(canonical(candidate));
				if (
					configuredWorktree !== undefined &&
					inferredWorktree !== undefined &&
					canonical(configuredWorktree) !== canonical(inferredWorktree)
				) {
					throw new Error(`pi-enclave: submodule worktree sources disagree for ${candidate}`);
				}
				const worktree = configuredWorktree ?? inferredWorktree;
				if (!worktree) {
					throw new Error(`pi-enclave: cannot associate submodule Git metadata with a worktree: ${candidate}`);
				}
				protectGitMetadata(candidate, worktree);
				protectSubmoduleGitfile(worktree, candidate);
				protectSubmoduleContainer(join(candidate, "modules"));
			} else {
				// Submodule names may contain slashes, which Git represents as
				// namespace directories below `.git/modules`.
				protectSubmoduleContainer(candidate);
			}
		}
	};

	// Protect both directory-backed repositories and gitfile-backed worktrees or
	// separate git dirs. In a non-Git workspace, register an inert `.git` parent
	// plus the standard config/hooks anchors for trusted materialization before
	// the first action; L1 separately refuses agent-driven `git init`.
	let hasGitMetadata = false;
	try {
		const stat = lstatSync(gitDir);
		hasGitMetadata = true;
		if (stat.isSymbolicLink()) throw new Error(`pi-enclave: refusing a symlinked Git metadata path: ${gitDir}`);
		if (stat.isDirectory()) protectGitMetadata(gitDir);
		else if (stat.isFile()) {
			if (stat.nlink !== 1) throw new Error(`pi-enclave: Git metadata file has multiple hard links: ${gitDir}`);
			writeDeny.push(gitDir);
			const firstLine = readFileSync(gitDir, "utf8").split(/\r?\n/, 1)[0] ?? "";
			const match = /^gitdir:\s*(.+?)\s*$/i.exec(firstLine);
			if (!match?.[1]) throw new Error(`pi-enclave: refusing an invalid Git metadata file: ${gitDir}`);
			const target = isAbsolute(match[1]) ? match[1] : resolve(dirname(gitDir), match[1]);
			protectGitMetadata(target);
		} else throw new Error(`pi-enclave: refusing a non-file Git metadata path: ${gitDir}`);
	} catch (error) {
		if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
		if (isBareGitMetadata(workspaceRoot)) {
			hasGitMetadata = true;
			protectGitMetadata(workspaceRoot);
		} else {
			const hooks = join(gitDir, "hooks");
			const config = join(gitDir, "config");
			writeDeny.push(hooks, config);
			// SRT can only mount a deny boundary over an existing path. Create an
			// inert metadata directory in the trusted parent first, then its protected
			// children; the directory itself remains writable so ordinary index,
			// objects and refs operations continue to work after human initialization.
			materializeWriteDeny.push(gitDir);
			materializeWriteDeny.push(hooks);
			materializeWriteDenyFiles.push(config);
		}
	}

	// Map worktree gitfiles before walking metadata. `core.worktree` is normally
	// present, but Git also accepts an inferred worktree selected by `.git`; the
	// mapping is the independent evidence needed to protect that real hook base.
	discoverSubmoduleWorktrees(workspaceRoot);

	// Every existing submodule has an independent config and hook execution
	// surface below the superproject's metadata. Discover those trusted-parent
	// paths before compiling L2 so an agent cannot persist through a later Git
	// invocation in either the superproject or a nested submodule.
	for (const metadataDir of [...protectedGitDirs]) {
		protectSubmoduleContainer(join(metadataDir, "modules"));
	}

	const initializedGitMetadata =
		hasGitMetadata &&
		[...protectedGitDirs].some((metadataDir) => {
			try {
				const head = lstatSync(join(metadataDir, "HEAD"));
				return head.isFile() && !head.isSymbolicLink();
			} catch (error) {
				if ((error as NodeJS.ErrnoException).code === "ENOENT") return false;
				throw error;
			}
		});
	if (initializedGitMetadata) {
		const active = parseGitConfigWithOrigins(
			gitCommand(workspaceRoot, effective.sandbox.writableRoots, [
				"config",
				"-z",
				"--show-origin",
				"--includes",
				"--list",
			]),
		);
		for (const { origin } of active) {
			if (!origin.startsWith("file:")) continue;
			const file = origin.slice("file:".length);
			const absolute = isAbsolute(file) ? file : resolve(workspaceRoot, file);
			seedGitConfig(absolute, workspaceRoot);
			protectWritableFile(absolute);
		}

		const queue = [...gitConfigSeeds];
		const visited = new Set<string>();
		for (let index = 0; index < queue.length; index++) {
			if (queue.length > 64) throw new Error("pi-enclave: Git configuration include graph exceeds 64 files");
			const queued = queue[index];
			if (!queued) continue;
			const { path: configFile, hooksBase } = queued;
			const identity = `${canonical(configFile)}\0${canonical(hooksBase)}`;
			if (visited.has(identity)) continue;
			visited.add(identity);
			protectWritableFile(configFile);

			try {
				const stat = lstatSync(configFile);
				if (!stat.isFile() || stat.isSymbolicLink()) {
					throw new Error(`pi-enclave: Git configuration is not a real file: ${configFile}`);
				}
			} catch (error) {
				if ((error as NodeJS.ErrnoException).code === "ENOENT") continue;
				throw error;
			}

			const entries = parseGitConfigEntries(
				gitCommand(workspaceRoot, effective.sandbox.writableRoots, [
					"config",
					"-z",
					"--no-includes",
					"--file",
					configFile,
					"--list",
				]),
			);
			for (const entry of entries) {
				if (entry.key === "include.path" || (entry.key.startsWith("includeif.") && entry.key.endsWith(".path"))) {
					const included = resolveConfigPath(entry.value, configFile, process.env.HOME ?? "");
					protectWritableFile(included);
					const key = `${canonical(included)}\0${canonical(hooksBase)}`;
					if (!gitConfigSeedKeys.has(key)) {
						gitConfigSeedKeys.add(key);
						queue.push({ path: included, hooksBase });
					}
				}
				if (entry.key === "core.hookspath") {
					const hooks = resolveHooksPath(entry.value, hooksBase, process.env.HOME ?? "");
					if (hooks) protectWritableDirectory(hooks);
				}
			}
		}

		const effectiveHooks = gitCommand(workspaceRoot, effective.sandbox.writableRoots, [
			"rev-parse",
			"--path-format=absolute",
			"--git-path",
			"hooks",
		]).trim();
		if (!effectiveHooks) throw new Error("pi-enclave: Git returned an empty effective hooks path");
		if (effectiveHooks !== "/dev/null") protectWritableDirectory(effectiveHooks);
	}
	return {
		mode: effective.sandbox.mode,
		writableRoots: [...effective.sandbox.writableRoots],
		writeDeny: [...new Set(writeDeny)],
		materializeWriteDeny: [...new Set(materializeWriteDeny)],
		materializeWriteDenyFiles: [...new Set(materializeWriteDenyFiles)],
		readDeny: [...effective.sandbox.readDeny],
		network: effective.sandbox.network.mode,
		allowPty: effective.sandbox.allowPty,
		envPassthrough: [...effective.sandbox.env.passthrough],
		envDeny: [...effective.sandbox.env.envDeny],
	};
}

export interface DevProfileOptions extends DefaultProfileOptions {
	/**
	 * PTY allocation. On by default: Seatbelt denies PTYs unless asked, which
	 * breaks `vim`, `less` and `git log` without a pager override. On Linux the
	 * field is informational only -- bubblewrap cannot deny PTYs.
	 */
	allowPty?: boolean;
}

/**
 * The zero-configuration profile, as a backend profile.
 *
 * Retained from Phase 1 for the benchmark and the conformance fixture, which
 * exercise the backend without a configuration file in sight. Sessions go
 * through `loadConfig` instead.
 */
export function createDevProfile(options: DevProfileOptions): Profile {
	const profile = toBackendProfile(defaultProfile(options), options.cwd);
	if (options.allowPty !== undefined) profile.allowPty = options.allowPty;
	return profile;
}
