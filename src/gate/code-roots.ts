/**
 * The code the trusted pi process loads, and whether the agent can change it
 * (#36).
 *
 * Everything else pi-enclave protects is data a later start reads: Git
 * configuration, `.pi`, the state directory. This is the code itself: pi,
 * pi-enclave and its dependencies, every other extension, the Node binary and
 * the seccomp helper. A change to any of it is inert in the running session
 * and runs with the user's privileges, outside every layer, the next time pi
 * starts. So none of it may sit below a writable root unless the user has
 * said so (`sandbox.allowSelfHosting`, user-global only), and then it is
 * write-denied at L2 so the session can read and test the code but cannot
 * change what the next start loads.
 *
 * A code root is a package root: the nearest ancestor with a `package.json`,
 * because a package loads its own files and its own `node_modules`. Every
 * existing `node_modules` directory above a root is a code root too, since
 * Node's resolution walks up through them. A `package.json` directly in the
 * home directory or at `/` does not make a package root: it is usually a stray
 * file, and treating it as one would make every workspace in the home
 * directory "inside loaded code".
 *
 * Limits, stated in the README: pi offers no list of loaded extensions, so an
 * extension that registers neither a tool nor a command is not seen; and an
 * `node_modules` directory that does not exist yet is not protected, so a
 * package a dependency loads only when it is present can still be planted.
 */
import { existsSync, lstatSync, readFileSync, statSync } from "node:fs";
import { createRequire } from "node:module";
import { homedir } from "node:os";
import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { canonical, isUnder, normalizePath } from "../backend/paths.ts";
import type { Profile } from "../backend/types.ts";

export interface CodeRoot {
	/** Canonical path. A directory, except for the Node binary, the helper and symlinks. */
	path: string;
	/** What loads from it, for the message. */
	from: string;
	/** A symlink the code is reached through, rather than the code itself. */
	link?: true;
	/**
	 * Why write-denying it is not enough, for a root the opt-in cannot
	 * accept: a symlink the configured path runs through, or the Node binary,
	 * which the native probe already refuses below the working directory.
	 */
	fixed?: string;
}

export interface CodeSources {
	/** This module's own file, `import.meta.url` of the extension entry. */
	ownSource: string;
	/** Entry files of pi-enclave's dependencies, resolved from its own package. */
	dependencyEntries: readonly string[];
	/** `process.argv[1]`: pi's entry script. */
	piEntry?: string;
	/** `sourceInfo.path` and `sourceInfo.baseDir` of every registered tool and command. */
	extensionPaths: readonly { path: string; from: string }[];
	execPath: string;
	seccompHelper: string | null;
	/** Where relative extension paths are resolved. */
	cwd: string;
	/** Injected by tests. */
	home?: string;
}

/** Synthetic `sourceInfo.path` values that name no file, such as `builtin:read`. */
function isSyntheticPath(path: string): boolean {
	return path.startsWith("builtin:") || path.startsWith("<");
}

function isDirectory(path: string): boolean {
	try {
		return statSync(path).isDirectory();
	} catch {
		return false;
	}
}

/**
 * The nearest ancestor of `path` (or `path` itself, for a directory) holding a
 * `package.json`, below the home directory and the filesystem root. Without
 * one, the directory itself.
 */
export function packageRootOf(path: string, home = homedir()): string {
	const real = canonical(path);
	const start = isDirectory(real) ? real : dirname(real);
	const stops = new Set([normalizePath(home), canonical(home), sep]);
	for (let dir = start; !stops.has(dir); dir = dirname(dir)) {
		if (existsSync(join(dir, "package.json"))) return dir;
		if (dirname(dir) === dir) break;
	}
	return start;
}

/** Every existing `node_modules` directory Node would search from `root` upwards. */
function resolutionDirs(root: string): string[] {
	const dirs: string[] = [];
	for (let dir = dirname(root); ; dir = dirname(dir)) {
		const candidate = join(dir, "node_modules");
		if (isDirectory(candidate)) dirs.push(canonical(candidate));
		if (dirname(dir) === dir) break;
	}
	return dirs;
}

/**
 * The entry files of pi-enclave's own dependencies and peer, resolved the way
 * its imports resolve. A dependency that does not resolve is skipped: what is
 * not installed is not loaded.
 */
export function resolveDependencyEntries(ownSource: string, home?: string): string[] {
	const root = packageRootOf(ownSource, home);
	let manifest: { dependencies?: Record<string, string>; peerDependencies?: Record<string, string> };
	try {
		manifest = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
	} catch {
		return [];
	}
	const names = new Set([...Object.keys(manifest.dependencies ?? {}), ...Object.keys(manifest.peerDependencies ?? {})]);
	const entries: string[] = [];
	// pi loads extensions through jiti, which provides `import.meta.resolve`;
	// a CommonJS transform without it falls back to `require` resolution.
	const require = createRequire(join(root, "package.json"));
	for (const name of names) {
		try {
			entries.push(
				typeof import.meta.resolve === "function" ? fileURLToPath(import.meta.resolve(name)) : require.resolve(name),
			);
		} catch {
			// Not installed, or no entry this resolver accepts.
		}
	}
	return entries;
}

/**
 * The symlinks between `root` and `path`, each a place where the agent could
 * point the configured path at other code.
 */
function linksBelow(path: string, roots: readonly string[]): string[] {
	const links: string[] = [];
	const lexical = normalizePath(path);
	for (const root of roots) {
		if (!isUnder(lexical, root)) continue;
		const parts = relative(normalizePath(root), lexical).split(sep).filter(Boolean);
		let current = normalizePath(root);
		for (const part of parts) {
			current = join(current, part);
			try {
				if (lstatSync(current).isSymbolicLink()) links.push(current);
			} catch {
				break;
			}
		}
	}
	return links;
}

/**
 * Every code root the process has loaded, canonical and without duplicates.
 * A root inside another is dropped in favour of the outer one, which is the
 * one that has to be protected or moved.
 */
export function collectCodeRoots(sources: CodeSources, writableRoots: readonly string[] = []): CodeRoot[] {
	const home = sources.home ?? homedir();
	const found: CodeRoot[] = [];
	const addPackage = (path: string, from: string) => {
		const root = packageRootOf(path, home);
		found.push({ path: root, from });
		for (const dir of resolutionDirs(root)) found.push({ path: dir, from: `module resolution for ${from}` });
	};
	const addLinks = (path: string, from: string) => {
		for (const link of linksBelow(path, writableRoots)) {
			found.push({
				path: link,
				from: `${from} (symlink)`,
				link: true,
				fixed: "the agent could point it at other code; load it by its real path",
			});
		}
	};

	addPackage(sources.ownSource, "pi-enclave");
	addLinks(sources.ownSource, "pi-enclave");
	for (const entry of sources.dependencyEntries) addPackage(entry, `pi-enclave dependency ${entry}`);
	if (sources.piEntry && existsSync(sources.piEntry)) {
		addPackage(sources.piEntry, "pi");
		addLinks(sources.piEntry, "pi");
	}
	for (const { path, from } of sources.extensionPaths) {
		if (isSyntheticPath(path)) continue;
		const absolute = isAbsolute(path) ? path : resolve(sources.cwd, path);
		// A package spec (`npm:...`) names no file; its baseDir is reported too.
		if (!existsSync(absolute)) continue;
		addPackage(absolute, from);
		addLinks(absolute, from);
	}
	found.push({
		path: canonical(sources.execPath),
		from: "the Node binary",
		fixed: "install Node outside the writable roots",
	});
	addLinks(sources.execPath, "the Node binary");
	if (sources.seccompHelper) found.push({ path: canonical(sources.seccompHelper), from: "the seccomp helper" });

	const unique = new Map<string, CodeRoot>();
	for (const root of found) if (!unique.has(root.path)) unique.set(root.path, root);
	const all = [...unique.values()];
	// Links are kept even inside another root: each is a separate way to swap
	// the code, which denying the root it sits in would not show.
	return all.filter(
		(root) =>
			root.link || !all.some((other) => !other.link && other.path !== root.path && isUnder(root.path, other.path)),
	);
}

export interface CodeRootCheck {
	/** Strictly below a writable root: write-denied with the opt-in, refused without. */
	exposed: CodeRoot[];
	/** Refused either way: it contains a writable root, or it is {@link CodeRoot.fixed}. */
	refused: { root: CodeRoot; reason: string }[];
}

export function checkCodeRoots(roots: readonly CodeRoot[], writableRoots: readonly string[]): CodeRootCheck {
	const writable = [...new Set(writableRoots.flatMap((root) => [normalizePath(root), canonical(root)]))];
	const exposed: CodeRoot[] = [];
	const refused: CodeRootCheck["refused"] = [];
	for (const root of roots) {
		const over = root.link ? undefined : writable.find((dir) => isUnder(dir, root.path));
		if (over !== undefined) {
			// Denying it would deny the whole workspace.
			refused.push({
				root,
				reason: `it contains the writable root ${over}; run pi from another worktree than the one it loads`,
			});
			continue;
		}
		if (!writable.some((dir) => isUnder(root.path, dir))) continue;
		if (root.fixed) refused.push({ root, reason: `it is below a writable root; ${root.fixed}` });
		else exposed.push(root);
	}
	return { exposed, refused };
}

/**
 * The refusal, or `undefined` when auto mode may start: with nothing exposed,
 * or with the opt-in and nothing it cannot accept.
 */
export function formatCodeRootProblems(check: CodeRootCheck, allowSelfHosting: boolean): string | undefined {
	const lines: string[] = [];
	for (const { root, reason } of check.refused) lines.push(`  ${root.path} (${root.from}): ${reason}.`);
	if (!allowSelfHosting) {
		for (const root of check.exposed) lines.push(`  ${root.path} (${root.from}) is below a writable root.`);
	}
	if (lines.length === 0) return undefined;
	return [
		"pi-enclave: refusing to start auto mode -- code this pi process loaded is agent-writable, " +
			"so a change to it would run outside the sandbox at the next start:",
		...lines,
		...(allowSelfHosting || check.exposed.length === 0
			? []
			: [
					"Load it from outside the writable roots, or set sandbox.allowSelfHosting in " +
						"~/.pi/agent/enclave.json to keep it read-only for the session instead.",
				]),
	].join("\n");
}

/**
 * The profile with every exposed root write-denied, and recorded for
 * `/enclave status`. Only called with the opt-in.
 */
export function applySelfHosting(profile: Profile, check: CodeRootCheck): Profile {
	if (check.exposed.length === 0) return profile;
	const paths = check.exposed.map((root) => root.path);
	return {
		...profile,
		writeDeny: [...new Set([...(profile.writeDeny ?? []), ...paths])],
		selfHosted: paths,
	};
}
