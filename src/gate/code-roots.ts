/**
 * The code the trusted pi process loads, and whether the agent can change it
 * (#36).
 *
 * Everything else pi-enclave protects is data a later start reads: Git
 * configuration, `.pi`, the state directory. This is the code itself: pi,
 * pi-enclave and its dependencies, every other extension, the Node binary,
 * the seccomp helper and the `attended.notify` program (#30), which the pi
 * process runs whenever it writes an approval record. A change to any of it is inert in the running session
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
 * Symlinked packages in any collected `node_modules` (npm workspaces,
 * `npm link`) are followed to their targets, transitively. With the opt-in,
 * a `node_modules` that does not exist between an exposed root and its
 * writable root is created read-only, since one created there would shadow
 * the dependencies the root resolves from further up.
 *
 * Limit, stated in the README: pi offers no list of loaded extensions. An
 * extension that registers neither a tool nor a command and was not named
 * with `-e`/`--extension` (one listed in `settings.json`, for example) is not
 * seen.
 */
import { type Dirent, existsSync, lstatSync, readdirSync, readFileSync, statSync } from "node:fs";
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
	/** `attended.notify[0]`, the program the pi process runs for a new record (#30). */
	notifyProgram?: string;
	/** Where relative extension paths are resolved. */
	cwd: string;
	/** Injected by tests. */
	home?: string;
}

/** The values of `-e`/`--extension` on pi's command line. */
export function extensionArguments(argv: readonly string[]): string[] {
	const values: string[] = [];
	for (let i = 0; i < argv.length; i++) {
		const arg = argv[i] as string;
		if ((arg === "-e" || arg === "--extension") && argv[i + 1] !== undefined) values.push(argv[++i] as string);
		else if (arg.startsWith("--extension=")) values.push(arg.slice("--extension=".length));
	}
	return values;
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

/** The symlinked packages directly in a `node_modules` directory, `@scope/*` included. */
function linkedPackages(dir: string): string[] {
	const list = (path: string): Dirent[] => {
		try {
			return readdirSync(path, { withFileTypes: true });
		} catch {
			return [];
		}
	};
	const links: string[] = [];
	for (const entry of list(dir)) {
		if (entry.name === ".bin") continue;
		const path = join(dir, entry.name);
		if (entry.isSymbolicLink()) links.push(path);
		else if (entry.name.startsWith("@") && entry.isDirectory()) {
			for (const scoped of list(path)) if (scoped.isSymbolicLink()) links.push(join(path, scoped.name));
		}
	}
	return links;
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
	// `node_modules` directories still to look through for symlinked packages.
	const pending: string[] = [];
	const addPackage = (path: string, from: string) => {
		const root = packageRootOf(path, home);
		found.push({ path: root, from });
		// A package's own node_modules can itself be a symlink to elsewhere.
		const own = canonical(join(root, "node_modules"));
		if (isDirectory(own) && !isUnder(own, root)) found.push({ path: own, from: `dependencies of ${from}` });
		pending.push(own);
		for (const dir of resolutionDirs(root)) {
			found.push({ path: dir, from: `module resolution for ${from}` });
			pending.push(dir);
		}
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
	if (sources.notifyProgram) {
		// Run by the trusted process on every ask, so like the Node binary:
		// write-denying it for the session is not enough, it has to move.
		found.push({
			path: canonical(sources.notifyProgram),
			from: "the attended.notify program",
			fixed: "install it, and anything it loads, outside the writable roots",
		});
		addLinks(sources.notifyProgram, "the attended.notify program");
	}

	// An npm workspace or `npm link` puts a symlink in `node_modules` and the
	// code elsewhere, so a collected directory does not contain everything it
	// resolves to. Follow every symlinked package to its target, and the
	// target's own `node_modules`, until nothing new appears. A target inside a
	// root already collected adds nothing (pnpm's links stay in `.pnpm`).
	const scanned = new Set<string>();
	while (pending.length > 0) {
		const dir = canonical(pending.shift() as string);
		if (scanned.has(dir) || !isDirectory(dir)) continue;
		scanned.add(dir);
		for (const link of linkedPackages(dir)) {
			const target = canonical(link);
			if (!isDirectory(target)) continue;
			if (found.some((root) => !root.link && root.path !== canonical(sources.execPath) && isUnder(target, root.path))) {
				continue;
			}
			addPackage(target, `package linked from ${link}`);
		}
	}

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
	/**
	 * `node_modules` directories that do not exist between an exposed root and
	 * its writable root. Node searches each on the way up, so one created there
	 * would shadow a dependency the root resolves from further up. With the
	 * opt-in they are created read-only.
	 */
	missing: string[];
}

export function checkCodeRoots(roots: readonly CodeRoot[], writableRoots: readonly string[]): CodeRootCheck {
	const writable = [...new Set(writableRoots.flatMap((root) => [normalizePath(root), canonical(root)]))];
	const exposed: CodeRoot[] = [];
	const refused: CodeRootCheck["refused"] = [];
	const missing = new Set<string>();
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
	for (const root of exposed) {
		if (!isDirectory(root.path)) continue;
		const top = writable.filter((dir) => isUnder(root.path, dir)).sort((a, b) => a.length - b.length)[0] as string;
		for (let dir = dirname(root.path); isUnder(dir, top); dir = dirname(dir)) {
			const candidate = join(dir, "node_modules");
			if (candidate === root.path) continue;
			let stat: ReturnType<typeof lstatSync> | undefined;
			try {
				stat = lstatSync(candidate);
			} catch {
				missing.add(candidate);
			}
			// An existing directory is a resolution directory, collected above.
			// A symlink there could be pointed at other code.
			if (stat?.isSymbolicLink()) {
				refused.push({
					root: { path: candidate, from: `module resolution for ${root.from}`, link: true },
					reason: "it is a symlink below a writable root; replace it with a directory",
				});
			}
			if (dir === top) break;
		}
	}
	return { exposed, refused, missing: [...missing].filter((dir) => !exposed.some((root) => isUnder(dir, root.path))) };
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
 * The profile with every loaded code root on the never-grantable write list (#21).
 *
 * A one-shot write capability to pi-enclave's package, its node_modules or
 * pi's own package would run the agent's code in the pi process at the next
 * start, which is the same trust-root problem as a write below a writable root.
 */
export function protectLoadedCode(profile: Profile, roots: readonly CodeRoot[]): Profile {
	if (roots.length === 0) return profile;
	return {
		...profile,
		protectedWrite: [
			...(profile.protectedWrite ?? []),
			...roots.map((root) => ({
				path: root.path,
				reason: `pi loads code from it (${root.from}) in its own process, outside the sandbox`,
			})),
		],
	};
}

/**
 * The profile with every exposed root write-denied, and recorded for
 * `/enclave status`. Only called with the opt-in.
 */
export function applySelfHosting(profile: Profile, check: CodeRootCheck): Profile {
	if (check.exposed.length === 0) return profile;
	const paths = [...check.exposed.map((root) => root.path), ...check.missing];
	return {
		...profile,
		writeDeny: [...new Set([...(profile.writeDeny ?? []), ...paths])],
		// bwrap can only deny a path that exists, so a missing node_modules is
		// created read-only, as `.pi` is.
		materializeWriteDeny: [...new Set([...(profile.materializeWriteDeny ?? []), ...check.missing])],
		selfHosted: paths,
	};
}
