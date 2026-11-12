/**
 * The read allowlist for `sandbox.readMode: "allowlist"` (#23).
 *
 * In the default `open` mode the native backends deny reads only from a list,
 * so anything nobody thought to list -- a sibling project's `.env`, a database
 * dump in `~/Downloads`, a credential store with a new name -- is readable and,
 * with network off, can still end up in the model's context. In `allowlist`
 * mode the whole filesystem is denied and only these roots are readable:
 *
 * - the system runtime (`/usr`, `/etc`, `/lib*` and the rest on Linux, the
 *   `/System`, `/usr`, `/Library` family on macOS), so shells, interpreters
 *   and their shared libraries keep working;
 * - the writable roots: the workspace and the session scratch;
 * - the toolchain the session is using: the Node running pi-enclave, the
 *   probed `rg`, `fd` and seccomp helper, and every absolute `PATH` entry
 *   (with the install root above a `bin` directory, where `lib` and `share`
 *   usually live);
 * - pi-enclave's own file helper, which runs inside the sandbox;
 * - the configured `sandbox.readableRoots`.
 *
 * `readDeny` still applies inside every one of them: sandbox-runtime applies
 * the deeper deny after the allow, on both bwrap and Seatbelt. So a `PATH`
 * entry under `~/.cargo` makes `~/.cargo` readable but not
 * `~/.cargo/credentials.toml`.
 *
 * The home directory itself is never added, nor `/`, however it is reached:
 * a `PATH` entry of `~/bin` exposes `~/bin`, not `~`.
 */

import { existsSync } from "node:fs";
import { homedir } from "node:os";
import { basename, dirname, isAbsolute, join } from "node:path";
import { canonical, isUnder, isUnderAny } from "./paths.ts";
import type { ChildEnv, Profile } from "./types.ts";

/** Readable on every Linux host: the runtime, its configuration and its libraries. */
export const LINUX_SYSTEM_READ_ROOTS = [
	"/usr",
	"/bin",
	"/sbin",
	"/lib",
	"/lib32",
	"/lib64",
	"/libx32",
	"/etc",
	// NixOS and nix-on-anything keep the whole userland here.
	"/nix",
	"/run/current-system",
] as const;

/** Readable on every macOS host. `/dev` is the null device, ttys and urandom. */
export const DARWIN_SYSTEM_READ_ROOTS = [
	"/System",
	"/usr",
	"/bin",
	"/sbin",
	"/Library",
	"/private/etc",
	"/etc",
	"/dev",
	// /etc/localtime points here; the dyld cache and the shells live under
	// /System. /var/select/sh picks the shell /bin/sh runs.
	"/private/var/db/timezone",
	"/private/var/select",
	// Where xcode-select points /usr/bin/git and the other developer shims.
	"/private/var/db/xcode_select_link",
	"/var/select",
	"/Applications/Xcode.app",
	"/opt/homebrew",
] as const;

/**
 * macOS's top-level links into /private. Following a link is a read of the
 * link itself, and Seatbelt only lets metadata reads through on directories,
 * so with these denied every path spelled through them -- the workspace under
 * `$TMPDIR` (`/var/folders/...`), anything in /tmp -- fails with EPERM even
 * when its target is allowed. Each is allowed by its own name and never
 * resolved: `/var` matches only the link (nothing real lives under that
 * spelling), whereas `/private/var` would expose everything behind it.
 */
export const DARWIN_SYSTEM_READ_LINKS = ["/var", "/tmp"] as const;

/** Readable inside the sandbox whatever the read mode: sandbox-runtime skips them when it denies `/`. */
const ALWAYS_MOUNTED = ["/proc", "/sys", "/dev"] as const;

export interface ReadAllowlistInput {
	profile: Pick<Profile, "writableRoots" | "readAllow" | "readDeny">;
	platform: NodeJS.Platform;
	/** The `PATH` sandboxed commands search. */
	path: string;
	/** The Node binary that runs the file helper. */
	execPath: string;
	/** pi-enclave's file helper script, which runs inside the sandbox. */
	helperPath: string;
	/** Host tools the sandbox runs: rg, fd, the seccomp helper. */
	hostTools?: readonly (string | undefined)[];
	home?: string;
	/** For the XDG base directories; `process.env` by default. */
	env?: NodeJS.ProcessEnv;
	/** Injected for tests. */
	exists?: (path: string) => boolean;
	resolve?: (path: string) => string;
}

/**
 * The directory that holds a binary, and the install root above it when the
 * binary sits in a `bin` directory. Whether either may be added is decided
 * later, on its canonical location.
 */
function toolchainRoots(dir: string): { path: string; installRoot: boolean }[] {
	const out = [{ path: dir, installRoot: false }];
	if (basename(dir) === "bin") out.push({ path: dirname(dir), installRoot: true });
	return out;
}

/**
 * The directories an install-root climb must not reach, as canonical paths:
 * the stores of every application's configuration, data and caches, which a
 * `bin` directory inside them (`~/.config/bin`, `~/Library/bin`) would
 * otherwise expose whole.
 */
function sharedStores(home: string, env: NodeJS.ProcessEnv, resolve: (path: string) => string): string[] {
	const xdg = ["XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME", "XDG_STATE_HOME"]
		.map((name) => env[name])
		.filter((value): value is string => Boolean(value) && isAbsolute(value as string));
	return [".local", ".local/share", ".local/state", ".config", ".cache", "Library", ...xdg].map((entry) =>
		resolve(isAbsolute(entry) ? entry : join(home, entry)),
	);
}

/**
 * The roots that stay readable in allowlist mode, in a stable order and
 * without duplicates. Paths that do not exist are left out, because bwrap
 * cannot bind a missing source.
 *
 * Every exclusion is judged on the candidate's canonical location, because
 * that is what the sandbox binds: sandbox-runtime resolves the parents of an
 * allow entry, so a spelling through a link that passes by name would land
 * on the very place it was meant to keep out (a home reached through a link,
 * a `PATH` entry spelled through one into a denied directory). A candidate
 * that fails is dropped in every spelling.
 */
export function allowlistReadRoots(input: ReadAllowlistInput): string[] {
	const exists = input.exists ?? existsSync;
	const resolve = input.resolve ?? canonical;
	const home = input.home ?? homedir();
	const homes = [...new Set([home, resolve(home)])];
	const system = input.platform === "darwin" ? DARWIN_SYSTEM_READ_ROOTS : LINUX_SYSTEM_READ_ROOTS;
	const stores = new Set(homes.flatMap((h) => sharedStores(h, input.env ?? process.env, resolve)));
	const candidates: { path: string; installRoot: boolean }[] = [
		...[...system, ...input.profile.writableRoots].map((path) => ({ path, installRoot: false })),
	];

	const binaries = [input.execPath, ...(input.hostTools ?? [])].filter((p): p is string => Boolean(p));
	for (const binary of binaries) {
		candidates.push(...toolchainRoots(dirname(binary)));
		// A symlinked binary (nvm, Homebrew, a version manager shim) needs its
		// real home readable too, not only the link.
		const real = resolve(binary);
		if (real !== binary) candidates.push(...toolchainRoots(dirname(real)));
	}
	candidates.push({ path: dirname(input.helperPath), installRoot: false });
	for (const entry of input.path.split(":")) {
		if (!entry || !isAbsolute(entry)) continue;
		candidates.push(...toolchainRoots(entry));
	}
	candidates.push(...(input.profile.readAllow ?? []).map((path) => ({ path, installRoot: false })));

	// sandbox-runtime lets an allow entry override a deny at or above it, so
	// a root at or below a deny entry would lift that deny. Such a root is
	// left out: the deny list is the one thing allowlist mode never loosens.
	const denied = [...new Set((input.profile.readDeny ?? []).flatMap((entry) => [entry, resolve(entry)]))];
	const excluded = (real: string, installRoot: boolean): boolean =>
		real === "/" ||
		// The home directory, and anything that contains it (`/home`, `/Users`),
		// which would expose every other user's home too.
		homes.some((h) => isUnder(h, real)) ||
		denied.some((entry) => isUnder(real, entry)) ||
		// An install root is a guess; never let it be a top-level directory or
		// a store every application shares.
		(installRoot && (dirname(real) === "/" || stores.has(real)));

	const out: string[] = [];
	const seen = new Set<string>();
	for (const candidate of candidates) {
		if (!isAbsolute(candidate.path)) continue;
		const path = candidate.path.replace(/\/+$/, "") || "/";
		if (!exists(path)) continue;
		const real = resolve(path);
		if (excluded(real, candidate.installRoot) || excluded(path, candidate.installRoot)) continue;
		// The canonical form too: bwrap and Seatbelt both match the resolved path,
		// so an allow spelled through a link would otherwise allow nothing.
		for (const spelling of new Set([path, real])) {
			if (seen.has(spelling)) continue;
			seen.add(spelling);
			out.push(spelling);
		}
	}
	if (input.platform === "darwin") {
		for (const link of DARWIN_SYSTEM_READ_LINKS) {
			if (!seen.has(link) && !denied.some((entry) => isUnder(link, entry))) out.push(link);
		}
	}
	return out;
}

/**
 * The environment a sandboxed command runs with in allowlist mode.
 *
 * Git refuses to run when its user configuration exists but cannot be read,
 * and Seatbelt answers a denied read with EPERM rather than ENOENT, so on
 * macOS every git command would die on `~/.gitconfig`. Unless the user made
 * their git configuration readable with `sandbox.readableRoots`, git is told
 * there is none -- which is also what it sees on Linux, where a denied home
 * is an empty directory.
 */
export function withAllowlistGitConfig(
	profile: Pick<Profile, "readMode" | "readAllow" | "writableRoots">,
	env: ChildEnv,
	home = homedir(),
): ChildEnv {
	if (profile.readMode !== "allowlist" || env.GIT_CONFIG_GLOBAL !== undefined) return env;
	const readable = [...(profile.readAllow ?? []), ...profile.writableRoots];
	const xdg = env.XDG_CONFIG_HOME && isAbsolute(env.XDG_CONFIG_HOME) ? env.XDG_CONFIG_HOME : join(home, ".config");
	const userConfig = [join(home, ".gitconfig"), join(xdg, "git", "config")];
	if (userConfig.some((path) => isUnderAny(path, readable))) return env;
	return { ...env, GIT_CONFIG_GLOBAL: "/dev/null" };
}

/**
 * Is `path` readable under this profile's read mode, as far as the policy is
 * concerned? Used to classify a refused read as a sandbox denial.
 */
export function outsideReadAllowlist(
	path: string,
	profile: Pick<Profile, "readMode" | "readAllow" | "writableRoots">,
): boolean {
	if (profile.readMode !== "allowlist") return false;
	// Judged on the canonical path, as the kernel judges it, and without the
	// macOS link names: `/var` lets the link be followed, it does not make
	// `/var/folders/...` readable.
	const links: readonly string[] = DARWIN_SYSTEM_READ_LINKS;
	const roots = [
		...(profile.readAllow ?? []),
		...profile.writableRoots,
		// Mounted by sandbox-runtime itself and never denied, so a missing file
		// there is an ordinary error, not a refusal.
		...ALWAYS_MOUNTED,
	].filter((root) => !links.includes(root));
	return !isUnderAny(canonical(path), roots);
}

/**
 * The profile a one-call read capability runs under: the exact deny entry
 * lifted and, in allowlist mode, its target added to the allowlist, since
 * lifting a deny inside a region that is not allowed would expose nothing.
 */
export function withReadCapability(profile: Profile, target: string): Profile {
	return {
		...profile,
		readDeny: profile.readDeny.filter((entry) => canonical(entry) !== target),
		...(profile.readMode === "allowlist" ? { readAllow: [...(profile.readAllow ?? []), target] } : {}),
	};
}
