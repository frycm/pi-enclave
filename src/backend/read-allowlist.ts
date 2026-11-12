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
	/** Injected for tests. */
	exists?: (path: string) => boolean;
	resolve?: (path: string) => string;
}

/**
 * The directory that holds a binary, and the install root above it when the
 * binary sits in a `bin` directory. Never the home directory or `/`.
 */
function toolchainRoots(dir: string, home: string): string[] {
	const out = [dir];
	if (basename(dir) === "bin") {
		const root = dirname(dir);
		// ~/.local holds keyrings and every XDG application's data; its bin is
		// enough for the tools installed there.
		if (root !== "/" && root !== home && root !== dirname(home) && root !== join(home, ".local")) out.push(root);
	}
	return out;
}

/**
 * The roots that stay readable in allowlist mode, in a stable order and
 * without duplicates. Paths that do not exist are left out, because bwrap
 * cannot bind a missing source.
 */
export function allowlistReadRoots(input: ReadAllowlistInput): string[] {
	const exists = input.exists ?? existsSync;
	const resolve = input.resolve ?? canonical;
	const home = input.home ?? homedir();
	const system = input.platform === "darwin" ? DARWIN_SYSTEM_READ_ROOTS : LINUX_SYSTEM_READ_ROOTS;
	const candidates: string[] = [...system, ...input.profile.writableRoots];

	const binaries = [input.execPath, ...(input.hostTools ?? [])].filter((p): p is string => Boolean(p));
	for (const binary of binaries) {
		candidates.push(...toolchainRoots(dirname(binary), home));
		// A symlinked binary (nvm, Homebrew, a version manager shim) needs its
		// real home readable too, not only the link.
		const real = resolve(binary);
		if (real !== binary) candidates.push(...toolchainRoots(dirname(real), home));
	}
	candidates.push(dirname(input.helperPath));
	for (const entry of input.path.split(":")) {
		if (!entry || !isAbsolute(entry)) continue;
		candidates.push(...toolchainRoots(entry, home));
	}
	candidates.push(...(input.profile.readAllow ?? []));

	// sandbox-runtime lets an allow entry override a deny at or above it, so
	// a root at or below a deny entry would lift that deny. Such a root is
	// left out: the deny list is the one thing allowlist mode never loosens.
	const denied = (input.profile.readDeny ?? []).flatMap((entry) => [entry, resolve(entry)]);
	const out: string[] = [];
	const seen = new Set<string>();
	for (const candidate of candidates) {
		if (!isAbsolute(candidate)) continue;
		const path = candidate.replace(/\/+$/, "") || "/";
		if (path === "/" || path === home) continue;
		if (!exists(path)) continue;
		// The canonical form too: bwrap and Seatbelt both match the resolved path,
		// so an allow spelled through a link would otherwise allow nothing.
		for (const spelling of new Set([path, resolve(path)])) {
			if (spelling === "/" || spelling === home || seen.has(spelling)) continue;
			// A root that would expose the home directory's parent (`/home`,
			// `/Users`) exposes every other user's home too.
			if (isUnder(home, spelling)) continue;
			if (denied.some((entry) => isUnder(spelling, entry))) continue;
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
	const roots = [...(profile.readAllow ?? []), ...profile.writableRoots].filter((root) => !links.includes(root));
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
