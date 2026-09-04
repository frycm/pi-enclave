/**
 * Build the child's environment from an allowlist.
 *
 * Protecting `~/.aws` and pi's stored credentials on disk is pointless if
 * `ANTHROPIC_API_KEY` and `AWS_SECRET_ACCESS_KEY` arrive in the sandboxed shell
 * through `process.env`: `env`, variable expansion and every child process would
 * see them, and redirecting one into a file moves a credential into the writable
 * workspace for later disclosure.
 *
 * Neither pi nor sandbox-runtime closes this. pi's own sandbox example spawns
 * with inherited `process.env`, and SRT's `wrapWithSandboxArgv` returns
 * `process.env` plus its own additions -- 54 keys in the step-0 spike, including
 * `SSH_AUTH_SOCK` and every `CLAUDE_CODE_*` variable. So the backend ignores
 * both and passes what this module builds.
 *
 * That composes cleanly: SRT injects its own variables as an `env NAME=VALUE`
 * prefix inside the argv, so a strict allowlist handed to `spawn` keeps the
 * proxy configuration while leaking none of the parent's secrets. Verified in
 * step 0 on both backends, including `/proc/self/environ` on Linux.
 */
import { delimiter, isAbsolute } from "node:path";
import { canonical, isUnderAny } from "../backend/paths.ts";

/**
 * The only variables copied from the pi process by default. Everything else is
 * absent from the child's environment -- not unset-then-inherited, but never
 * present.
 */
export const CHILD_ENV_BASE = [
	"PATH",
	"HOME",
	"USER",
	"LOGNAME",
	"SHELL",
	"TERM",
	"LANG",
	"LC_ALL",
	"LC_CTYPE",
	"TZ",
	"TMPDIR",
	"XDG_CACHE_HOME",
	"XDG_CONFIG_HOME",
	"XDG_DATA_HOME",
	"COLORTERM",
	"NO_COLOR",
	"FORCE_COLOR",
	"CI",
] as const;

/**
 * Variables pi-enclave sets itself, regardless of the parent.
 *
 * `PYTHONDONTWRITEBYTECODE` is not cosmetic: without it every Python invocation
 * tries to write bytecode into its own read-only install directory, which
 * produced 62 spurious violations from a single call in the step-0 spike and
 * broke `multiprocessing` outright on macOS.
 */
export const CHILD_ENV_FORCED: Readonly<Record<string, string>> = {
	PYTHONDONTWRITEBYTECODE: "1",
};

/**
 * Names that never reach the child, applied last so neither `passthrough` nor a
 * future addition to the base list can leak one by mistake.
 *
 * Patterns are shell-style globs matched against the whole name,
 * case-sensitively -- environment variables are case-sensitive on POSIX, and a
 * case-insensitive match would surprise someone who deliberately named a
 * variable `my_token_count`.
 */
export const CREDENTIAL_DENY_PATTERNS = [
	"*_API_KEY",
	"*_SECRET*",
	"*SECRET_*",
	"*_TOKEN",
	"*PASSWORD*",
	"*CREDENTIAL*",
	"AWS_*",
	"GOOGLE_APPLICATION_CREDENTIALS",
	"AZURE_*",
	"OPENAI_*",
	"ANTHROPIC_*",
	"GH_TOKEN",
	"GITHUB_TOKEN",
	"NPM_TOKEN",
	"SSH_AUTH_SOCK",
	"GPG_AGENT_INFO",
	"KUBECONFIG",
	"DOCKER_HOST",
	"PI_*",
] as const;

/**
 * Compile a shell-style glob (asterisk only) into an anchored regex.
 *
 * The replacement is inserted verbatim rather than rescanned, so `*` can expand
 * straight to `.*` in the same pass that escapes the rest. An earlier version
 * went through a sentinel character to avoid a re-scan that never happens, and
 * the sentinel was a literal NUL -- which made git treat this whole file as
 * binary and hide it from every diff and review.
 */
export function globToRegExp(pattern: string): RegExp {
	const escaped = pattern.replace(/[.*+?^${}()|[\]\\]/g, (ch) => (ch === "*" ? ".*" : `\\${ch}`));
	return new RegExp(`^${escaped}$`);
}

const DENY_REGEXPS = CREDENTIAL_DENY_PATTERNS.map(globToRegExp);
const XDG_DIRECTORY_NAMES = new Set(["XDG_CACHE_HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME"]);

/** True when a variable name is forbidden by the credential deny list. */
export function isCredentialName(name: string, extraPatterns: readonly string[] = []): boolean {
	if (DENY_REGEXPS.some((re) => re.test(name))) return true;
	return extraPatterns.map(globToRegExp).some((re) => re.test(name));
}

export interface PassthroughDiagnostic {
	name: string;
	reason: string;
}

/**
 * Validate a user's `env.passthrough` list.
 *
 * A name matching the credential deny list is refused loudly at config load
 * rather than dropped quietly: someone who listed `FOO_TOKEN` believes it is
 * reaching the sandbox, and silently ignoring it would leave them debugging the
 * wrong thing. `buildChildEnv` applies the deny list again anyway -- this is the
 * diagnostic, not the enforcement.
 */
export function validatePassthrough(
	names: readonly string[],
	extraPatterns: readonly string[] = [],
): { accepted: string[]; rejected: PassthroughDiagnostic[] } {
	const accepted: string[] = [];
	const rejected: PassthroughDiagnostic[] = [];
	for (const name of names) {
		if (isCredentialName(name, extraPatterns)) {
			rejected.push({
				name,
				reason: `"${name}" matches the credential deny list and cannot be passed into the sandbox`,
			});
		} else {
			accepted.push(name);
		}
	}
	return { accepted, rejected };
}

export interface ChildEnvOptions {
	/**
	 * Extra names to copy from the parent. User-global configuration only: a
	 * project file cannot widen this (the monotonic rule), because a repository
	 * you have just cloned must not be able to name the variable it wants.
	 */
	passthrough?: readonly string[];
	/** Additional deny patterns. The default list can be extended, never shortened. */
	envDeny?: readonly string[];
	/** The child's `HOME`. The real home is not writable inside the sandbox. */
	home?: string;
	/** The child's `TMPDIR`, which must be one of the writable roots. */
	tmpdir?: string;
	/**
	 * Read-denied roots. PATH entries underneath one are dropped, so the child
	 * does not carry directory names it cannot use -- and so a PATH entry can
	 * never be the thing that reveals a denied location exists.
	 */
	readDeny?: readonly string[];
	/**
	 * Writable roots. Relative PATH entries and entries inside these roots are
	 * dropped so project-controlled executables cannot impersonate a command.
	 */
	writableRoots?: readonly string[];
}

/**
 * Construct the complete child environment.
 *
 * Order matters: base and passthrough are collected, pi-enclave's forced values
 * are applied, `HOME`/`TMPDIR` are rewritten to the sandbox's view, `PATH` is
 * filtered, and the credential deny list runs last over everything.
 */
export function buildChildEnv(
	parentEnv: Readonly<Record<string, string | undefined>>,
	options: ChildEnvOptions = {},
): Readonly<Record<string, string>> {
	const { passthrough = [], envDeny = [], home, tmpdir, readDeny = [], writableRoots = [] } = options;
	const env: Record<string, string> = {};

	for (const name of [...CHILD_ENV_BASE, ...passthrough]) {
		const value = parentEnv[name];
		if (typeof value !== "string") continue;
		// The XDG specification requires absolute base-directory values. Passing a
		// relative value would make the repository cwd choose where tools look for
		// configuration and credentials.
		if (XDG_DIRECTORY_NAMES.has(name) && !isAbsolute(value)) continue;
		env[name] = value;
	}

	Object.assign(env, CHILD_ENV_FORCED);

	// The sandbox's view of home and scratch space, not the host's.
	if (home !== undefined) env.HOME = home;
	if (tmpdir !== undefined) env.TMPDIR = tmpdir;

	if (env.PATH !== undefined) {
		const kept = env.PATH.split(delimiter).filter((entry) => {
			if (!entry || !isAbsolute(entry)) return false;
			const resolved = canonical(entry);
			return (
				!isUnderAny(entry, readDeny) &&
				!isUnderAny(resolved, readDeny) &&
				!isUnderAny(entry, writableRoots) &&
				!isUnderAny(resolved, writableRoots)
			);
		});
		if (kept.length > 0) env.PATH = kept.join(delimiter);
		else delete env.PATH;
	}

	// Applied last, over base, passthrough and forced alike.
	for (const name of Object.keys(env)) {
		if (isCredentialName(name, envDeny)) delete env[name];
	}

	return Object.freeze(env);
}
