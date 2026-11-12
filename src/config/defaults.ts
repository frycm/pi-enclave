/**
 * The built-in defaults: what `"$defaults"` splices, and the profile a user who
 * writes no configuration at all gets.
 *
 * Every list here is the *whole* of its boundary, so each entry is a claim that
 * has to hold on its own. The pattern lists in particular are deliberately
 * short. The Anthropic argument against hand-written command lists is that they
 * are error-prone and give false confidence, and it applies to ours too: the
 * only things that belong in `rules.deny` are the ones that must hold under
 * adversarial input *and* that the sandbox cannot already enforce. Everything
 * else is either a sandbox boundary or a judgement call for the prose rulebook
 * a reviewer reads.
 */
import { homedir } from "node:os";
import { isAbsolute, join } from "node:path";
import { getAgentDir } from "@earendil-works/pi-coding-agent";
import { DEFAULT_CONTAINER_LIMITS } from "../backend/limits.ts";
import type {
	AttendedSettings,
	AuditSettings,
	BreakerSettings,
	EffectiveProfile,
	LimitsSettings,
	ProtectedWriteTarget,
	ReviewerSettings,
	ToolsSettings,
} from "./types.ts";

/**
 * Paths denied for reading by default.
 *
 * Reads are a deny-list on both backends -- there is no way to say "only the
 * workspace is readable" -- so this list is the whole of the read boundary, and
 * anything absent from it is readable by the agent. It covers credential stores
 * an agent has no business reading, including pi's own, so a task cannot
 * exfiltrate the key that is running it.
 */
export function defaultReadDeny(
	home = homedir(),
	agentDir = getAgentDir(),
	env: Readonly<Record<string, string | undefined>> = process.env,
): string[] {
	const xdgConfig = env.XDG_CONFIG_HOME;
	const configRoots = [join(home, ".config")];
	// XDG base-directory values are paths only when absolute. Never resolve a
	// relative value against the repository: that would turn untrusted cwd into
	// authorization data. Keep the conventional root as well, because stale
	// credentials there remain sensitive after a migration.
	if (xdgConfig && isAbsolute(xdgConfig)) configRoots.push(xdgConfig);

	return [
		...new Set([
			// pi's *live* credential storage. pi resolves its agent directory from
			// PI_CODING_AGENT_DIR, so the default path below is only where auth.json
			// usually is; this entry is where it actually is. The child never sees the
			// variable, but the file is on disk regardless, and an agent that can read
			// it can spend the account running it.
			join(agentDir, "auth.json"),
			// Pi 1.1 stores MCP OAuth tokens separately; server configuration may
			// also contain literal authorization headers or environment secrets.
			join(agentDir, "mcp-auth.json"),
			join(agentDir, "mcp.json"),
			// pi-enclave's own state: pending approval records, the audit log, and the
			// attendance secret. The pending records are the one place "what a human
			// approved" is persisted, and the secret is the whole of the RPC
			// attendance proof -- an agent that can read either can forge the other
			// side of an escalation. `merge.ts` additionally refuses any profile that
			// makes this directory writable.
			enclaveStateDir(agentDir),
			join(home, ".ssh"),
			join(home, ".aws"),
			join(home, ".gnupg"),
			join(home, ".kube"),
			join(home, ".docker"),
			...configRoots.map((root) => join(root, "gh")),
			join(home, ".netrc"),
			join(home, ".npmrc"),
			// The default agent directory, kept even when the live one is elsewhere:
			// a stale auth.json at the default path is still a credential.
			join(home, ".pi", "agent", "auth.json"),
			join(home, ".pi", "agent", "mcp-auth.json"),
			join(home, ".pi", "agent", "mcp.json"),
			join(home, ".pi", "auth.json"),
			// Sibling agents' stored credentials, for the same reason.
			join(home, ".claude", ".credentials.json"),
			...configRoots.map((root) => join(root, "claude")),
			// What a server keeps besides SSH keys (#23). A deny-list is always one
			// entry short, which is why `sandbox.readMode: "allowlist"` exists; this
			// list is what `open` mode can still do.
			...credentialStores(home, configRoots),
			// pi's own records: other projects' transcripts, the trust store, and the
			// policy itself, which is the first thing an adversary would read.
			join(agentDir, "sessions"),
			join(agentDir, "trust.json"),
			join(agentDir, "enclave.json"),
			join(home, ".pi", "agent", "sessions"),
			// Secrets a server exposes outside any home directory.
			...SERVER_READ_DENY,
		]),
	];
}

/** Server-side material readable by the agent's uid more often than it should be. */
const SERVER_READ_DENY = [
	"/etc/letsencrypt",
	"/etc/ssl/private",
	"/run/secrets",
	"/var/run/secrets",
	"/run/credentials",
];

/** Credential, history and other-agent files under a home directory (#23). */
function credentialStores(home: string, configRoots: readonly string[]): string[] {
	const inHome = [
		// Git and forge credentials.
		".git-credentials",
		// Cloud CLIs and secret managers.
		".azure",
		".oci",
		".terraform.d/credentials.tfrc.json",
		".terraformrc",
		".vault-token",
		".password-store",
		// Package registries.
		".pypirc",
		".cargo/credentials.toml",
		".cargo/credentials",
		".gem/credentials",
		".m2/settings.xml",
		".gradle/gradle.properties",
		".composer/auth.json",
		".yarnrc.yml",
		// Databases and services.
		".pgpass",
		".my.cnf",
		".mylogin.cnf",
		".redis-cli-auth",
		// Keyrings and keychains.
		".local/share/keyrings",
		"Library/Keychains",
		// Shell and REPL histories: commands typed with secrets in them.
		".bash_history",
		".zsh_history",
		".histfile",
		".local/share/fish/fish_history",
		".python_history",
		".psql_history",
		".mysql_history",
		".sqlite_history",
		".node_repl_history",
		".rediscli_history",
		".lesshst",
		// Other agents and editors, which keep their own tokens and transcripts.
		".codex",
		".gemini",
		".cursor",
		".continue",
		".aider",
		// Browser profiles: cookies are sessions.
		".mozilla",
		".config/google-chrome",
		".config/chromium",
		".config/BraveSoftware",
		"Library/Application Support/Google/Chrome",
		"Library/Application Support/Firefox",
		"Library/Cookies",
		"Library/Safari",
	].map((path) => join(home, path));
	const inConfig = [
		"git/credentials",
		"glab-cli",
		"hub",
		"tea",
		"gcloud",
		"doctl",
		"hcloud",
		"sops",
		"age",
		"rclone",
		"pip",
		"op",
		"github-copilot",
		"Code/User/globalStorage",
	];
	return [...inHome, ...configRoots.flatMap((root) => inConfig.map((path) => join(root, path)))];
}

/**
 * Paths a one-shot write capability may never target, whoever approves it (#21).
 *
 * The write-side counterpart of the immutable built-in read denials. Each one is
 * part of the trust boundary itself: pi-enclave's policy, code pi loads at the
 * next start, or code the user's own shell, Git, login session or service
 * manager runs outside any sandbox. One approval of a request that looks like
 * "let me fix a setting" must not hand any of that over. Credentials (`~/.ssh`
 * and friends) are covered separately, through `readDeny`.
 *
 * Not configurable, and checked whether or not the path exists: creating the
 * file is the attack.
 */
export function protectedWriteTargets(
	home = homedir(),
	agentDir = getAgentDir(),
	env: Readonly<Record<string, string | undefined>> = process.env,
): ProtectedWriteTarget[] {
	const xdgConfig = env.XDG_CONFIG_HOME;
	const configRoots = [join(home, ".config")];
	if (xdgConfig && isAbsolute(xdgConfig)) configRoots.push(xdgConfig);
	const policy = "it holds pi's configuration, including pi-enclave's own policy and the code pi loads at start";
	const shell = "the user's shell or login session runs it outside any sandbox";
	const git = "Git reads it outside the sandbox, and aliases, hooks, core.fsmonitor or core.sshCommand there run code";
	const service = "the user's service manager or desktop session starts what it lists, outside any sandbox";
	const bin = "it is a conventional user PATH directory, so a file there runs as a command outside the sandbox";
	const editor = "the editor runs it when the user next opens a file";
	const toolchain = "a language toolchain or version manager outside the sandbox loads or runs code from it";
	const targets: ProtectedWriteTarget[] = [
		// pi's agent directory as a whole: enclave.json, settings.json, trust.json,
		// models.json, extensions/, packages/, skills/, prompts/, themes/.
		{ path: agentDir, reason: policy },
		{ path: join(home, ".pi"), reason: policy },
		...[
			".bashrc",
			".bash_profile",
			".bash_login",
			".bash_logout",
			".profile",
			".zshrc",
			".zshenv",
			".zprofile",
			".zlogin",
			".zlogout",
			".cshrc",
			".tcshrc",
			".login",
			".kshrc",
			".mkshrc",
			".xprofile",
			".xinitrc",
			".xsession",
			".xsessionrc",
			".pam_environment",
			".envrc",
			".inputrc",
			".bash_aliases",
			".bashrc.d",
			".oh-my-zsh",
			".zsh",
			".tmux.conf",
			".pythonrc",
			".gdbinit",
		].map((name) => ({ path: join(home, name), reason: shell })),
		...configRoots.flatMap((root) => [
			{ path: join(root, "fish"), reason: shell },
			{ path: join(root, "environment.d"), reason: shell },
			{ path: join(root, "git"), reason: git },
			{ path: join(root, "systemd"), reason: service },
			{ path: join(root, "autostart"), reason: service },
			{ path: join(root, "nvim"), reason: editor },
			{ path: join(root, "zsh"), reason: shell },
			{ path: join(root, "direnv"), reason: shell },
			{ path: join(root, "tmux"), reason: shell },
			{ path: join(root, "pip"), reason: toolchain },
		]),
		{ path: join(home, ".gitconfig"), reason: git },
		{ path: join(home, "Library", "LaunchAgents"), reason: service },
		{ path: join(home, ".local", "share", "systemd"), reason: service },
		{ path: join(home, ".local", "bin"), reason: bin },
		{ path: join(home, "bin"), reason: bin },
		{ path: join(home, ".cargo"), reason: toolchain },
		{ path: join(home, "go", "bin"), reason: bin },
		{ path: join(home, ".npm-global"), reason: bin },
		{ path: join(home, ".deno", "bin"), reason: bin },
		{ path: join(home, ".bun", "bin"), reason: bin },
		{ path: join(home, ".yarn", "bin"), reason: bin },
		{ path: join(home, ".local", "share", "pnpm"), reason: bin },
		{ path: join(home, ".local", "lib"), reason: toolchain },
		{ path: join(home, ".local", "share", "applications"), reason: service },
		...[".nvm", ".pyenv", ".rbenv", ".asdf", ".volta"].map((name) => ({ path: join(home, name), reason: toolchain })),
		{ path: join(home, ".vimrc"), reason: editor },
		{ path: join(home, ".vim"), reason: editor },
		{ path: join(home, ".emacs"), reason: editor },
		{ path: join(home, ".emacs.d"), reason: editor },
		// Crontab spools. Usually root-owned, listed so a misconfigured host does
		// not depend on that.
		...["/var/spool/cron", "/var/spool/cron/crontabs", "/var/at/tabs", "/usr/lib/cron/tabs"].map((path) => ({
			path,
			reason: "cron runs what it lists as the user, outside any sandbox",
		})),
	];
	const seen = new Set<string>();
	return targets.filter((target) => !seen.has(target.path) && seen.add(target.path) !== undefined);
}

/** pi-enclave's own state directory: audit log, pending records, attendance secret. */
export function enclaveStateDir(agentDir = getAgentDir()): string {
	return join(agentDir, "enclave");
}

/**
 * Credential-shaped environment names, stripped from the child last.
 *
 * Applied after `passthrough`, so neither a passthrough entry nor a future
 * addition to the base list can leak by mistake. `*` is the only wildcard.
 */
export const DEFAULT_ENV_DENY: readonly string[] = [
	"*_API_KEY",
	"*_SECRET*",
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
];

/**
 * Pattern denials. Nothing below can override a match.
 *
 * Each entry is here because the sandbox cannot express it, not because it
 * looks dangerous. Reading a credential file is absent: `readDeny` already
 * denies it at the kernel, and a pattern rule would only catch the spellings
 * someone thought of.
 */
export const DEFAULT_RULES_DENY: readonly string[] = [
	// Creating or relocating Git metadata establishes a privileged hook consumer
	// that is absent from the profile compiled for this session. A person can do
	// this deliberately through direct `!` input; the next agent call then starts
	// under a newly compiled profile that protects the resulting metadata.
	"bash(git init*)",
	"bash(git clone*)",
	"bash(git worktree add*)",
	"bash(git worktree move*)",
	"bash(git worktree repair*)",
	"bash(git submodule add*)",
	"bash(git submodule update*--init*)",
	"bash(git submodule absorbgitdirs*)",
	// Privilege escalation. The sandbox denies these too, but a pattern denial
	// names the outcome to the agent instead of surfacing a bare EPERM it will
	// try to work around.
	"bash(sudo *)",
	"bash(su *)",
	"bash(doas *)",
	// Disabling transport security, which no task legitimately needs and which
	// no filesystem boundary can see.
	"bash(* --no-check-certificate*)",
	"bash(curl *-k *)",
	"bash(curl *--insecure*)",
	"bash(git config *sslVerify false*)",
	"bash(npm config set strict-ssl false*)",
	// Persistence and machine-level configuration: outside any workspace, and
	// outcomes rather than file writes.
	"bash(crontab *)",
	"bash(launchctl load*)",
	"bash(launchctl bootstrap*)",
	"bash(systemctl enable*)",
	"bash(systemctl disable*)",
	"bash(security add-trusted-cert*)",
	"bash(spctl --master-disable*)",
	"bash(csrutil disable*)",
	// pi-enclave's own configuration and state. The sandbox denies the state
	// directory, but `.pi/enclave*.json` lives inside the workspace on purpose --
	// the monotonic rule makes it safe for the agent to *write*, and this makes
	// it visible when it does.
	"write(**/.pi/enclave.json)",
	"write(**/.pi/enclave.local.json)",
	"edit(**/.pi/enclave.json)",
	"edit(**/.pi/enclave.local.json)",
];

/**
 * Pattern escalations. Always a human decision.
 *
 * Short on purpose: in deterministic mode every entry here interrupts an
 * unattended run, and a list long enough to be "safe" is a list that makes auto
 * mode unusable and pushes people toward `skipReview`.
 */
export const DEFAULT_RULES_ASK: readonly string[] = [
	"bash(git push *)",
	"bash(git push)",
	"bash(gh pr create*)",
	"bash(gh release*)",
	"bash(npm publish*)",
	"bash(git reset --hard*)",
	"bash(git clean -*f*)",
];

/** Path denials, matched against every resolved write target. */
export const DEFAULT_PROTECTED_DENY: readonly string[] = [
	"**/.git",
	"**/.git/hooks/**",
	"**/.git/config",
	// Submodule and linked-worktree Git directories have their own config and
	// hooks, read by `git status` in the superproject (#33).
	"**/.git/modules/**/config",
	"**/.git/modules/**/hooks/**",
	"**/.git/worktrees/**/config.worktree",
	// Everything pi loads from a project, at any depth: extensions, settings,
	// MCP servers and skills (#19). The directory itself too, so that renaming
	// a prepared tree into place is refused like writing into it.
	"**/.pi",
	"**/.pi/**",
	"**/.agents",
	"**/.agents/**",
	"**/.ssh/**",
	"**/authorized_keys",
];

/** Path escalations, matched against every resolved write target. */
export const DEFAULT_PROTECTED_ASK: readonly string[] = [
	"**/.github/workflows/**",
	"**/Dockerfile",
	"**/docker-compose*.y*ml",
	// Loaded or run later outside the sandbox: instructions every agent reads,
	// direnv, hook managers and editor tasks (#19).
	"**/AGENTS.md",
	"**/AGENTS.override.md",
	"**/CLAUDE.md",
	"**/.envrc",
	"**/.husky/**",
	"**/.pre-commit-config.yaml",
	"**/lefthook.yml",
	"**/lefthook.yaml",
	"**/.lefthook.yml",
	"**/.lefthook.yaml",
	"**/.vscode/tasks.json",
];

/** The seven tools pi-enclave owns and executes inside the sandbox. */
export const OWNED_TOOLS: readonly string[] = ["bash", "read", "edit", "write", "grep", "find", "ls"];

/**
 * The default tool allowlist: exactly the tools pi-enclave sandboxes.
 *
 * Anything else executes in the pi process with the user's privileges, so the
 * default is to deny it and make the user name it. `readOnly` here is a
 * statement about what the tool does, used by the reviewer's trigger.
 */
export function defaultTools(): ToolsSettings {
	return {
		allow: {
			bash: {},
			read: { readOnly: true },
			grep: { readOnly: true },
			find: { readOnly: true },
			ls: { readOnly: true },
			edit: {},
			write: {},
		},
	};
}

/**
 * Resource limits (#24). Chosen so ordinary development work (tsc, cargo,
 * npm ci, test runners) is not affected, while a hung command, a fork loop,
 * a runaway write or a memory hog stops well before it hurts the host. The
 * container values are the ones the container backend has always used.
 */
export function defaultLimits(): LimitsSettings {
	return {
		defaultTimeoutSec: 120,
		maxTimeoutSec: 1800,
		maxOutputMb: 64,
		fileSizeMb: 4096,
		openFiles: 8192,
		processes: 1024,
		memoryMb: 8192,
		minFreeDiskMb: 1024,
		container: { ...DEFAULT_CONTAINER_LIMITS },
	};
}

export const DEFAULT_REVIEWER: ReviewerSettings = {
	model: "none",
	timeoutMs: 30_000,
	fallback: "none",
	transport: "chat",
};

/** Guardian's numbers, which are the only ones with field evidence behind them. */
export const DEFAULT_BREAKER: BreakerSettings = { consecutive: 3, window: [10, 50] };

export const DEFAULT_ATTENDED: AttendedSettings = { mode: "off", confirmTimeoutMs: 300_000, headlessTrust: [] };

export const DEFAULT_AUDIT: AuditSettings = {
	retentionDays: 30,
	retentionMb: 200,
	required: false,
	sessionMaxMb: 100,
	syslog: false,
};

export interface DefaultProfileOptions {
	/** The workspace root. Normally pi's cwd. */
	cwd: string;
	home?: string;
	/**
	 * What `$TMPDIR` expands to in configuration files. Not a writable root by
	 * default: the native backend adds a private per-session directory below
	 * this per-user base by itself (#20).
	 */
	tmp?: string;
	agentDir?: string;
	/** Parent environment used to derive effective credential locations. */
	env?: Readonly<Record<string, string | undefined>>;
}

/**
 * The profile a user with no configuration file gets.
 *
 * `attended.mode` defaults to `"off"`, which means every `ask` is a deny. That
 * is the safe direction and the one a user has to opt out of deliberately: the
 * alternative -- inferring a human from `ctx.hasUI` -- is true in RPC mode as
 * well as TUI, so it would draw a confirm dialog for a headless orchestrator
 * whose default answer resolves to "approved".
 */
export function defaultProfile(options: DefaultProfileOptions): EffectiveProfile {
	const { cwd, home = homedir(), agentDir = getAgentDir(), env = process.env } = options;
	return {
		name: "dev",
		auto: true,
		sandbox: {
			backend: { kind: "native", fallback: "podman", image: "", binary: "", socket: "", readableRoots: [] },
			mode: "workspace-write",
			// The temp directory is not configured here. The native backend adds a
			// private per-session directory of its own and the container backend
			// an in-container tmpfs; a fixed shared path such as /tmp/claude is
			// exactly what must not be writable (#20).
			writableRoots: [cwd],
			readDeny: [...defaultReadDeny(home, agentDir, env), join(cwd, ".pi", "mcp.json")],
			grantableReadDeny: [],
			grantableWriteRoots: [],
			readMode: "open",
			readableRoots: [],
			protectedWrite: protectedWriteTargets(home, agentDir, env),
			network: { mode: "off", allowHosts: [] },
			capabilities: "reviewed",
			hostExec: "never",
			// Seatbelt denies PTYs unless asked, which breaks `vim`, `less` and
			// anything paged; an agent that has to fight the sandbox to run
			// ordinary commands is steered toward workarounds rather than away
			// from the boundary. On Linux the field is informational -- bubblewrap
			// cannot deny PTYs.
			allowPty: true,
			// Loaded code below a writable root refuses auto mode (#36).
			allowSelfHosting: false,
			env: { passthrough: [], envDeny: [...DEFAULT_ENV_DENY] },
			limits: defaultLimits(),
		},
		rules: {
			deny: [...DEFAULT_RULES_DENY],
			ask: [...DEFAULT_RULES_ASK],
			skipReview: [],
			protectedPaths: { deny: [...DEFAULT_PROTECTED_DENY], ask: [...DEFAULT_PROTECTED_ASK] },
		},
		review: { trigger: "boundary", environment: [], hard_deny: [], soft_deny: [], allow: [] },
		tools: defaultTools(),
		reviewer: { ...DEFAULT_REVIEWER },
		breaker: { ...DEFAULT_BREAKER, window: [...DEFAULT_BREAKER.window] },
		attended: { ...DEFAULT_ATTENDED, headlessTrust: [] },
		audit: { ...DEFAULT_AUDIT },
	};
}

/**
 * What `"$defaults"` splices, per list path.
 *
 * A list absent from this map has no defaults, so `"$defaults"` in it is a
 * no-op rather than an error -- the same choice automode makes, and the one
 * that keeps a user's config working when a list later gains defaults.
 */
export function defaultListFor(listPath: string, options: DefaultProfileOptions): readonly string[] {
	const base = defaultProfile(options);
	switch (listPath) {
		case "sandbox.readDeny":
			return base.sandbox.readDeny;
		case "sandbox.env.envDeny":
			return base.sandbox.env.envDeny;
		case "sandbox.env.passthrough":
			return base.sandbox.env.passthrough;
		case "sandbox.writableRoots":
			return base.sandbox.writableRoots;
		case "sandbox.network.allowHosts":
			return base.sandbox.network.allowHosts;
		case "sandbox.grantableWriteRoots":
			return base.sandbox.grantableWriteRoots;
		case "sandbox.readableRoots":
			return base.sandbox.readableRoots;
		case "rules.deny":
			return base.rules.deny;
		case "rules.ask":
			return base.rules.ask;
		case "rules.skipReview":
			return base.rules.skipReview;
		case "rules.protectedPaths.deny":
			return base.rules.protectedPaths.deny;
		case "rules.protectedPaths.ask":
			return base.rules.protectedPaths.ask;
		default:
			// The four prose lists have no built-in entries in Phase 2: a default
			// rulebook nobody reads would only be false confidence.
			return [];
	}
}
