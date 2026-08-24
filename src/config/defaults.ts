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
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";
import { getAgentDir } from "@earendil-works/pi-coding-agent";
import type {
	AttendedSettings,
	AuditSettings,
	BreakerSettings,
	EffectiveProfile,
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
export function defaultReadDeny(home = homedir(), agentDir = getAgentDir()): string[] {
	return [
		// pi's *live* credential storage. pi resolves its agent directory from
		// PI_CODING_AGENT_DIR, so the default path below is only where auth.json
		// usually is; this entry is where it actually is. The child never sees the
		// variable, but the file is on disk regardless, and an agent that can read
		// it can spend the account running it.
		join(agentDir, "auth.json"),
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
		join(home, ".config", "gh"),
		join(home, ".netrc"),
		join(home, ".npmrc"),
		// The default agent directory, kept even when the live one is elsewhere:
		// a stale auth.json at the default path is still a credential.
		join(home, ".pi", "agent", "auth.json"),
		join(home, ".pi", "auth.json"),
		// Sibling agents' stored credentials, for the same reason.
		join(home, ".claude", ".credentials.json"),
		join(home, ".config", "claude"),
	];
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
	"**/.git/hooks/**",
	"**/.pi/extensions/**",
	"**/.ssh/**",
	"**/authorized_keys",
];

/** Path escalations, matched against every resolved write target. */
export const DEFAULT_PROTECTED_ASK: readonly string[] = [
	"**/.github/workflows/**",
	"**/.git/config",
	"**/Dockerfile",
	"**/docker-compose*.y*ml",
];

/** The seven tools pi-enclave owns and executes inside the sandbox. */
export const OWNED_TOOLS: readonly string[] = ["bash", "read", "edit", "write", "grep", "find", "ls"];

/**
 * The default tool allowlist: exactly the tools pi-enclave sandboxes.
 *
 * Anything else executes in the pi process with the user's privileges, so the
 * default is to deny it and make the user name it. `readOnly` here is a
 * statement about what the tool does, used by Phase 3's trigger; in Phase 2 it
 * changes nothing, because there is no reviewer to skip.
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

export const DEFAULT_REVIEWER: ReviewerSettings = { model: "none", timeoutMs: 30_000, fallback: "none" };

/** Guardian's numbers, which are the only ones with field evidence behind them. */
export const DEFAULT_BREAKER: BreakerSettings = { consecutive: 3, window: [10, 50] };

export const DEFAULT_ATTENDED: AttendedSettings = { mode: "off", confirmTimeoutMs: 300_000 };

export const DEFAULT_AUDIT: AuditSettings = { retentionDays: 30, retentionMb: 200 };

export interface DefaultProfileOptions {
	/** The workspace root. Normally pi's cwd. */
	cwd: string;
	home?: string;
	tmp?: string;
	agentDir?: string;
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
	const { cwd, home = homedir(), tmp = tmpdir(), agentDir = getAgentDir() } = options;
	return {
		name: "dev",
		auto: true,
		sandbox: {
			mode: "workspace-write",
			writableRoots: [cwd, tmp],
			readDeny: defaultReadDeny(home, agentDir),
			network: { mode: "off", allowHosts: [] },
			capabilities: "reviewed",
			hostExec: "never",
			// Seatbelt denies PTYs unless asked, which breaks `vim`, `less` and
			// anything paged; an agent that has to fight the sandbox to run
			// ordinary commands is steered toward workarounds rather than away
			// from the boundary. On Linux the field is informational -- bubblewrap
			// cannot deny PTYs.
			allowPty: true,
			env: { passthrough: [], envDeny: [...DEFAULT_ENV_DENY] },
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
		attended: { ...DEFAULT_ATTENDED },
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
