/**
 * The Phase-1 dev profile.
 *
 * One mode, `workspace-write`, with no configuration surface yet -- the config
 * loader, the monotonic merge and the project/user precedence rules are phase 2.
 * Building it here keeps the defaults in one place and makes them testable
 * before any of that exists.
 */
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";
import { getAgentDir } from "@earendil-works/pi-coding-agent";
import type { Profile } from "../backend/types.ts";

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

export interface DevProfileOptions {
	/** The workspace root. Normally pi's cwd. */
	cwd: string;
	/** Overrides for testing. */
	home?: string;
	tmp?: string;
	/**
	 * PTY allocation. On by default: Seatbelt denies PTYs unless asked, which
	 * breaks `vim`, `less` and `git log` without a pager override, and an agent
	 * that has to fight the sandbox to run ordinary commands will be steered
	 * toward workarounds rather than away from the boundary. On Linux the field
	 * is informational only -- bubblewrap cannot deny PTYs.
	 */
	allowPty?: boolean;
}

export function createDevProfile(options: DevProfileOptions): Profile {
	const { cwd, home = homedir(), tmp = tmpdir(), allowPty = true } = options;
	return {
		mode: "workspace-write",
		writableRoots: [cwd, tmp],
		readDeny: defaultReadDeny(home),
		network: "off",
		allowPty,
	};
}
