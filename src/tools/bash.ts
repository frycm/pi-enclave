/**
 * `BashOperations` backed by the sandbox.
 *
 * This is the whole of pi's shell execution surface (`bash.ts:62`), so one
 * implementation covers the `bash` tool and, through the `user_bash` event, the
 * `!` and `!!` shortcuts as well -- no second code path to keep in step.
 *
 * Two deliberate departures from what pi hands us:
 *
 * - The `env` argument is ignored. pi passes the session environment, which
 *   carries the provider credentials the agent is running on. The child gets
 *   `buildChildEnv`'s allowlist instead.
 * - Violations are appended to the command's output. The operations interface
 *   can only return an exit code, and an agent that sees "Operation not
 *   permitted" with no explanation will usually retry the same thing with
 *   `sudo`. Telling it which boundary it hit is what lets it change approach.
 */
import { isUnderAny } from "../backend/paths.ts";
import type { CompiledProfile, SandboxBackend, Violation } from "../backend/types.ts";
import { formatViolations } from "../backend/violations.ts";
import { buildChildEnv } from "../env/child-env.ts";
import type { CanonicalAction } from "../policy/canonical.ts";

/** Same seconds/range contract as pi's default BashOperations. */
export function validateBashTimeout(timeout: unknown): number | undefined {
	if (timeout === undefined) return undefined;
	if (
		typeof timeout !== "number" ||
		!Number.isFinite(timeout) ||
		timeout <= 0 ||
		timeout > Math.floor(2_147_483_647 / 1000)
	) {
		throw new Error("Invalid timeout: must be positive finite seconds, at most 2147483");
	}
	return timeout;
}

function pathMayBeReached(action: CanonicalAction, raw: string): boolean {
	if (!action.shell) return true;
	let mentioned = false;
	let possibleStatus = new Set([true]);
	for (let index = 0; index < action.shell.commands.length; index++) {
		const command = action.shell.commands[index];
		if (!command) continue;

		const connector = command.connector;
		const reachable =
			index === 0 ||
			connector === undefined ||
			(connector === "&&" && possibleStatus.has(true)) ||
			(connector === "||" && possibleStatus.has(false)) ||
			(connector !== "&&" && connector !== "||");
		const namesPath =
			command.name.includes(raw) ||
			command.args.some((arg) => arg.includes(raw)) ||
			command.redirects.some((redirect) => redirect.target.includes(raw));
		if (namesPath) {
			mentioned = true;
			if (reachable) return true;
		}

		const commandName = command.name.slice(command.name.lastIndexOf("/") + 1);
		const commandStatus =
			commandName === "true" ? new Set([true]) : commandName === "false" ? new Set([false]) : new Set([true, false]);
		if (index === 0 || connector === undefined || (connector !== "&&" && connector !== "||")) {
			possibleStatus = commandStatus;
		} else if (connector === "&&") {
			possibleStatus = new Set([
				...(possibleStatus.has(false) ? [false] : []),
				...(possibleStatus.has(true) ? commandStatus : []),
			]);
		} else {
			possibleStatus = new Set([
				...(possibleStatus.has(true) ? [true] : []),
				...(possibleStatus.has(false) ? commandStatus : []),
			]);
		}
	}
	return !mentioned;
}

/**
 * The subset of pi's `BashOperations` we implement, restated so this module
 * carries no runtime dependency on pi's types.
 */
export interface BashExecOptions {
	onData: (data: Buffer) => void;
	signal?: AbortSignal;
	timeout?: number;
	env?: NodeJS.ProcessEnv;
}

export interface BashOperationsLike {
	exec: (command: string, cwd: string, options: BashExecOptions) => Promise<{ exitCode: number | null }>;
}

export interface EnclaveBashOptions {
	backend: SandboxBackend;
	/**
	 * Resolved per call rather than captured, so the operations object can be
	 * registered with pi before the profile is compiled at session start.
	 */
	getCompiled: () => CompiledProfile;
	/** Extra names to copy from the parent environment. User-global config only. */
	passthrough?: readonly string[];
	/** Additional credential deny patterns. */
	envDeny?: readonly string[];
	/** Called for every violation, for the phase-2 audit log and status line. */
	onViolations?: (violations: Violation[]) => void;
	/**
	 * A locked agent action explicitly named a configured read-deny target.
	 * Needed for breaker accounting on Linux, where bwrap emits no read event
	 * and a shell can suppress the final failure status with `|| true`.
	 */
	onDeniedReadAttempt?: (paths: readonly string[]) => void;
	/**
	 * Asked again, here, whether this command may run.
	 *
	 * Not redundant with the gate. pi prepares every tool call in a batch before
	 * executing any of them, so a command gated before the breaker tripped is
	 * already prepared when it trips and blocking cannot un-prepare it. This is
	 * the only place left to stop it. Throwing refuses the command.
	 */
	guard?: (command: string) => CanonicalAction | undefined;
}

/**
 * A per-session counter for violation attribution.
 *
 * sandbox-runtime keys violations by `commandId` and compares only the first 100
 * characters, so using the command text would cross-attribute between two long
 * commands sharing a prefix, and would make a rerun inherit the previous run's
 * events. A counter cannot collide either way.
 */
let sequence = 0;
const SESSION_NONCE = Math.random().toString(36).slice(2, 8);

export function nextCommandId(): string {
	return `enclave-${SESSION_NONCE}-${++sequence}`;
}

export function createEnclaveBashOperations(options: EnclaveBashOptions): BashOperationsLike {
	const { backend, getCompiled, passthrough, envDeny, onViolations, onDeniedReadAttempt } = options;

	return {
		async exec(command, cwd, execOptions) {
			validateBashTimeout(execOptions.timeout);
			const action = options.guard?.(command);
			const compiled = getCompiled();
			// The compiled profile's env settings are the configured ones and win;
			// the static options remain only as a fallback for callers (tests, the
			// benchmark) that build operations without a folded config. Passing
			// them here rather than at construction is what lets the live session
			// honour `sandbox.env.passthrough` / `envDeny`, which an earlier version
			// silently dropped.
			const env = buildChildEnv(process.env, {
				passthrough: compiled.profile.envPassthrough ?? passthrough ?? [],
				envDeny: compiled.profile.envDeny ?? envDeny ?? [],
				readDeny: compiled.profile.readDeny,
				writableRoots: compiled.profile.writableRoots,
				...(compiled.profile.tmpDir ? { tmpdir: compiled.profile.tmpDir } : {}),
			});

			const result = await backend.run(compiled, {
				command,
				cwd,
				env,
				commandId: nextCommandId(),
				...(action?.capability?.kind === "write" ? { writeCapability: action.capability.value } : {}),
				...(action?.capability?.kind === "read" ? { readCapability: action.capability.value } : {}),
				onData: execOptions.onData,
				...(execOptions.signal ? { signal: execOptions.signal } : {}),
				...(execOptions.timeout !== undefined ? { timeout: execOptions.timeout } : {}),
			});

			const violations = [...result.violations];
			const deniedReadPaths = action?.paths
				.filter((path) => isUnderAny(path.resolved, compiled.profile.readDeny) && pathMayBeReached(action, path.raw))
				.map((path) => path.resolved);
			if (deniedReadPaths && deniedReadPaths.length > 0) onDeniedReadAttempt?.(deniedReadPaths);
			// bubblewrap reports denied writes through SRT's observer, but a denied
			// read is only an errno in the child and produces no event. When the exact
			// locked action explicitly names a configured read-deny target and the
			// command fails, retain that conservative policy evidence so repeated
			// retries reach the breaker. Never synthesize this on success: doing so
			// could hide a backend that accidentally disclosed the file.
			if (violations.length === 0 && result.exitCode !== 0 && action) {
				for (const path of action.paths) {
					if (!deniedReadPaths?.includes(path.resolved)) continue;
					violations.push({
						kind: path.writes ? "write" : "read",
						source: "policy",
						op: "read-deny-exit",
						path: path.resolved,
						backend: compiled.backend,
					});
				}
			}

			if (violations.length > 0) {
				onViolations?.(violations);
				// Appended after the command's own output so it reads as a postscript
				// rather than interleaving with whatever the command printed.
				execOptions.onData(Buffer.from(`\n${formatViolations(violations)}\n`, "utf8"));
			}

			return { exitCode: result.exitCode };
		},
	};
}

/**
 * Guidance appended to the `bash` tool description.
 *
 * Deliberately backend-neutral. The two backends report denials with different
 * errnos and different wording, so an agent taught one platform's vocabulary
 * would not recognise the other's. It is also honest about the Linux gap: a
 * denied read there is indistinguishable from a missing file, and telling the
 * agent that costs nothing while leaving it guessing costs a retry loop.
 */
export const BASH_PROMPT_GUIDELINES: string[] = [
	"Commands run inside an OS-enforced sandbox.",
	"- You can write inside the workspace and the temporary directory, and read most of the filesystem.",
	"- Writes elsewhere, reads of credential stores, and all network access are refused by the kernel.",
	"- A refusal is not something you can retry your way past, and sudo is not available.",
	"- When a refusal is detected it is reported after the command output as 'sandbox denied:'.",
	"- If a required write is denied, retry the exact command with allow_write set to that exact path and explain why.",
	"- If a configured, grantable read denial blocks the command, retry with allow_read set to that exact denied root.",
	"  Capability requests are reviewed, apply to one action only, and may still be refused.",
	"- On some platforms a denied read is reported as a missing file. If a path you expect to exist",
	"  appears absent and it looks like a credential location, treat it as denied rather than missing.",
];
