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
import type { CompiledProfile, SandboxBackend, Violation } from "../backend/types.ts";
import { formatViolations } from "../backend/violations.ts";
import { buildChildEnv } from "../env/child-env.ts";

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
	const { backend, getCompiled, passthrough, envDeny, onViolations } = options;

	return {
		async exec(command, cwd, execOptions) {
			const compiled = getCompiled();
			const env = buildChildEnv(process.env, {
				...(passthrough ? { passthrough } : {}),
				...(envDeny ? { envDeny } : {}),
				readDeny: compiled.profile.readDeny,
			});

			const result = await backend.run(compiled, {
				command,
				cwd,
				env,
				commandId: nextCommandId(),
				onData: execOptions.onData,
				...(execOptions.signal ? { signal: execOptions.signal } : {}),
				...(execOptions.timeout !== undefined ? { timeout: execOptions.timeout } : {}),
			});

			if (result.violations.length > 0) {
				onViolations?.(result.violations);
				// Appended after the command's own output so it reads as a postscript
				// rather than interleaving with whatever the command printed.
				execOptions.onData(Buffer.from(`\n${formatViolations(result.violations)}\n`, "utf8"));
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
	"- On some platforms a denied read is reported as a missing file. If a path you expect to exist",
	"  appears absent and it looks like a credential location, treat it as denied rather than missing.",
];
