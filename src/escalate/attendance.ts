/**
 * Whether a human is actually there.
 *
 * An earlier draft of the README inferred this from `ctx.hasUI`. Verified
 * against pi 0.84.2, that is wrong in the most dangerous possible way:
 * `hasUI` is `true` in **both** TUI and RPC mode (`runner.ts:443-445`), and an
 * RPC client may be a headless orchestrator with nobody behind it. Showing a
 * confirm dialog there produces a `false` -- which is a deny, so it fails safe
 * -- but *believing* somebody is present would make the session claim to be
 * attended in the status line while every escalation silently denied.
 *
 * So attendance is an explicit contract, and this module's whole job is to
 * decide what is in force and to keep two rules:
 *
 * - **Preconditions are re-checked on every escalation**, not only at session
 *   start. A TTY can be lost and an RPC client can disconnect.
 * - **It never degrades toward attended.** Every transition this module can
 *   make goes one way.
 */
import type { AttendedMode } from "../config/types.ts";

/** pi's four modes. */
export type PiMode = "tui" | "rpc" | "json" | "print";

export interface AttendanceEnvironment {
	mode: PiMode;
	hasUI: boolean;
	/** `process.stdin.isTTY`. A TUI without one is not a person at a terminal. */
	hasTty: boolean;
	/** Set once the RPC handshake has been completed for this session. */
	handshakeVerified?: boolean;
}

export interface AttendanceState {
	/** What the configuration asked for. */
	configured: AttendedMode;
	/** What is actually in force. Never wider than `configured`. */
	effective: AttendedMode;
	/** Why they differ, when they do. Shown in the status line. */
	reason?: string;
	/** True when the mismatch means auto mode must not start at all. */
	fatal?: boolean;
}

/**
 * Resolve the attendance mode at session start.
 *
 * A declared `tui` with no terminal is **fatal** rather than a downgrade: the
 * user explicitly said a person would be at a terminal, and if that is not true
 * then the configuration describes a different situation from the real one.
 * Silently continuing as `off` would be safe but dishonest -- every `ask` would
 * deny, and the user would be looking for a dialog that is never coming.
 *
 * A declared `rpc` with no handshake **does** degrade, because the README
 * specifies it and because it is the expected state: no client implements the
 * handshake yet, so refusing to start would make `rpc` unusable rather than
 * merely unattended.
 */
export function resolveAttendance(configured: AttendedMode, env: AttendanceEnvironment): AttendanceState {
	if (configured === "off") return { configured, effective: "off" };

	// Neither mode can show anything at all in json or print mode: pi installs a
	// no-op UI context there and `confirm` returns false immediately.
	if (env.mode === "json" || env.mode === "print") {
		return {
			configured,
			effective: "off",
			reason: `pi is in ${env.mode} mode, where no dialog can be drawn; every ask is a deny`,
		};
	}

	if (configured === "tui") {
		if (env.mode !== "tui") {
			return {
				configured,
				effective: "off",
				reason: `attended.mode is "tui" but pi is in ${env.mode} mode`,
				fatal: true,
			};
		}
		if (!env.hasTty) {
			return {
				configured,
				effective: "off",
				reason: 'attended.mode is "tui" but the process has no controlling terminal',
				fatal: true,
			};
		}
		return { configured, effective: "tui" };
	}

	// rpc
	if (env.mode !== "rpc") {
		return {
			configured,
			effective: "off",
			reason: `attended.mode is "rpc" but pi is in ${env.mode} mode`,
			fatal: true,
		};
	}
	if (!env.handshakeVerified) {
		return {
			configured,
			effective: "off",
			reason: "the RPC client did not complete the attendance handshake, so it is not treated as a console",
		};
	}
	return { configured, effective: "rpc" };
}

/**
 * Re-check the preconditions mid-session.
 *
 * Returns the state that should now be in force. Only ever narrows: a session
 * that has degraded to `off` stays there even if the TTY comes back, because a
 * channel that dropped once is not one to start trusting again mid-run.
 */
export function recheckAttendance(current: AttendanceState, env: AttendanceEnvironment): AttendanceState {
	if (current.effective === "off") return current;
	if (current.effective === "tui" && (env.mode !== "tui" || !env.hasTty)) {
		return { ...current, effective: "off", reason: "the controlling terminal was lost mid-session" };
	}
	if (current.effective === "rpc" && (env.mode !== "rpc" || !env.hasUI)) {
		return { ...current, effective: "off", reason: "the RPC client disconnected mid-session" };
	}
	return current;
}

export function describeAttendance(state: AttendanceState): string {
	if (state.effective === state.configured && !state.reason) return state.effective;
	return `${state.effective} (configured ${state.configured}: ${state.reason ?? "unavailable"})`;
}
