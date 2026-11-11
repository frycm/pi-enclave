/**
 * Asking the person, and the two rules that hold whatever the answer is.
 *
 * **Timeout is a deny.** pi's `confirm` resolves a timeout, a cancel, a closed
 * dialog and a disconnected client all to the same `false`, so there is nothing
 * to distinguish and nothing to decide: no answer is not an answer. A
 * pi-enclave-owned `AbortSignal` separates timeout from decline *for the audit
 * record only*, never for the verdict.
 *
 * **The canonical action is what is shown.** Never the raw command string. A
 * command containing a newline would otherwise put a second command below the
 * fold of a dialog whose first line looks harmless, and a person approving what
 * they can see is the whole mechanism.
 */

import type { ExtensionUIContext } from "@earendil-works/pi-coding-agent";
import type { Escalator } from "../gate/gate.ts";
import { describeReachability, type ToolReachability } from "../gate/reachability.ts";
import type { CanonicalAction } from "../policy/canonical.ts";
import { approvalSerialize, describeActionForApproval } from "../policy/canonical.ts";
import type { AttendanceState } from "./attendance.ts";
import { confirmPermission } from "./dialog.ts";

export interface ConfirmUI {
	confirm(title: string, message: string, options?: { timeout?: number; signal?: AbortSignal }): Promise<boolean>;
	custom?: ExtensionUIContext["custom"];
}

export type EscalationOutcome = "approved" | "declined" | "timeout" | "unattended";

export interface EscalationEvent {
	reachability?: ToolReachability;
	action: CanonicalAction;
	reason: string;
	outcome: EscalationOutcome;
	attended: string;
}

export interface ConfirmEscalatorOptions {
	reachability?: (action: CanonicalAction) => ToolReachability | undefined;
	ui: () => ConfirmUI | undefined;
	/** Re-evaluated per escalation: a channel can be lost mid-session. */
	attendance: () => AttendanceState;
	confirmTimeoutMs: () => number;
	onEscalation?: (event: EscalationEvent) => void;
	/** Called when nobody was there, so a pending record can be written. */
	onUnattended?: (action: CanonicalAction, reason: string, toolSource?: string) => void | Promise<void>;
}

export function createConfirmEscalator(options: ConfirmEscalatorOptions): Escalator {
	return {
		async confirm(action, reason, toolSource) {
			const reachability = options.reachability?.(action);
			if (reachability) reason = `${reason}\n${describeReachability(reachability)}`;
			const attendance = options.attendance();
			const ui = options.ui();

			if (attendance.effective === "off" || !ui) {
				await options.onUnattended?.(action, reason, toolSource);
				options.onEscalation?.({ action, reason, outcome: "unattended", attended: attendance.effective });
				return false;
			}

			// Our own signal, so a timeout can be told from a decline. pi cannot
			// report the difference -- both come back as `false` -- and the audit
			// record is the only place it matters.
			const controller = new AbortController();
			const timeoutMs = options.confirmTimeoutMs();
			const timer = setTimeout(() => controller.abort(), timeoutMs);
			let answered = false;
			try {
				const title = escalationTitle(action);
				const message = escalationMessage(action, reason, timeoutMs);
				answered =
					attendance.effective === "tui" && ui.custom
						? await confirmPermission({ custom: ui.custom.bind(ui) }, title, message, controller.signal)
						: await ui.confirm(title, message, { timeout: timeoutMs, signal: controller.signal });
				answered = answered && !controller.signal.aborted;
			} catch {
				// A rejected confirm is a disconnected client. Same verdict.
				answered = false;
			} finally {
				clearTimeout(timer);
			}

			const outcome: EscalationOutcome = answered ? "approved" : controller.signal.aborted ? "timeout" : "declined";
			options.onEscalation?.({
				action,
				reason,
				outcome,
				attended: attendance.effective,
				...(reachability ? { reachability } : {}),
			});
			if (!answered) await options.onUnattended?.(action, reason, toolSource);
			return answered;
		},
	};
}

export function escalationTitle(action: CanonicalAction): string {
	return `pi-enclave: approve this ${approvalSerialize(action.tool)} call?`;
}

export function escalationMessage(action: CanonicalAction, reason: string, timeoutMs: number): string {
	return [
		`reason: ${approvalSerialize(reason)}`,
		"",
		describeActionForApproval(action),
		"",
		`No answer within ${Math.round(timeoutMs / 1000)}s is a refusal.`,
	].join("\n");
}
