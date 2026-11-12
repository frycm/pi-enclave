/**
 * Telling a person that a record is waiting (#30).
 *
 * `attended.notify` is a user-global argv the trusted parent runs when it
 * writes a pending or queued record: `mail`, `wall`, a LAN ntfy or Gotify
 * instance through curl, `tmux display-message`, a file drop. Three rules:
 *
 * - **No shell, and the argv is exactly the configured one.** Nothing the
 *   agent influenced is ever an argument, so no quoting can go wrong.
 * - **What the agent influenced arrives on stdin, bounded and serialized.**
 *   One line, at most `SUMMARY_LIMIT` characters, in the same JSON-string
 *   spelling the approval prompt uses, so it cannot add a line of its own or a
 *   terminal escape. The nonce, session, tool and expiry are also in the
 *   environment, as `ENCLAVE_*` variables.
 * - **Rate-limited.** The agent decides how often an `ask` happens, so at most
 *   one notification per `minIntervalMs`; the next one says how many were
 *   held back. A failure to notify is recorded and never blocks the gate.
 */

import { spawn as nodeSpawn } from "node:child_process";
import { approvalSerialize } from "../policy/canonical.ts";
import type { PendingRecord } from "./pending.ts";

export const SUMMARY_LIMIT = 200;
export const NOTIFY_MIN_INTERVAL_MS = 30_000;
const NOTIFY_TIMEOUT_MS = 10_000;

/** A one-line, bounded, serialized description of what the action does. */
export function summarizeRecord(record: PendingRecord): string {
	const input = record.action.input;
	const subject =
		typeof input.command === "string"
			? input.command
			: typeof input.path === "string"
				? input.path
				: (record.action.paths?.[0]?.path ?? JSON.stringify(input));
	const serialized = approvalSerialize(subject);
	if (serialized.length <= SUMMARY_LIMIT) return serialized;
	return `${serialized.slice(0, SUMMARY_LIMIT - 1)}…`;
}

export function notificationText(record: PendingRecord, suppressed: number): string {
	const text = (value: string) => approvalSerialize(value).slice(1, -1);
	const lines = [
		`pi-enclave: session ${text(record.sessionId)} needs approval for ${approvalSerialize(record.action.tool)}`,
		`action: ${summarizeRecord(record)}`,
		`approve: pi-enclave approve ${record.nonce}`,
	];
	if (record.waiter) {
		lines.push(`decline: pi-enclave decline ${record.nonce}`, `waits until: ${text(record.waiter.until)}`);
	} else {
		lines.push(`expires: ${text(record.expiresAt)}`);
	}
	if (suppressed > 0) lines.push(`(${suppressed} earlier request(s) were not notified; see pi-enclave pending)`);
	return `${lines.join("\n")}\n`;
}

export interface SpawnedNotifier {
	stdin: NodeJS.WritableStream | null;
	on(event: "error", listener: (error: Error) => void): unknown;
	on(event: "exit", listener: (code: number | null, signal: NodeJS.Signals | null) => void): unknown;
	kill(signal?: NodeJS.Signals): boolean;
	unref?(): void;
}

export type NotifySpawn = (
	file: string,
	args: readonly string[],
	options: { env: NodeJS.ProcessEnv; stdio: ["pipe", "ignore", "ignore"]; shell: false },
) => SpawnedNotifier;

export interface NotifierOptions {
	argv: () => readonly string[];
	minIntervalMs?: number;
	now?: () => number;
	spawn?: NotifySpawn;
	env?: NodeJS.ProcessEnv;
	/** For the audit log: sent, suppressed, failed and the exit status. */
	onEvent?: (fields: Record<string, unknown>) => void;
}

export function createNotifier(options: NotifierOptions) {
	const now = options.now ?? Date.now;
	const minInterval = options.minIntervalMs ?? NOTIFY_MIN_INTERVAL_MS;
	const spawn = options.spawn ?? (nodeSpawn as unknown as NotifySpawn);
	let last = Number.NEGATIVE_INFINITY;
	let suppressed = 0;

	return (record: PendingRecord): void => {
		const argv = options.argv();
		const [file, ...args] = argv;
		if (!file) return;
		const at = now();
		if (at - last < minInterval) {
			suppressed++;
			options.onEvent?.({ event: "notify-suppressed", nonce: record.nonce });
			return;
		}
		last = at;
		const held = suppressed;
		suppressed = 0;
		try {
			const child = spawn(file, args, {
				env: {
					...(options.env ?? process.env),
					ENCLAVE_NONCE: record.nonce,
					ENCLAVE_SESSION: record.sessionId,
					ENCLAVE_TOOL: record.action.tool,
					ENCLAVE_EXPIRES: record.waiter?.until ?? record.expiresAt,
				},
				stdio: ["pipe", "ignore", "ignore"],
				shell: false,
			});
			const timer = setTimeout(() => child.kill("SIGKILL"), NOTIFY_TIMEOUT_MS);
			timer.unref?.();
			child.on("error", (error) => {
				clearTimeout(timer);
				options.onEvent?.({ event: "notify-failed", nonce: record.nonce, error: error.message });
			});
			child.on("exit", (code, signal) => {
				clearTimeout(timer);
				options.onEvent?.({ event: "notify-sent", nonce: record.nonce, exitCode: code, signal });
			});
			child.stdin?.on?.("error", () => {});
			child.stdin?.end(notificationText(record, held));
			child.unref?.();
		} catch (error) {
			options.onEvent?.({ event: "notify-failed", nonce: record.nonce, error: (error as Error).message });
		}
	};
}
