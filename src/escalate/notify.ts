/**
 * Telling a person that a record is waiting (#30).
 *
 * `attended.notify` is a user-global argv the trusted parent runs when it
 * writes a pending or queued record: `mail`, `wall`, a LAN ntfy or Gotify
 * instance through curl, `tmux display-message`, a file drop. Three rules:
 *
 * - **No shell, and the argv is exactly the configured one.** Nothing the
 *   agent influenced is ever an argument, so no quoting can go wrong. It runs
 *   in `/`, not in the workspace, so a program that reads its working
 *   directory (`python3 -m`, a dotfile) does not load what the agent wrote;
 *   the program itself is a code root, refused below a writable root (#36).
 * - **What the agent influenced arrives on stdin, bounded and serialized.**
 *   One line, at most `SUMMARY_LIMIT` characters, in the same JSON-string
 *   spelling the approval prompt uses, so it cannot add a line of its own or a
 *   terminal escape. The nonce, session, tool and expiry are also in the
 *   environment, as `ENCLAVE_*` variables; the tool name only when it is a
 *   plain identifier.
 * - **Rate-limited, never dropped.** The agent decides how often an `ask`
 *   happens, so at most one notification per `minIntervalMs`. One that falls
 *   inside the interval is held and sent when it ends, naming the newest
 *   request and how many others came with it; `flush()` sends it at once, at
 *   session shutdown. A failure to notify is recorded and never blocks the
 *   gate.
 */

import { spawn as nodeSpawn } from "node:child_process";
import { accessSync, constants, statSync } from "node:fs";
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

export function notificationText(record: PendingRecord, others: number): string {
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
	if (others > 0) {
		lines.push(`(and ${others} other request(s) since the last notification; see pi-enclave pending)`);
	}
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
	options: { cwd: string; env: NodeJS.ProcessEnv; stdio: ["pipe", "ignore", "ignore"]; shell: false },
) => SpawnedNotifier;

/**
 * The tool name as it goes into `ENCLAVE_TOOL`: a plain identifier, or
 * `other`. Provider tool names are normally safe, but a hook that echoes the
 * variable should not have to rely on that.
 */
export function envToolName(tool: string): string {
	return /^[A-Za-z0-9_.:-]{1,64}$/.test(tool) ? tool : "other";
}

/**
 * A warning for session start when the configured program cannot run, so a
 * person learns it then rather than from a `notify-failed` line nobody reads.
 */
export function checkNotifyProgram(argv: readonly string[]): string | undefined {
	const program = argv[0];
	if (!program) return undefined;
	try {
		if (!statSync(program).isFile()) {
			return `pi-enclave: attended.notify names ${program}, which is not a file; nobody will be notified.`;
		}
		accessSync(program, constants.X_OK);
	} catch (error) {
		const code = (error as NodeJS.ErrnoException).code;
		const why = code === "ENOENT" ? "which does not exist" : "which is not executable";
		return `pi-enclave: attended.notify names ${program}, ${why}; nobody will be notified.`;
	}
	return undefined;
}

export interface Notifier {
	(record: PendingRecord): void;
	/** Send a held notification now (session shutdown). */
	flush(): void;
}

export interface NotifierOptions {
	argv: () => readonly string[];
	/** The hook's working directory. Never the workspace. */
	cwd?: string;
	minIntervalMs?: number;
	now?: () => number;
	spawn?: NotifySpawn;
	env?: NodeJS.ProcessEnv;
	/** For the audit log: sent, deferred, failed and the exit status. */
	onEvent?: (fields: Record<string, unknown>) => void;
}

export function createNotifier(options: NotifierOptions): Notifier {
	const now = options.now ?? Date.now;
	const minInterval = options.minIntervalMs ?? NOTIFY_MIN_INTERVAL_MS;
	const spawn = options.spawn ?? (nodeSpawn as unknown as NotifySpawn);
	const cwd = options.cwd ?? "/";
	let last = Number.NEGATIVE_INFINITY;
	/** The newest request inside the interval, and how many there were. */
	let held: PendingRecord | undefined;
	let heldCount = 0;
	let timer: ReturnType<typeof setTimeout> | undefined;

	const send = (record: PendingRecord, others: number) => {
		const [file, ...args] = options.argv();
		if (!file) return;
		last = now();
		try {
			const child = spawn(file, args, {
				cwd,
				env: {
					...(options.env ?? process.env),
					ENCLAVE_NONCE: record.nonce,
					ENCLAVE_SESSION: record.sessionId,
					ENCLAVE_TOOL: envToolName(record.action.tool),
					ENCLAVE_EXPIRES: record.waiter?.until ?? record.expiresAt,
				},
				stdio: ["pipe", "ignore", "ignore"],
				shell: false,
			});
			const kill = setTimeout(() => child.kill("SIGKILL"), NOTIFY_TIMEOUT_MS);
			kill.unref?.();
			child.on("error", (error) => {
				clearTimeout(kill);
				options.onEvent?.({ event: "notify-failed", nonce: record.nonce, error: error.message });
			});
			child.on("exit", (code, signal) => {
				clearTimeout(kill);
				options.onEvent?.({ event: "notify-sent", nonce: record.nonce, exitCode: code, signal });
			});
			child.stdin?.on?.("error", () => {});
			child.stdin?.end(notificationText(record, others));
			child.unref?.();
		} catch (error) {
			options.onEvent?.({ event: "notify-failed", nonce: record.nonce, error: (error as Error).message });
		}
	};

	const release = () => {
		if (timer !== undefined) clearTimeout(timer);
		timer = undefined;
		const record = held;
		const others = heldCount - 1;
		held = undefined;
		heldCount = 0;
		if (record) send(record, others);
	};

	const notify = (record: PendingRecord): void => {
		if (!options.argv()[0]) return;
		const at = now();
		if (at - last < minInterval) {
			// Held, not dropped: the end of the interval announces it.
			held = record;
			heldCount++;
			options.onEvent?.({ event: "notify-deferred", nonce: record.nonce });
			if (timer === undefined) {
				timer = setTimeout(release, Math.max(1, minInterval - (at - last)));
				timer.unref?.();
			}
			return;
		}
		send(record, 0);
	};
	notify.flush = release;
	return notify;
}
