/**
 * A copy of the audit head in syslog (#37, `audit.syslog`).
 *
 * The anchor beside the log belongs to the same user as the log, so whatever
 * can rewrite one can rewrite the other. On a server, syslog is usually the
 * one place the user can add to but not edit: journald and rsyslog files are
 * owned by root, and many servers forward them off the host. Only the head is
 * sent (session, seq, kind, hash), never a record's content: it is enough to
 * prove which records existed, and it keeps commands and paths out of a log
 * that other people read.
 *
 * `logger` rather than a socket: Node has no Unix datagram socket, and
 * `logger` already knows each platform's syslog. One short-lived process per
 * record is a cost an operator opts into.
 */
import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import type { AuditHead } from "./audit.ts";

const LOGGER_PATHS = ["/usr/bin/logger", "/bin/logger"];

export function syslogLine(head: AuditHead): string {
	return `audit session=${head.sessionId} seq=${head.seq} kind=${head.kind} head=${head.head}`;
}

/** An `AuditLog` mirror that can say it has stopped. */
export interface SyslogMirror {
	(head: AuditHead): void;
	/** True once a send failed; nothing more is sent. Shown in status, and refuses under `audit.required`. */
	readonly stopped: boolean;
}

/**
 * A mirror for `AuditLog`. The first failure is reported and the mirror stops,
 * so a missing `logger` does not fill stderr.
 */
export function createSyslogMirror(
	onError: (error: Error) => void,
	loggerPath: string | null = LOGGER_PATHS.find((path) => existsSync(path)) ?? null,
): SyslogMirror {
	let broken = false;
	const fail = (error: Error) => {
		if (broken) return;
		broken = true;
		onError(error);
	};
	if (!loggerPath) {
		fail(new Error(`audit.syslog is set but no logger was found at ${LOGGER_PATHS.join(" or ")}`));
	}
	const send = (head: AuditHead) => {
		if (broken || !loggerPath) return;
		try {
			const child = spawn(loggerPath, ["-p", "authpriv.info", "-t", "pi-enclave", "--", syslogLine(head)], {
				stdio: "ignore",
			});
			child.on("error", fail);
			child.on("exit", (code) => {
				if (code !== 0) fail(new Error(`logger exited with ${code}`));
			});
			child.unref();
		} catch (error) {
			fail(error as Error);
		}
	};
	Object.defineProperty(send, "stopped", { get: () => broken, enumerable: true });
	return send as SyslogMirror;
}
