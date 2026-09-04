#!/usr/bin/env -S node --import tsx
/**
 * The `pi-enclave` command.
 *
 * A separate binary rather than a pi subcommand, because pi 0.84.2's subcommand
 * set is closed -- `install`, `remove`, `update`, `list`, `config`, `auth` --
 * and any other bare word on its command line becomes a prompt for the model
 * (`cli/args.ts:229-231`). `pi enclave approve …` would therefore not run a
 * command; it would ask the agent to do something called "enclave approve".
 *
 * Read-only inspection is also available in-session as `/enclave …`.
 * `approve` and `attend-secret` deliberately remain outside the session the
 * agent is driving.
 */
import { readdirSync } from "node:fs";
import { homedir } from "node:os";
import { createInterface } from "node:readline/promises";
import { approve } from "../src/cli/approve.ts";
import { renderConfig, renderDefaults } from "../src/config/render.ts";
import { loadConfig } from "../src/config/sources.ts";
import { provisionSecret } from "../src/escalate/handshake.ts";
import { describeRecord, listPending, listSessions, readPending } from "../src/escalate/pending.ts";
import { formatVerifyResult, verifyLog } from "../src/state/audit.ts";
import { ensureStateDirs, stateDirs } from "../src/state/dir.ts";

const USAGE = `pi-enclave <command>

  rules defaults [--readonly]   print the built-in rule lists
  rules config                  print the effective rulebook, tagged by source
  pending [--all]               list approval records awaiting a decision
  approve <nonce>               show an action, ask, and run it once
  audit [verify] [--session id] read or re-chain the audit log
  attend-secret                 provision the RPC attendance secret

Read-only status, rules, pending, and audit inspection are also available inside pi as
/enclave <command>. Approval and secret provisioning are CLI-only.`;

async function main(argv: string[]): Promise<number> {
	const [command, ...rest] = argv;
	const cwd = process.cwd();

	switch (command) {
		case undefined:
		case "help":
		case "--help":
		case "-h":
			process.stdout.write(`${USAGE}\n`);
			return 0;

		case "rules":
			return rules(rest, cwd);

		case "pending":
			return pending(rest);

		case "approve":
			return runApprove(rest);

		case "audit":
			return auditCommand(rest);

		case "attend-secret":
			return attendSecret();

		default:
			process.stderr.write(`pi-enclave: unknown command "${command}"\n\n${USAGE}\n`);
			return 2;
	}
}

/**
 * The configuration as a session would see it.
 *
 * `projectTrusted: true` on purpose. A session that wrote a pending record
 * folded the project files in, so its `profileSnapshot` already reflects any
 * narrowing they add; dropping them here made the CLI's profile strictly *wider*
 * than the snapshot, and `checkResume`'s narrower-or-equal test then refused
 * every approval from any repo that configures policy. It is safe to apply them
 * because the monotonic fold lets a project file only tighten, never widen — so
 * reading them can only make the resume profile the same or narrower, never a
 * grant nobody approved.
 */
function currentConfig(cwd: string) {
	const loaded = loadConfig({ cwd, projectTrusted: true });
	if (!loaded.ok) {
		process.stderr.write(`${loaded.message}\n`);
		return undefined;
	}
	return loaded;
}

function rules(argv: string[], cwd: string): number {
	const verb = argv[0] ?? "config";
	if (verb === "defaults") {
		process.stdout.write(`${renderDefaults({ cwd }, argv.includes("--readonly"))}\n`);
		return 0;
	}
	if (verb !== "config") {
		process.stderr.write(`pi-enclave: unknown rules subcommand "${verb}"\n`);
		return 2;
	}
	const loaded = currentConfig(cwd);
	if (!loaded) return 1;
	process.stdout.write(`${renderConfig(loaded.profile, loaded.provenance)}\n`);
	return 0;
}

function pending(argv: string[]): number {
	const dirs = stateDirs();
	const sessions = listSessions(dirs.state);
	const showAll = argv.includes("--all");
	let found = 0;

	for (const sessionId of sessions) {
		for (const entry of listPending(dirs.state, sessionId)) {
			if (!showAll && entry.state !== "pending") continue;
			found++;
			process.stdout.write(`\n[${entry.state}] session ${sessionId}\n${describeRecord(entry.record)}\n`);
		}
	}

	if (found === 0) {
		process.stdout.write(showAll ? "no approval records\n" : "nothing is waiting for approval\n");
	} else {
		process.stdout.write(`\nApprove one with: pi-enclave approve <nonce>\n`);
	}
	return 0;
}

async function runApprove(argv: string[]): Promise<number> {
	const nonce = argv[0];
	if (!nonce) {
		process.stderr.write("pi-enclave: approve needs a nonce. Run `pi-enclave pending` to see them.\n");
		return 2;
	}

	const dirs = stateDirs();
	// A nonce is unique across sessions, so the session does not have to be
	// named -- but the record is still validated against the session it claims.
	let located: { sessionId: string } | undefined;
	for (const sessionId of listSessions(dirs.state)) {
		const result = readPending({ stateRoot: dirs.state, sessionId, nonce });
		if (result.ok) {
			located = { sessionId };
			break;
		}
	}
	if (!located) {
		process.stderr.write(`pi-enclave: no pending record with nonce ${nonce}.\n`);
		return 1;
	}

	const read = readPending({ stateRoot: dirs.state, sessionId: located.sessionId, nonce });
	if (!read.ok) {
		process.stderr.write(`pi-enclave: ${read.reason}\n`);
		return 1;
	}

	const loaded = currentConfig(read.record.action.cwd);
	if (!loaded) return 1;

	const rl = createInterface({ input: process.stdin, output: process.stdout });
	try {
		const result = await approve({
			record: read.record,
			stateRoot: dirs.state,
			current: loaded.profile,
			home: homedir(),
			io: {
				out: (text) => process.stdout.write(text.endsWith("\n") ? text : `${text}\n`),
				err: (text) => process.stderr.write(`${text}\n`),
				ask: async (question) => {
					const answer = await rl.question(question);
					return /^y(es)?$/i.test(answer.trim());
				},
			},
		});
		switch (result.outcome) {
			case "executed":
				return result.exitCode === 0 ? 0 : 1;
			case "declined":
				return 0;
			default:
				return 1;
		}
	} finally {
		rl.close();
	}
}

function auditCommand(argv: string[]): number {
	const dirs = stateDirs();
	const sessionIndex = argv.indexOf("--session");
	const sessionId = sessionIndex >= 0 ? argv[sessionIndex + 1] : undefined;

	let files: string[];
	try {
		files = readdirSync(dirs.audit)
			.filter((name) => name.endsWith(".jsonl"))
			.filter((name) => !sessionId || name === `${sessionId}.jsonl`);
	} catch {
		process.stdout.write("no audit logs yet\n");
		return 0;
	}
	if (files.length === 0) {
		process.stdout.write("no audit logs match\n");
		return 0;
	}

	if (argv[0] === "verify") {
		let ok = true;
		for (const name of files) {
			const result = verifyLog(`${dirs.audit}/${name}`);
			ok &&= result.ok;
			process.stdout.write(`${formatVerifyResult(name, result)}\n`);
		}
		return ok ? 0 : 1;
	}

	for (const name of files) process.stdout.write(`${dirs.audit}/${name}\n`);
	process.stdout.write("\nRe-chain them with: pi-enclave audit verify\n");
	return 0;
}

function attendSecret(): number {
	const dirs = ensureStateDirs();
	const path = provisionSecret(dirs.attendSecret);
	// The path, never the value. A secret echoed to a terminal is a secret in
	// the scrollback, in the shell history, and in any CI log that captured it.
	process.stdout.write(
		[
			`Wrote a 256-bit attendance secret to ${path} (mode 600).`,
			"",
			"Copy its contents to the RPC client through a channel you already trust.",
			"The client answers the attendance challenge with:",
			"  base64(HMAC-SHA256(secret, nonce || sessionId))",
			"",
			'Until a client does that, attended.mode "rpc" behaves as "off".',
			"",
		].join("\n"),
	);
	return 0;
}

main(process.argv.slice(2))
	.then((code) => {
		process.exitCode = code;
	})
	.catch((error: Error) => {
		process.stderr.write(`pi-enclave: ${error.message}\n`);
		process.exitCode = 1;
	});
