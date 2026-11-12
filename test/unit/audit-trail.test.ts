/**
 * The audit log as the record of what an unattended agent did (#37): what is
 * recorded, how the end of the log is anchored, and what happens when the log
 * cannot keep up.
 */
import { existsSync, mkdtempSync, readFileSync, rmSync, unlinkSync, utimesSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { defaultProfile } from "../../src/config/defaults.ts";
import { fold } from "../../src/config/merge.ts";
import { parseDocument } from "../../src/config/schema.ts";
import { decide } from "../../src/gate/gate.ts";
import { ActionLock } from "../../src/gate/lock.ts";
import { canonicalize } from "../../src/policy/canonical.ts";
import type { ReviewerResult } from "../../src/reviewer/types.ts";
import {
	type AuditHead,
	AuditLog,
	anchorPathFor,
	decisionFields,
	executedFields,
	formatVerifyResult,
	MAX_AUDIT_TEXT,
	readAnchor,
	reviewerVerdictFields,
	userCommandFields,
	verifyLog,
	writeAnchor,
} from "../../src/state/audit.ts";
import { applyRetention } from "../../src/state/retention.ts";
import { createSyslogMirror, syslogLine } from "../../src/state/syslog.ts";

const OPTIONS = { cwd: "/work", home: "/home/u", tmp: "/tmp", agentDir: "/home/u/.pi/agent" };

let root: string;
beforeEach(() => {
	root = mkdtempSync(join(tmpdir(), "enclave-audit-trail-"));
});
afterEach(() => {
	rmSync(root, { recursive: true, force: true });
});

const records = (path: string) =>
	readFileSync(path, "utf8")
		.trim()
		.split("\n")
		.filter(Boolean)
		.map((line) => JSON.parse(line) as Record<string, unknown>);

async function written(
	count: number,
	sessionId = "s1",
	options: Partial<ConstructorParameters<typeof AuditLog>[0]> = {},
) {
	const audit = new AuditLog({ dir: root, sessionId, ...options });
	for (let i = 0; i < count; i++) audit.append("decision", { i });
	await audit.flush();
	return audit;
}

describe("what a decision record holds", () => {
	const action = (command: string) =>
		canonicalize({ tool: "bash", input: { command }, cwd: "/work", home: "/home/u", profileName: "dev" });

	it("keeps the command as bash received it, next to the tokenizer's reading", () => {
		const command = `cat README.md # it's\ngit push --force origin main\n# it's`;
		const fields = decisionFields({
			action: action(command),
			outcome: "allow",
			matches: [],
			turnIndex: 1,
			attended: "off",
		});
		expect(fields.command).toBe(command);
		expect(fields.commandTruncated).toBeUndefined();
		expect(fields.commands).toBeDefined();
	});

	it("bounds a long command and says it was cut", () => {
		const fields = decisionFields({
			action: action(`echo ${"x".repeat(MAX_AUDIT_TEXT * 2)}`),
			outcome: "allow",
			matches: [],
			turnIndex: 1,
			attended: "off",
		});
		expect(String(fields.command)).toHaveLength(MAX_AUDIT_TEXT);
		expect(fields.commandTruncated).toBe(true);
	});

	it("redacts a secret in the command when it is written", async () => {
		const audit = new AuditLog({ dir: root, sessionId: "redact" });
		audit.append(
			"decision",
			decisionFields({
				action: action("curl -H 'Authorization: Bearer sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789' x"),
				outcome: "allow",
				matches: [],
				turnIndex: 1,
				attended: "off",
			}),
		);
		await audit.flush();
		expect(readFileSync(audit.path, "utf8")).not.toContain("abcdefghijklmnopqrstuvwxyz0123456789");
	});
});

describe("records that follow a decision", () => {
	it("an executed record carries the exit code, the duration and whether pi saw an error", () => {
		expect(
			executedFields({
				toolCallId: "c1",
				tool: "bash",
				hash: "h",
				isError: false,
				durationMs: 12.6,
				exitCode: 0,
				turnIndex: 2,
			}),
		).toEqual({ toolCallId: "c1", tool: "bash", hash: "h", isError: false, durationMs: 13, exitCode: 0, turnIndex: 2 });
		// null is "ended without an exit code" (killed, timed out); absent is "not a shell".
		expect(
			executedFields({ toolCallId: "c2", tool: "bash", hash: "h", isError: true, exitCode: null, turnIndex: 2 }),
		).toHaveProperty("exitCode", null);
		expect(
			executedFields({ toolCallId: "c3", tool: "read", hash: "h", isError: false, turnIndex: 2 }),
		).not.toHaveProperty("exitCode");
	});

	it("a ! command is recorded with its exit code", () => {
		expect(
			userCommandFields({
				command: "systemctl status nginx",
				cwd: "/srv",
				excludeFromContext: true,
				exitCode: 3,
				durationMs: 40,
			}),
		).toEqual({
			command: "systemctl status nginx",
			cwd: "/srv",
			excludeFromContext: true,
			exitCode: 3,
			durationMs: 40,
		});
	});

	it("a reviewer verdict keeps the model's answer next to the enforced one", () => {
		const action = canonicalize({
			tool: "bash",
			input: { command: "rm -rf build" },
			cwd: "/work",
			home: "/home/u",
			profileName: "dev",
		});
		const result = {
			ok: true,
			review: {
				decision: "ask",
				risk: "high",
				reason: "effective high risk lacks covering direct authorization: cleans build output",
				modelRisk: "low",
				minimumRisk: "high",
				authorizationCovers: false,
			},
			modelReview: { decision: "allow", risk: "low", reason: "cleans build output" },
			evidence: {},
		} as unknown as ReviewerResult;
		expect(reviewerVerdictFields(result, { action, trigger: "mutating" })).toMatchObject({
			event: "verdict",
			hash: action.hash,
			ok: true,
			decision: "ask",
			modelDecision: "allow",
			risk: "high",
			modelRisk: "low",
			minimumRisk: "high",
			modelReason: "cleans build output",
		});
		const failed = { ok: false, kind: "unavailable", reason: "timeout", evidence: {} } as unknown as ReviewerResult;
		expect(reviewerVerdictFields(failed, { action, trigger: "mutating" })).toMatchObject({
			ok: false,
			failure: "unavailable",
			reason: "timeout",
		});
	});
});

describe("the head anchor", () => {
	it("follows every append", async () => {
		const audit = await written(3);
		const anchor = readAnchor(anchorPathFor(audit.path));
		expect(anchor).toMatchObject({ sessionId: "s1", seq: 3, kind: "decision" });
		expect(verifyLog(audit.path)).toMatchObject({ ok: true, records: 3, anchor: { seq: 3 } });
		expect(formatVerifyResult(audit.path, verifyLog(audit.path))).toContain("ends where its head anchor says");
	});

	it("reveals a replaced newest record", async () => {
		const audit = await written(3);
		const lines = readFileSync(audit.path, "utf8").trim().split("\n");
		lines[2] = (lines[2] as string).replace('"i":2', '"i":7');
		writeFileSync(audit.path, `${lines.join("\n")}\n`);
		const result = verifyLog(audit.path);
		expect(result.ok).toBe(false);
		expect(result.problem).toContain("does not match its head anchor");
	});

	it("reveals a deleted log", async () => {
		const audit = await written(3);
		unlinkSync(audit.path);
		const result = verifyLog(audit.path);
		expect(result.ok).toBe(false);
		expect(result.problem).toContain("cannot read");
		expect(result.anchor?.seq).toBe(3);
	});

	it("accepts one record past the anchor, a crash between the two writes, and no more", async () => {
		const audit = await written(4);
		const anchorPath = anchorPathFor(audit.path);
		const anchor = readAnchor(anchorPath) as AuditHead;
		const lines = readFileSync(audit.path, "utf8").trim().split("\n");
		const { createHash } = await import("node:crypto");
		const headOf = (seq: number) =>
			`sha256:${createHash("sha256")
				.update(lines[seq - 1] as string)
				.digest("hex")}`;
		writeAnchor(anchorPath, { ...anchor, seq: 3, head: headOf(3) });
		expect(verifyLog(audit.path)).toMatchObject({ ok: true, anchorBehind: 1 });
		writeAnchor(anchorPath, { ...anchor, seq: 2, head: headOf(2) });
		const result = verifyLog(audit.path);
		expect(result.ok).toBe(false);
		expect(result.problem).toContain("2 records follow the head anchor");
	});

	it("records a missing tail in the chain when the session resumes", async () => {
		const audit = await written(4, "resumed");
		const lines = readFileSync(audit.path, "utf8").trim().split("\n");
		writeFileSync(audit.path, `${lines.slice(0, 2).join("\n")}\n`);
		const resumed = new AuditLog({ dir: root, sessionId: "resumed" });
		resumed.append("decision", { after: true });
		await resumed.flush();
		const after = records(audit.path);
		expect(after[2]).toMatchObject({ kind: "audit", event: "tail-missing", anchorSeq: 4, logSeq: 2 });
		// The chain is intact from here on, and the evidence stays in it even
		// though the anchor now follows the shorter log.
		expect(verifyLog(audit.path)).toMatchObject({ ok: true, records: 4 });
	});

	it("records a whole deleted log when the session resumes", async () => {
		const audit = await written(2, "gone");
		unlinkSync(audit.path);
		const resumed = new AuditLog({ dir: root, sessionId: "gone" });
		await resumed.flush();
		expect(records(audit.path)[0]).toMatchObject({ kind: "audit", event: "tail-missing", anchorSeq: 2, logSeq: 0 });
	});

	it("is mirrored to an external sink with the head only", async () => {
		const heads: AuditHead[] = [];
		const audit = new AuditLog({ dir: root, sessionId: "mirrored", mirror: (head) => heads.push(head) });
		audit.append("decision", { command: "secret stuff" });
		await audit.flush();
		expect(heads).toHaveLength(1);
		expect(syslogLine(heads[0] as AuditHead)).toMatch(
			/^audit session=mirrored seq=1 kind=decision head=sha256:[0-9a-f]{64}$/,
		);
		expect(syslogLine(heads[0] as AuditHead)).not.toContain("secret");
	});

	it("reports a missing logger once and then stays quiet", () => {
		const errors: Error[] = [];
		const mirror = createSyslogMirror((error) => errors.push(error), null);
		mirror({ sessionId: "s", seq: 1, head: "sha256:x", kind: "decision", ts: "t" });
		mirror({ sessionId: "s", seq: 2, head: "sha256:y", kind: "decision", ts: "t" });
		expect(errors).toHaveLength(1);
		expect(errors[0]?.message).toContain("no logger was found");
	});
});

describe("the per-session cap", () => {
	it("writes one last record saying why, then stops and reports it", async () => {
		const onError = vi.fn();
		const audit = new AuditLog({ dir: root, sessionId: "capped", maxBytes: 600, onError });
		for (let i = 0; i < 20; i++) audit.append("decision", { i, padding: "x".repeat(100) });
		await audit.flush();
		const all = records(audit.path);
		expect(all.at(-1)).toMatchObject({ kind: "audit", event: "cap-reached", maxBytes: 600, dropped: "decision" });
		expect(all.length).toBeLessThan(10);
		expect(audit.degraded).toBe(true);
		expect(audit.full).toBe(true);
		expect(onError).toHaveBeenCalledTimes(1);
		expect(verifyLog(audit.path).ok).toBe(true);
	});
});

describe("retention", () => {
	const age = (path: string, days: number) => {
		const when = (Date.now() - days * 24 * 60 * 60 * 1000) / 1000;
		utimesSync(path, when, when);
	};

	it("keeps sessions with a breaker, violation or approval record past the size budget", async () => {
		const plain = await written(1, "plain");
		const incident = new AuditLog({ dir: root, sessionId: "incident" });
		incident.append("breaker", { event: "opened" });
		await incident.flush();
		age(plain.path, 2);
		age(incident.path, 3);
		writeFileSync(join(root, "big.jsonl"), "x".repeat(2 * 1024 * 1024));
		const result = applyRetention({ dir: root, retentionDays: 30, retentionMb: 1, keepSessionId: "big" });
		expect(result.deleted).toEqual(["plain.jsonl"]);
		expect(result.keptForIncidents).toEqual(["incident.jsonl"]);
		expect(existsSync(incident.path)).toBe(true);
	});

	it("does not mistake the text of a record for its kind", async () => {
		const audit = new AuditLog({ dir: root, sessionId: "quoted" });
		audit.append("decision", { note: '"kind":"breaker"' });
		await audit.flush();
		age(audit.path, 2);
		writeFileSync(join(root, "big.jsonl"), "x".repeat(2 * 1024 * 1024));
		expect(applyRetention({ dir: root, retentionDays: 30, retentionMb: 1, keepSessionId: "big" }).deleted).toEqual([
			"quoted.jsonl",
		]);
	});

	it("marks the anchor of a log it deletes, so verify can tell retention from loss", async () => {
		const audit = await written(2, "old");
		age(audit.path, 40);
		applyRetention({ dir: root, retentionDays: 30, retentionMb: 200 });
		expect(existsSync(audit.path)).toBe(false);
		const result = verifyLog(audit.path);
		expect(result.ok).toBe(true);
		expect(result.anchor?.retired?.reason).toBe("retention (age)");
		expect(formatVerifyResult(audit.path, result)).toContain("retired by retention (age)");
	});

	it("removes a retired anchor after another retention period", async () => {
		const audit = await written(1, "older");
		const anchorPath = anchorPathFor(audit.path);
		unlinkSync(audit.path);
		const anchor = readAnchor(anchorPath) as AuditHead;
		writeAnchor(anchorPath, {
			...anchor,
			retired: { ts: new Date(Date.now() - 31 * 86_400_000).toISOString(), reason: "retention (age)" },
		});
		applyRetention({ dir: root, retentionDays: 30, retentionMb: 200 });
		expect(existsSync(anchorPath)).toBe(false);
	});
});

describe("audit settings", () => {
	const parse = (audit: object, source: "user_global" | "project_local" = "user_global") =>
		parseDocument(
			{ audit },
			source,
			source === "user_global" ? "/home/u/.pi/agent/enclave.json" : "/work/.pi/enclave.json",
			OPTIONS,
		);

	it("default to recording without stopping, with a cap and no syslog", () => {
		expect(defaultProfile(OPTIONS).audit).toEqual({
			retentionDays: 30,
			retentionMb: 200,
			required: false,
			sessionMaxMb: 100,
			syslog: false,
		});
	});

	it("are set in the user-global file only", () => {
		const parsed = parse({ required: true, syslog: true, sessionMaxMb: 500 });
		if (!parsed.ok) throw new Error(JSON.stringify(parsed.errors));
		const result = fold([{ source: "builtin" }, parsed.document], OPTIONS);
		if (!result.ok) throw new Error(JSON.stringify(result.errors));
		expect(result.profile.audit).toMatchObject({ required: true, syslog: true, sessionMaxMb: 500 });
		expect(parse({ required: false }, "project_local").ok).toBe(false);
		expect(parse({ required: "yes" }).ok).toBe(false);
		expect(parse({ sessionMaxMb: 0 }).ok).toBe(false);
	});
});

describe("the gate's write boundary", () => {
	it("uses the boundary flag rather than the message text to skip its own suffix", async () => {
		const profile = defaultProfile(OPTIONS);
		const decideWith = (issue: string | { message: string; boundary: true }) =>
			decide(
				{ toolName: "bash", toolCallId: "c", input: { command: "echo x > /srv/x", allow_write: "/srv/x" } },
				{
					profile: { ...profile, sandbox: { ...profile.sandbox, grantableWriteRoots: ["/srv"] } },
					cwd: "/work",
					home: "/home/u",
					lock: new ActionLock({ breakerOpen: () => false }),
					owned: ["bash"],
					writeCapabilityIssue: () => issue,
				},
			);
		expect((await decideWith({ message: "pi-enclave: loaded code", boundary: true })).reason).toBe(
			"pi-enclave: loaded code",
		);
		expect((await decideWith("pi-enclave: no approval can, in other words")).reason).toContain(
			"This boundary is not grantable by approval.",
		);
	});
});
