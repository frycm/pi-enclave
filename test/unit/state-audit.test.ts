import {
	chmodSync,
	lstatSync,
	mkdirSync,
	mkdtempSync,
	readFileSync,
	rmSync,
	symlinkSync,
	utimesSync,
	writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { AuditLog, formatVerifyResult, GENESIS, verifyLog } from "../../src/state/audit.ts";
import { checkSecureFile, ensureSecureDir, ensureStateDirs, StateDirError } from "../../src/state/dir.ts";
import { redact, redactString } from "../../src/state/redact.ts";
import { applyRetention } from "../../src/state/retention.ts";

let root: string;

beforeEach(() => {
	root = mkdtempSync(join(tmpdir(), "enclave-state-"));
});

afterEach(() => {
	rmSync(root, { recursive: true, force: true });
});

describe("the state directory", () => {
	it("creates its directories 0700", () => {
		const dirs = ensureStateDirs(root);
		for (const path of [dirs.root, dirs.audit, dirs.state]) {
			expect(lstatSync(path).mode & 0o777).toBe(0o700);
		}
	});

	// A umask or a restore from a backup can widen a directory. Refusing to
	// start would be a worse answer than tightening it.
	it("tightens an over-permissive directory rather than refusing", () => {
		const path = join(root, "audit");
		mkdirSync(path, { recursive: true, mode: 0o755 });
		chmodSync(path, 0o755);
		ensureSecureDir(path);
		expect(lstatSync(path).mode & 0o777).toBe(0o700);
	});

	// A symlinked state directory redirects every write, and the redirection is
	// invisible in every path this code prints.
	it("refuses a symlinked directory", () => {
		const real = join(root, "real");
		const link = join(root, "link");
		mkdirSync(real, { mode: 0o700 });
		symlinkSync(real, link);
		expect(() => ensureSecureDir(link)).toThrow(StateDirError);
	});

	it("refuses a directory owned by somebody else", () => {
		const path = join(root, "theirs");
		mkdirSync(path, { mode: 0o700 });
		expect(() => ensureSecureDir(path, 999_999)).toThrow(/owned by uid/);
	});

	it("refuses a path that is a file", () => {
		const path = join(root, "notadir");
		writeFileSync(path, "");
		expect(() => ensureSecureDir(path)).toThrow(/not a directory/);
	});

	describe("checkSecureFile", () => {
		// Unlike a directory, a file with the wrong mode may already have been
		// read by whoever could reach it, so tightening it quietly would hide
		// that it happened.
		it("refuses a 0644 file rather than repairing it", () => {
			const path = join(root, "secret");
			writeFileSync(path, "x", { mode: 0o600 });
			chmodSync(path, 0o644);
			expect(checkSecureFile(path)).toMatch(/mode 644/);
		});

		it("accepts a 0600 file", () => {
			const path = join(root, "secret");
			writeFileSync(path, "x", { mode: 0o600 });
			chmodSync(path, 0o600);
			expect(checkSecureFile(path)).toBeUndefined();
		});

		it("refuses a symlink", () => {
			const target = join(root, "target");
			const link = join(root, "link");
			writeFileSync(target, "x", { mode: 0o600 });
			symlinkSync(target, link);
			expect(checkSecureFile(link)).toMatch(/symlink/);
		});
	});
});

describe("the audit log", () => {
	function log(sessionId = "s1") {
		mkdirSync(join(root, "audit"), { recursive: true, mode: 0o700 });
		return new AuditLog({ dir: join(root, "audit"), sessionId, now: () => new Date("2026-08-23T12:00:00Z") });
	}

	it("chains records", async () => {
		const audit = log();
		audit.append("decision", { outcome: "allow" });
		audit.append("decision", { outcome: "deny" });
		await audit.flush();

		const result = verifyLog(audit.path);
		expect(result.ok).toBe(true);
		expect(result.records).toBe(2);

		const lines = readFileSync(audit.path, "utf8")
			.trim()
			.split("\n")
			.map((line) => JSON.parse(line));
		expect(lines[0].seq).toBe(1);
		expect(lines[0].prevHash).toBe(GENESIS);
		expect(lines[1].prevHash).not.toBe(GENESIS);
	});

	it("writes 0600", async () => {
		const audit = log();
		audit.append("decision", {});
		await audit.flush();
		expect(lstatSync(audit.path).mode & 0o777).toBe(0o600);
	});

	// seq and prevHash are derived from the previous record, so concurrent
	// appends would interleave -- and a chain that breaks under ordinary
	// parallel tool use cannot be told apart from tampering.
	it("survives many concurrent appends", async () => {
		const audit = log();
		for (let i = 0; i < 200; i++) audit.append("decision", { i });
		await audit.flush();
		expect(verifyLog(audit.path).ok).toBe(true);
		expect(verifyLog(audit.path).records).toBe(200);
	});

	it("continues the chain after a resume", async () => {
		const first = log();
		first.append("decision", { n: 1 });
		await first.flush();

		const second = log();
		second.append("decision", { n: 2 });
		await second.flush();

		const result = verifyLog(second.path);
		expect(result.ok).toBe(true);
		expect(result.records).toBe(2);
	});

	describe("verification", () => {
		async function corrupt(edit: (lines: string[]) => string[]) {
			const audit = log();
			for (let i = 0; i < 4; i++) audit.append("decision", { i });
			await audit.flush();
			const lines = readFileSync(audit.path, "utf8").trim().split("\n");
			writeFileSync(audit.path, `${edit(lines).join("\n")}\n`);
			return verifyLog(audit.path);
		}

		it("detects a deleted middle record", async () => {
			const result = await corrupt((lines) => [...lines.slice(0, 1), ...lines.slice(2)]);
			expect(result.ok).toBe(false);
			expect(result.problem).toContain("records are missing");
		});

		it("detects an edited record", async () => {
			const result = await corrupt((lines) =>
				lines.map((line, index) => (index === 1 ? line.replace('"i":1', '"i":99') : line)),
			);
			expect(result.ok).toBe(false);
			expect(result.problem).toContain("prevHash");
			expect(result.brokenAt).toBe(3);
		});

		it("detects truncation from the end", async () => {
			// Removing trailing records leaves a chain that still verifies -- and
			// says so. Only the record count reveals it, which is why the count is
			// reported rather than just a boolean.
			const result = await corrupt((lines) => lines.slice(0, 2));
			expect(result.ok).toBe(true);
			expect(result.records).toBe(2);
		});

		// A crash mid-write and an edit mean different things and are reported
		// differently.
		it("reports a torn final line separately from a broken chain", async () => {
			const audit = log();
			audit.append("decision", { n: 1 });
			await audit.flush();
			writeFileSync(audit.path, `${readFileSync(audit.path, "utf8")}{"seq":2,"partial`, { flag: "w" });
			const result = verifyLog(audit.path);
			expect(result.ok).toBe(true);
			expect(result.truncatedTail).toBe(true);
			expect(formatVerifyResult(audit.path, result)).toContain("incomplete");
		});

		it("says plainly when the chain is broken", async () => {
			const result = await corrupt((lines) => [...lines.slice(0, 1), ...lines.slice(2)]);
			expect(formatVerifyResult("x", result)).toContain("not trustworthy");
		});
	});

	it("keeps going when a write fails, and says it is degraded", async () => {
		const errors: Error[] = [];
		const audit = new AuditLog({
			dir: join(root, "does", "not", "exist"),
			sessionId: "s",
			onError: (e) => errors.push(e),
		});
		audit.append("decision", {});
		await audit.flush();
		expect(audit.degraded).toBe(true);
		expect(errors).toHaveLength(1);
	});

	it("redacts as it writes, so no call site can forget", async () => {
		const audit = log();
		audit.append("decision", { command: "curl -H 'Authorization: Bearer sk-abcdefghij0123456789'" });
		await audit.flush();
		const text = readFileSync(audit.path, "utf8");
		expect(text).not.toContain("sk-abcdefghij0123456789");
		expect(text).toContain("<redacted:sha256:");
	});
});

describe("redaction", () => {
	it.each([
		["an AWS key id", "AKIAIOSFODNN7EXAMPLE"],
		["a GitHub token", "ghp_abcdefghijklmnopqrstuvwxyz0123456789"],
		["an OpenAI key", "sk-abcdefghijklmnopqrstuvwxyz"],
		["an Anthropic key", "sk-ant-abcdefghijklmnopqrstuvwxyz"],
		["a Slack token", "xoxb-1234567890-abcdefghijk"],
		["a GitLab token", "glpat-abcdefghijklmnopqrst"],
	])("redacts %s", (_label, secret) => {
		const out = redactString(`export KEY=${secret} && run`);
		expect(out).not.toContain(secret);
		expect(out).toContain("<redacted:");
	});

	it("redacts a private key block whole", () => {
		const key = "-----BEGIN RSA PRIVATE KEY-----\nMIIabc\n-----END RSA PRIVATE KEY-----";
		expect(redactString(key)).not.toContain("MIIabc");
	});

	it("keeps the surrounding command readable", () => {
		const out = redactString(
			"curl -H 'Authorization: Bearer ghp_abcdefghijklmnopqrstuvwxyz0123' https://api.example.com",
		);
		expect(out).toContain("curl -H");
		expect(out).toContain("https://api.example.com");
	});

	// An audit log where everything is <redacted> is one nobody reads, which is
	// the same as not having one.
	it("leaves ordinary arguments alone", () => {
		const command = "git commit -m 'fix the parser' && npm test";
		expect(redactString(command)).toBe(command);
	});

	it("does not redact a plain hash or id", () => {
		const text = "commit 5dfbf1c9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3";
		expect(redactString(text)).toBe(text);
	});

	describe("through the record walker", () => {
		it("replaces a write body with its hash and length", () => {
			const out = redact({ path: "/work/x", content: "a".repeat(500) }) as Record<string, string>;
			expect(out.content).toMatch(/^<redacted:sha256:[0-9a-f]{16}> \(500 chars\)$/);
			expect(out.path).toBe("/work/x");
		});

		it("replaces a mention of a read-denied path", () => {
			const out = redact({ command: "cat /home/u/.ssh/id_ed25519" }, { readDeny: ["/home/u/.ssh"] }) as Record<
				string,
				string
			>;
			expect(out.command).not.toContain("id_ed25519");
			expect(out.command).toContain("cat ");
		});

		// Whole tokens only: a partially-masked path is neither readable nor safe.
		it("does not redact a path that merely shares a prefix", () => {
			const out = redact({ command: "cat /home/u/.sshconfig" }, { readDeny: ["/home/u/.ssh"] }) as Record<
				string,
				string
			>;
			expect(out.command).toContain(".sshconfig");
		});

		it("recurses through arrays and nested objects", () => {
			const out = redact({ a: [{ content: "secret body" }] }) as { a: { content: string }[] };
			expect(out.a[0]?.content).toContain("<redacted:");
		});

		// The hash is what lets an investigator confirm two records hold the same
		// secret without the log ever storing it.
		it("gives the same secret the same marker", () => {
			expect(redactString("AKIAIOSFODNN7EXAMPLE")).toBe(redactString("AKIAIOSFODNN7EXAMPLE"));
			expect(redactString("AKIAIOSFODNN7EXAMPLE")).not.toBe(redactString("AKIAIOSFODNN7EXAMPLB"));
		});
	});
});

describe("retention", () => {
	function makeLog(name: string, ageDays: number, bytes = 10) {
		const dir = join(root, "audit");
		mkdirSync(dir, { recursive: true });
		const path = join(dir, name);
		writeFileSync(path, "x".repeat(bytes));
		const when = new Date(Date.now() - ageDays * 24 * 3600 * 1000);
		utimesSync(path, when, when);
		return path;
	}

	it("deletes files older than the age bound", () => {
		makeLog("old.jsonl", 40);
		makeLog("new.jsonl", 1);
		const result = applyRetention({ dir: join(root, "audit"), retentionDays: 30, retentionMb: 200 });
		expect(result.deleted).toEqual(["old.jsonl"]);
	});

	it("deletes oldest first until the size bound is met", () => {
		makeLog("a.jsonl", 3, 1024 * 1024);
		makeLog("b.jsonl", 2, 1024 * 1024);
		makeLog("c.jsonl", 1, 1024 * 1024);
		const result = applyRetention({ dir: join(root, "audit"), retentionDays: 30, retentionMb: 2 });
		expect(result.deleted).toEqual(["a.jsonl"]);
	});

	// Deleting the log being written would break the chain mid-session, which
	// is the one thing worse for a hash chain than deleting a whole file.
	it("never deletes the current session's log", () => {
		makeLog("current.jsonl", 100);
		const result = applyRetention({
			dir: join(root, "audit"),
			retentionDays: 30,
			retentionMb: 200,
			keepSessionId: "current",
		});
		expect(result.deleted).toEqual([]);
	});

	it("is a no-op when there is no directory", () => {
		expect(applyRetention({ dir: join(root, "nope"), retentionDays: 30, retentionMb: 1 }).deleted).toEqual([]);
	});
});
