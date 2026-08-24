import {
	chmodSync,
	existsSync,
	lstatSync,
	mkdtempSync,
	readdirSync,
	readFileSync,
	rmSync,
	symlinkSync,
	writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { defaultProfile } from "../../src/config/defaults.ts";
import type { EffectiveProfile } from "../../src/config/types.ts";
import {
	describeRecord,
	listPending,
	pendingDirs,
	readPending,
	transition,
	writePending,
} from "../../src/escalate/pending.ts";
import { checkResume, describeNarrowing, formatResumeFailure } from "../../src/escalate/resume.ts";
import { canonicalize } from "../../src/policy/canonical.ts";
import { configHash } from "../../src/state/audit.ts";

const OPTIONS = { cwd: "/work", home: "/home/u", tmp: "/tmp", agentDir: "/home/u/.pi/agent" };
const SESSION = "session-1";
const NONCE = "0123456789abcdef0123456789abcdef";

let stateRoot: string;

beforeEach(() => {
	stateRoot = mkdtempSync(join(tmpdir(), "enclave-pending-"));
});

afterEach(() => {
	rmSync(stateRoot, { recursive: true, force: true });
});

function profile(edit: (p: EffectiveProfile) => void = () => {}): EffectiveProfile {
	const p = defaultProfile(OPTIONS);
	edit(p);
	return p;
}

const action = (command = "git push --force origin main") =>
	canonicalize({ tool: "bash", input: { command }, cwd: "/work", home: "/home/u", profileName: "dev" });

function write(overrides: Partial<Parameters<typeof writePending>[0]> = {}) {
	const p = overrides.profile ?? profile();
	return writePending({
		stateRoot,
		sessionId: SESSION,
		action: action(),
		profile: p,
		configHash: configHash(p),
		reason: "matches ask rule bash(git push *)",
		nonce: NONCE,
		...overrides,
	});
}

describe("writing a record", () => {
	it("writes it 0600 under the session's pending directory", () => {
		const { path } = write();
		expect(path).toBe(join(pendingDirs(stateRoot, SESSION).pending, `${NONCE}.json`));
		expect(lstatSync(path).mode & 0o777).toBe(0o600);
	});

	// A half-written approval that happens to parse is the sort of thing that
	// only fails once.
	it("leaves no temporary file behind", () => {
		write();
		expect(readdirSync(pendingDirs(stateRoot, SESSION).pending)).toEqual([`${NONCE}.json`]);
	});

	// A hash would force the approver to trust whatever the agent put in the
	// workspace to see what they were approving.
	it("carries the full action, not just a hash", () => {
		const { record } = write();
		expect(record.action.input.command).toBe("git push --force origin main");
		expect(record.action.commands).toEqual(["git push --force origin main"]);
		expect(record.action.hash).toMatch(/^sha256:/);
	});

	it("carries the profile it was evaluated under", () => {
		const { record } = write();
		expect(record.profileSnapshot.sandbox.writableRoots).toEqual(["/work", "/tmp"]);
	});

	it("expires 24 hours out by default", () => {
		const { record } = write({ now: () => 0 });
		expect(Date.parse(record.expiresAt) - Date.parse(record.createdAt)).toBe(24 * 3600 * 1000);
	});
});

describe("reading a record", () => {
	const read = (overrides = {}) => readPending({ stateRoot, sessionId: SESSION, nonce: NONCE, ...overrides });

	it("round-trips", () => {
		write();
		const result = read();
		expect(result.ok).toBe(true);
		if (!result.ok) return;
		expect(result.record.nonce).toBe(NONCE);
	});

	// Every one of these is a way the record could have been tampered with, and
	// each is refused rather than repaired.
	describe("refuses", () => {
		it("a record with the wrong mode", () => {
			const { path } = write();
			chmodSync(path, 0o644);
			const result = read();
			expect(result.ok).toBe(false);
			if (result.ok) return;
			expect(result.reason).toContain("mode 644");
		});

		it("a symlinked record", () => {
			write();
			const dirs = pendingDirs(stateRoot, SESSION);
			const other = "ffffffffffffffffffffffffffffffff";
			symlinkSync(join(dirs.pending, `${NONCE}.json`), join(dirs.pending, `${other}.json`));
			const result = read({ nonce: other });
			expect(result.ok).toBe(false);
			if (result.ok) return;
			expect(result.reason).toContain("symlink");
		});

		// The nonce is in the body as well as the filename, so renaming a record
		// does not turn it into a different one.
		it("a record renamed to a different nonce", () => {
			const { path } = write();
			const other = "ffffffffffffffffffffffffffffffff";
			const target = join(pendingDirs(stateRoot, SESSION).pending, `${other}.json`);
			writeFileSync(target, readFileSync(path), { mode: 0o600 });
			const result = read({ nonce: other });
			expect(result.ok).toBe(false);
			if (result.ok) return;
			expect(result.reason).toContain("does not match its filename");
		});

		it("a record from a different session", () => {
			write();
			const result = readPending({ stateRoot, sessionId: "another-session", nonce: NONCE });
			expect(result.ok).toBe(false);
		});

		// The nonce is used as a filename, so it must not be able to escape the
		// directory.
		it.each(["../../etc/passwd", "not-hex", "0123", `${NONCE}/x`])("a nonce like %s", (nonce) => {
			const result = read({ nonce });
			expect(result.ok).toBe(false);
			if (result.ok) return;
			expect(result.reason).toContain("128-bit hex");
		});

		it("an edited body that no longer parses", () => {
			const { path } = write();
			writeFileSync(path, "{ truncated", { mode: 0o600 });
			expect(read().ok).toBe(false);
		});

		it("a record from a future version", () => {
			const { path, record } = write();
			writeFileSync(path, JSON.stringify({ ...record, version: 2 }), { mode: 0o600 });
			const result = read();
			expect(result.ok).toBe(false);
			if (result.ok) return;
			expect(result.reason).toContain("version");
		});
	});

	// An expired approval request is a decision nobody made, and keeping it
	// invites approving it later without the context that produced it.
	it("deletes an expired record instead of leaving it", () => {
		const { path } = write({ now: () => 0, ttlMs: 1000 });
		const result = read({ now: () => 5000 });
		expect(result.ok).toBe(false);
		if (result.ok) return;
		expect(result.reason).toContain("expired");
		expect(existsSync(path)).toBe(false);
	});
});

describe("the single-use lifecycle", () => {
	// pending → approved before execution and approved → consumed after, so a
	// crash between them leaves visible evidence rather than an ambiguity that
	// resolves itself.
	it("moves through pending, approved and consumed", () => {
		write();
		const dirs = pendingDirs(stateRoot, SESSION);

		transition(stateRoot, SESSION, NONCE, "pending", "approved");
		expect(readdirSync(dirs.pending)).toEqual([]);
		expect(readdirSync(dirs.approved)).toEqual([`${NONCE}.json`]);

		transition(stateRoot, SESSION, NONCE, "approved", "consumed");
		expect(readdirSync(dirs.consumed)).toEqual([`${NONCE}.json`]);
	});

	it("a second approval of the same nonce finds nothing to approve", () => {
		write();
		transition(stateRoot, SESSION, NONCE, "pending", "approved");
		expect(readPending({ stateRoot, sessionId: SESSION, nonce: NONCE }).ok).toBe(false);
	});

	it("lists records in every state", () => {
		write();
		transition(stateRoot, SESSION, NONCE, "pending", "approved");
		const listed = listPending(stateRoot, SESSION);
		expect(listed).toHaveLength(1);
		expect(listed[0]?.state).toBe("approved");
	});

	it("renders the whole action for the approver", () => {
		const { record } = write();
		const text = describeRecord(record);
		expect(text).toContain("git push --force origin main");
		expect(text).toContain(NONCE);
		expect(text).toContain("sha256:");
	});
});

describe("resuming", () => {
	const check = (record: Parameters<typeof checkResume>[0]["record"], current: EffectiveProfile) =>
		checkResume({ record, current, home: "/home/u" });

	it("permits when nothing has changed", () => {
		const { record } = write();
		const result = check(record, profile());
		expect(result.ok).toBe(true);
	});

	// The recorded hash is what the approver saw described; re-deriving it is
	// what proves the description matched the action.
	it("refuses when the action was edited on disk", () => {
		const { record } = write();
		const tampered = { ...record, action: { ...record.action, input: { command: "rm -rf /" } } };
		const result = check(tampered, profile());
		expect(result.ok).toBe(false);
		if (result.ok) return;
		expect(result.reason).toContain("was edited");
	});

	// An approval is permission to proceed past an ask, never past a deny.
	it("refuses when a rule added since denies it", () => {
		const { record } = write();
		const result = check(
			record,
			profile((p) => {
				p.rules.deny.push("bash(git push *)");
			}),
		);
		expect(result.ok).toBe(false);
		if (result.ok) return;
		expect(result.reason).toContain("denies this action");
	});

	describe("against the profile snapshot", () => {
		// The snapshot is evidence and an upper bound, never an execution input.
		it("permits a narrower current profile", () => {
			const { record } = write();
			const result = check(
				record,
				profile((p) => {
					p.sandbox.writableRoots = ["/work"];
					p.sandbox.readDeny.push("/work/secrets");
				}),
			);
			expect(result.ok).toBe(true);
		});

		it("refuses a wider current profile", () => {
			const { record } = write();
			const result = check(
				record,
				profile((p) => {
					p.sandbox.writableRoots.push("/etc");
				}),
			);
			expect(result.ok).toBe(false);
			if (result.ok) return;
			expect(result.reason).toContain("widened");
			expect(result.detail?.[0]).toContain("sandbox.writableRoots");
		});

		it("refuses when a read denial has been lifted since", () => {
			const { record } = write();
			const result = check(
				record,
				profile((p) => {
					p.sandbox.readDeny = p.sandbox.readDeny.filter((path) => !path.endsWith(".ssh"));
				}),
			);
			expect(result.ok).toBe(false);
		});
	});

	it("refuses a host-execution request under hostExec never", () => {
		const { record } = write({ requiresHuman: true });
		const result = check(record, profile());
		expect(result.ok).toBe(false);
		if (result.ok) return;
		expect(result.reason).toContain("host execution");
	});

	// A narrowing is not an error, but it changes what will happen, so it is
	// shown rather than silently applied.
	it("describes what narrowed, for the approver to read", () => {
		const { record } = write();
		const notes = describeNarrowing(
			record,
			profile((p) => {
				p.sandbox.writableRoots = ["/work"];
				p.rules.ask.push("bash(deploy*)");
			}),
		);
		expect(notes.join("\n")).toContain("/tmp");
		expect(notes.join("\n")).toContain("bash(deploy*)");
	});

	it("explains a refusal in full", () => {
		const { record } = write();
		const result = check(
			record,
			profile((p) => {
				p.sandbox.writableRoots.push("/etc");
			}),
		);
		if (result.ok) throw new Error("expected a refusal");
		const text = formatResumeFailure(result);
		expect(text).toContain("refusing to resume");
		expect(text).toContain("sandbox.writableRoots");
	});
});
