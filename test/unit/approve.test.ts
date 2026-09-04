import { mkdtempSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { CompiledProfile, FsClient, Profile, RunRequest, SandboxBackend } from "../../src/backend/types.ts";
import { type ApproveIO, approve } from "../../src/cli/approve.ts";
import { defaultProfile } from "../../src/config/defaults.ts";
import type { EffectiveProfile } from "../../src/config/types.ts";
import { pendingDirs, writePending } from "../../src/escalate/pending.ts";
import { canonicalize } from "../../src/policy/canonical.ts";
import { configHash } from "../../src/state/audit.ts";

const OPTIONS = { cwd: "/work", home: "/home/u", tmp: "/tmp", agentDir: "/home/u/.pi/agent" };
const SESSION = "session-1";
const NONCE = "0123456789abcdef0123456789abcdef";

let stateRoot: string;

beforeEach(() => {
	stateRoot = mkdtempSync(join(tmpdir(), "enclave-approve-"));
});

afterEach(() => {
	rmSync(stateRoot, { recursive: true, force: true });
});

/** Records what it was asked to run without running anything. */
class RecordingBackend implements SandboxBackend {
	readonly name = "seatbelt" as const;
	readonly commands: RunRequest[] = [];
	readonly writes: { path: string; content: string }[] = [];
	compiledProfile?: Profile;
	disposed = false;
	beforeCompile?: () => void;

	async compile(profile: Profile): Promise<CompiledProfile> {
		this.beforeCompile?.();
		this.compiledProfile = profile;
		return { backend: this.name, profile, describe: () => "(fake)" };
	}

	/** Lets a test observe the filesystem at the moment the command would run. */
	beforeRun?: () => void;

	async run(_compiled: CompiledProfile, request: RunRequest) {
		this.beforeRun?.();
		this.commands.push(request);
		request.onData?.(Buffer.from("ok\n"));
		return { exitCode: 0, violations: [] };
	}

	fs(): FsClient {
		return {
			writeFile: async (path: string, content: string) => {
				this.writes.push({ path, content });
			},
		} as unknown as FsClient;
	}

	async dispose() {
		this.disposed = true;
	}
}

function io() {
	const out: string[] = [];
	const err: string[] = [];
	const asked: string[] = [];
	return {
		out,
		err,
		asked,
		make: (answer: boolean): ApproveIO => ({
			out: (text) => out.push(text),
			err: (text) => err.push(text),
			ask: async (question) => {
				asked.push(question);
				return answer;
			},
		}),
	};
}

function profile(edit: (p: EffectiveProfile) => void = () => {}): EffectiveProfile {
	const p = defaultProfile(OPTIONS);
	edit(p);
	return p;
}

function record(tool: string, input: Record<string, unknown>) {
	const p = profile();
	return writePending({
		stateRoot,
		sessionId: SESSION,
		action: canonicalize({ tool, input, cwd: "/work", home: "/home/u", profileName: "dev" }),
		profile: p,
		configHash: configHash(p),
		reason: "matches ask rule",
		nonce: NONCE,
	}).record;
}

describe("approving a record", () => {
	it("shows the action before asking", async () => {
		const backend = new RecordingBackend();
		const channel = io();
		await approve({
			record: record("bash", { command: "git push origin main" }),
			stateRoot,
			current: profile(),
			home: "/home/u",
			io: channel.make(false),
			backend,
		});
		expect(channel.out.join("\n")).toContain("git push origin main");
		expect(channel.asked).toHaveLength(1);
	});

	it("shows complete terminal-safe evidence before asking", async () => {
		const backend = new RecordingBackend();
		const channel = io();
		const content = `${"A".repeat(300)}ERASE-PRODUCTION${"Z".repeat(300)}`;
		await approve({
			record: record("write", { path: "/work/prod", content, note: "safe\u202Eliated" }),
			stateRoot,
			current: profile(),
			home: "/home/u",
			io: channel.make(false),
			backend,
		});
		const shown = channel.out.join("\n");
		expect(shown).toContain(content);
		expect(shown).toContain("\\u202e");
		expect(shown).not.toContain("\u202E");
		expect(channel.asked).toHaveLength(1);
	});

	it("runs the command through the sandbox when the person says yes", async () => {
		const backend = new RecordingBackend();
		const result = await approve({
			record: record("bash", { command: "git push origin main" }),
			stateRoot,
			current: profile(),
			home: "/home/u",
			io: io().make(true),
			backend,
		});
		expect(result).toEqual({ outcome: "executed", exitCode: 0 });
		expect(backend.commands[0]?.command).toBe("git push origin main");
		expect(backend.disposed).toBe(true);
	});

	// The credential isolation that Phase 1 built has to hold here too: this
	// process has the provider keys, and the child must not.
	it("builds the child environment rather than inheriting this process's", async () => {
		const backend = new RecordingBackend();
		process.env.APPROVE_TEST_TOKEN = "super-secret";
		try {
			await approve({
				record: record("bash", { command: "env" }),
				stateRoot,
				current: profile(),
				home: "/home/u",
				io: io().make(true),
				backend,
			});
		} finally {
			delete process.env.APPROVE_TEST_TOKEN;
		}
		expect(Object.values(backend.commands[0]?.env ?? {})).not.toContain("super-secret");
	});

	it("does nothing when the person says no, and leaves the record pending", async () => {
		const backend = new RecordingBackend();
		const result = await approve({
			record: record("bash", { command: "git push origin main" }),
			stateRoot,
			current: profile(),
			home: "/home/u",
			io: io().make(false),
			backend,
		});
		expect(result).toEqual({ outcome: "declined" });
		expect(backend.commands).toHaveLength(0);
		expect(readdirSync(pendingDirs(stateRoot, SESSION).pending)).toEqual([`${NONCE}.json`]);
	});

	it("refuses when a record expires while the approval prompt is open", async () => {
		const backend = new RecordingBackend();
		const rec = record("bash", { command: "git push origin main" });
		rec.expiresAt = new Date(1_000).toISOString();
		const result = await approve({
			record: rec,
			stateRoot,
			current: profile(),
			home: "/home/u",
			io: io().make(true),
			backend,
			now: () => 2_000,
		});

		expect(result.outcome).toBe("refused");
		expect(backend.compiledProfile).toBeUndefined();
		expect(backend.commands).toHaveLength(0);
		expect(readdirSync(pendingDirs(stateRoot, SESSION).pending)).toEqual([`${NONCE}.json`]);
	});

	it("refuses when a record expires while the sandbox profile compiles", async () => {
		const backend = new RecordingBackend();
		const rec = record("bash", { command: "git push origin main" });
		rec.expiresAt = new Date(1_000).toISOString();
		let now = 0;
		backend.beforeCompile = () => {
			now = 2_000;
		};
		const result = await approve({
			record: rec,
			stateRoot,
			current: profile(),
			home: "/home/u",
			io: io().make(true),
			backend,
			now: () => now,
		});

		expect(result.outcome).toBe("refused");
		expect(backend.commands).toHaveLength(0);
		expect(readdirSync(pendingDirs(stateRoot, SESSION).approved)).toEqual([`${NONCE}.json`]);
		expect(backend.disposed).toBe(true);
	});

	// pending → approved before execution and approved → consumed after, so a
	// crash mid-run leaves evidence rather than an ambiguity.
	it("moves the record to consumed once it has run", async () => {
		await approve({
			record: record("bash", { command: "ls" }),
			stateRoot,
			current: profile(),
			home: "/home/u",
			io: io().make(true),
			backend: new RecordingBackend(),
		});
		const dirs = pendingDirs(stateRoot, SESSION);
		expect(readdirSync(dirs.pending)).toEqual([]);
		expect(readdirSync(dirs.consumed)).toEqual([`${NONCE}.json`]);
	});

	// The crash-evidence property, and the reason the rename happens before the
	// command rather than after it: a crash mid-run must leave the record in
	// approved/, which says "this was approved and may have run" -- a state a
	// person needs to be told about. Caught by a mutation check that moved the
	// rename after execution and passed every other test.
	it("moves the record to approved *before* the command runs", async () => {
		const backend = new RecordingBackend();
		const dirs = pendingDirs(stateRoot, SESSION);
		let duringRun: { pending: string[]; approved: string[] } | undefined;
		backend.beforeRun = () => {
			duringRun = { pending: readdirSync(dirs.pending), approved: readdirSync(dirs.approved) };
		};

		await approve({
			record: record("bash", { command: "ls" }),
			stateRoot,
			current: profile(),
			home: "/home/u",
			io: io().make(true),
			backend,
		});

		expect(duringRun?.pending).toEqual([]);
		expect(duringRun?.approved).toEqual([`${NONCE}.json`]);
	});

	it("applies a write action through the sandboxed helper", async () => {
		const backend = new RecordingBackend();
		const result = await approve({
			record: record("write", { path: "/work/notes.md", content: "hello" }),
			stateRoot,
			current: profile(),
			home: "/home/u",
			io: io().make(true),
			backend,
		});
		expect(result.outcome).toBe("executed");
		expect(backend.writes).toEqual([{ path: "/work/notes.md", content: "hello" }]);
	});

	// A relative path must resolve against the *session's* cwd, not the CLI's, or
	// the file lands somewhere other than what the approver read.
	it("resolves a relative write against the record's cwd", async () => {
		const backend = new RecordingBackend();
		await approve({
			record: record("write", { path: "notes.md", content: "hi" }),
			stateRoot,
			current: profile(),
			home: "/home/u",
			io: io().make(true),
			backend,
		});
		expect(backend.writes).toEqual([{ path: "/work/notes.md", content: "hi" }]);
	});

	// pi's write tool uses `file_path`; canonicalize accepts it, so approve must too.
	it("accepts the file_path key", async () => {
		const backend = new RecordingBackend();
		const result = await approve({
			record: record("write", { file_path: "/work/x", content: "y" }),
			stateRoot,
			current: profile(),
			home: "/home/u",
			io: io().make(true),
			backend,
		});
		expect(result.outcome).toBe("executed");
		expect(backend.writes).toEqual([{ path: "/work/x", content: "y" }]);
	});

	// An approval that applied a slightly different edit from the one described
	// would be exactly the failure the canonical hash exists to prevent.
	it("refuses an edit rather than reimplementing pi's replacement semantics", async () => {
		const backend = new RecordingBackend();
		const channel = io();
		const result = await approve({
			record: record("edit", { path: "/work/x", oldString: "a", newString: "b" }),
			stateRoot,
			current: profile(),
			home: "/home/u",
			io: channel.make(true),
			backend,
		});
		expect(result.outcome).toBe("unsupported");
		expect(channel.err.join("\n")).toContain("Re-run the task instead");
		expect(backend.commands).toHaveLength(0);
	});

	it("never asks when the resume checks already refused", async () => {
		const backend = new RecordingBackend();
		const channel = io();
		const result = await approve({
			record: record("bash", { command: "git push origin main" }),
			stateRoot,
			// Wider than the snapshot: nobody approved this version.
			current: profile((p) => {
				p.sandbox.writableRoots.push("/etc");
			}),
			home: "/home/u",
			io: channel.make(true),
			backend,
		});
		expect(result.outcome).toBe("refused");
		expect(channel.asked).toHaveLength(0);
		expect(backend.commands).toHaveLength(0);
	});

	// A pending write capability targets a path outside the writable roots (that
	// is why it was escalated); approving it must fold that path into a one-shot
	// writable root, or the approval reaches the same denial.
	it("applies an approved write capability as a one-shot writable root", async () => {
		const backend = new RecordingBackend();
		const p = profile();
		const rec = writePending({
			stateRoot,
			sessionId: SESSION,
			action: canonicalize({
				tool: "bash",
				input: { command: "touch /etc/x", allow_write: "/etc/x" },
				cwd: "/work",
				home: "/home/u",
				profileName: "dev",
			}),
			profile: p,
			configHash: configHash(p),
			reason: "capability",
			nonce: NONCE,
		}).record;
		const result = await approve({
			record: rec,
			stateRoot,
			current: profile(),
			home: "/home/u",
			io: io().make(true),
			backend,
			platform: "linux",
		});
		expect(result.outcome).toBe("executed");
		expect(backend.compiledProfile?.writableRoots).toContain("/etc/x");
	});

	it("leaves a credential-overlapping write capability pending without asking", async () => {
		const backend = new RecordingBackend();
		const channel = io();
		const result = await approve({
			record: record("bash", {
				command: "cat /home/u/.ssh/id_ed25519",
				allow_write: "/home/u/.ssh/out",
			}),
			stateRoot,
			current: profile(),
			home: "/home/u",
			io: channel.make(true),
			backend,
			platform: "linux",
		});
		expect(result.outcome).toBe("refused");
		expect(channel.asked).toHaveLength(0);
		expect(channel.err.join("\n")).toContain("immutable denied path");
		expect(readdirSync(pendingDirs(stateRoot, SESSION).pending)).toEqual([`${NONCE}.json`]);
		expect(backend.compiledProfile).toBeUndefined();
	});

	it("refuses a macOS Bash write capability whose widened process could detach", async () => {
		const backend = new RecordingBackend();
		const channel = io();
		const result = await approve({
			record: record("bash", { command: "touch /srv/result", allow_write: "/srv/result" }),
			stateRoot,
			current: profile(),
			home: "/home/u",
			io: channel.make(true),
			backend,
			platform: "darwin",
		});
		expect(result.outcome).toBe("refused");
		expect(channel.asked).toHaveLength(0);
		expect(channel.err.join("\n")).toContain("could outlive the invocation");
		expect(backend.compiledProfile).toBeUndefined();
	});

	it("refuses an unsupported capability before asking or consuming the record", async () => {
		const backend = new RecordingBackend();
		const channel = io();
		const result = await approve({
			record: record("bash", { command: "cat /etc/x", allow_read: "/etc/x" }),
			stateRoot,
			current: profile(),
			home: "/home/u",
			io: channel.make(true),
			backend,
		});
		expect(result.outcome).toBe("unsupported");
		expect(channel.asked).toHaveLength(0);
		expect(channel.err.join("\n")).toContain("Phase 3/4");
		expect(readdirSync(pendingDirs(stateRoot, SESSION).pending)).toEqual([`${NONCE}.json`]);
		expect(backend.compiledProfile).toBeUndefined();
	});

	it("refuses capability metadata that differs from the hash-checked input", async () => {
		const backend = new RecordingBackend();
		const rec = record("bash", { command: "touch /srv/x", allow_write: "/srv/x" });
		rec.action.capability = { kind: "write", value: "/etc" };
		const result = await approve({
			record: rec,
			stateRoot,
			current: profile(),
			home: "/home/u",
			io: io().make(true),
			backend,
			assumeYes: true,
		});
		expect(result.outcome).toBe("refused");
		expect(backend.compiledProfile).toBeUndefined();
		expect(readdirSync(pendingDirs(stateRoot, SESSION).pending)).toEqual([`${NONCE}.json`]);
	});

	// It changes what the person is agreeing to, so it comes before the
	// question rather than after it.
	it("warns about a narrowed configuration before asking", async () => {
		const channel = io();
		await approve({
			record: record("bash", { command: "ls" }),
			stateRoot,
			current: profile((p) => {
				p.sandbox.writableRoots = ["/work"];
			}),
			home: "/home/u",
			io: channel.make(false),
			backend: new RecordingBackend(),
		});
		const text = channel.out.join("\n");
		expect(text).toContain("narrowed since this was recorded");
		expect(text).toContain("/tmp");
		expect(text.indexOf("narrowed")).toBeLessThan(text.length);
		expect(channel.asked).toHaveLength(1);
	});
});
