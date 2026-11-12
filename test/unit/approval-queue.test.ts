/**
 * The approval queue and the notify hook (#30).
 */
import { EventEmitter } from "node:events";
import {
	chmodSync,
	existsSync,
	mkdirSync,
	mkdtempSync,
	readdirSync,
	readFileSync,
	rmSync,
	writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PassThrough } from "node:stream";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { approveQueued, decline, locateUndecided } from "../../src/cli/decide.ts";
import { defaultProfile, OWNED_TOOLS } from "../../src/config/defaults.ts";
import type { EffectiveProfile } from "../../src/config/types.ts";
import { resolveAttendance } from "../../src/escalate/attendance.ts";
import { createConfirmEscalator } from "../../src/escalate/confirm.ts";
import {
	checkNotifyProgram,
	createNotifier,
	envToolName,
	type NotifySpawn,
	notificationText,
	SUMMARY_LIMIT,
} from "../../src/escalate/notify.ts";
import { dirFor, type PendingRecord, readPending, transition, writePending } from "../../src/escalate/pending.ts";
import { claimQueued, createQueueEscalation, waiterAlive, waitForDecision } from "../../src/escalate/queue.ts";
import { DENY_ESCALATOR, decide, type Escalator } from "../../src/gate/gate.ts";
import { ActionLock } from "../../src/gate/lock.ts";
import { canonicalize } from "../../src/policy/canonical.ts";
import { configHash } from "../../src/state/audit.ts";

const OPTIONS = { cwd: "/work", home: "/nonexistent-home/u", tmp: "/tmp", agentDir: "/nonexistent-home/u/.pi/agent" };
const HOME = OPTIONS.home;
const SESSION = "session-q";
const NONCE = "0123456789abcdef0123456789abcdef";

let stateRoot: string;

beforeEach(() => {
	stateRoot = mkdtempSync(join(tmpdir(), "enclave-queue-"));
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
	canonicalize({ tool: "bash", input: { command }, cwd: "/work", home: HOME, profileName: "dev" });

function queue(until = Date.now() + 60_000, p = profile()) {
	return writePending({
		stateRoot,
		sessionId: SESSION,
		action: action(),
		profile: p,
		configHash: configHash(p),
		reason: "needs a person",
		nonce: NONCE,
		waiter: { pid: process.pid, until: new Date(until).toISOString() },
	});
}

const at = (state: Parameters<typeof dirFor>[2]) =>
	existsSync(join(dirFor(stateRoot, SESSION, state), `${NONCE}.json`));

describe("waiting for a decision", () => {
	it("writes a queued record that names the waiting process", () => {
		const { record, path } = queue();
		expect(path).toBe(join(dirFor(stateRoot, SESSION, "queued"), `${NONCE}.json`));
		expect(record.waiter?.pid).toBe(process.pid);
		expect(readPending({ stateRoot, sessionId: SESSION, nonce: NONCE, state: "queued" }).ok).toBe(true);
		// Not visible as an ordinary pending record while the session waits.
		expect(at("pending")).toBe(false);
	});

	it("returns approved once the record is moved to approved/", async () => {
		queue();
		setTimeout(() => claimQueued(stateRoot, SESSION, NONCE, "approved"), 30);
		const outcome = await waitForDecision({
			stateRoot,
			sessionId: SESSION,
			nonce: NONCE,
			until: Date.now() + 5_000,
			pollMs: 5,
		});
		expect(outcome).toBe("approved");
	});

	it("returns declined once the record is moved to declined/", async () => {
		queue();
		setTimeout(() => claimQueued(stateRoot, SESSION, NONCE, "declined"), 30);
		expect(
			await waitForDecision({ stateRoot, sessionId: SESSION, nonce: NONCE, until: Date.now() + 5_000, pollMs: 5 }),
		).toBe("declined");
	});

	it("gives up at the deadline and leaves an ordinary pending record", async () => {
		queue();
		expect(
			await waitForDecision({ stateRoot, sessionId: SESSION, nonce: NONCE, until: Date.now() + 40, pollMs: 5 }),
		).toBe("timeout");
		expect(at("queued")).toBe(false);
		const pending = readPending({ stateRoot, sessionId: SESSION, nonce: NONCE });
		expect(pending.ok).toBe(true);
		// Without its waiter: an out-of-session approval of it is not a queue
		// approval a later lookup may take back.
		expect(pending.ok && pending.record.waiter).toBeUndefined();
		// A decision that arrives after the session gave up has nothing to claim.
		expect(claimQueued(stateRoot, SESSION, NONCE, "approved")).toBe(false);
		expect(at("approved")).toBe(false);
	});

	it("stops waiting when the turn is aborted", async () => {
		queue();
		const controller = new AbortController();
		setTimeout(() => controller.abort(), 20);
		expect(
			await waitForDecision({
				stateRoot,
				sessionId: SESSION,
				nonce: NONCE,
				until: Date.now() + 60_000,
				signal: controller.signal,
			}),
		).toBe("aborted");
		expect(at("pending")).toBe(true);
	});

	it("honours a decision that landed before the session could give up", async () => {
		queue();
		claimQueued(stateRoot, SESSION, NONCE, "approved");
		// Past the deadline already: the give-up rename loses, and the decision stands.
		expect(await waitForDecision({ stateRoot, sessionId: SESSION, nonce: NONCE, until: 0, pollMs: 5 })).toBe(
			"approved",
		);
		expect(at("pending")).toBe(false);
	});

	it("treats a record that vanished as a refusal", async () => {
		queue();
		rmSync(join(dirFor(stateRoot, SESSION, "queued"), `${NONCE}.json`));
		expect(
			await waitForDecision({ stateRoot, sessionId: SESSION, nonce: NONCE, until: Date.now() + 5_000, pollMs: 5 }),
		).toBe("declined");
	});

	it("reads a waiter as gone once its time is up or its process is", () => {
		const { record } = queue(Date.now() + 60_000);
		expect(waiterAlive(record)).toBe(true);
		expect(waiterAlive(record, Date.now() + 61_000)).toBe(false);
		expect(waiterAlive(record, Date.now(), () => false)).toBe(false);
		const { waiter: _waiter, ...unqueued } = record;
		expect(waiterAlive(unqueued)).toBe(false);
	});
});

describe("the session side", () => {
	function escalation(current: () => EffectiveProfile | undefined, sessionProfile = profile()) {
		const events: Record<string, unknown>[] = [];
		const queued: PendingRecord[] = [];
		const run = createQueueEscalation({
			stateRoot: () => stateRoot,
			sessionId: () => SESSION,
			profile: () => sessionProfile,
			reload: current,
			home: HOME,
			timeoutMs: () => 5_000,
			audit: (_kind, fields) => events.push(fields),
			onQueued: (record) => {
				queued.push(record);
				// The other terminal: approve as soon as the record exists.
				setTimeout(() => claimQueued(stateRoot, SESSION, record.nonce, "approved"), 10);
			},
			stderr: () => {},
			pollMs: 5,
		});
		return { run, events, queued };
	}

	it("runs an approved call once: the record ends in consumed/", async () => {
		const { run, queued } = escalation(() => profile());
		expect(await run(action(), "needs a person")).toBe("approved");
		const nonce = queued[0]?.nonce ?? "";
		expect(readPending({ stateRoot, sessionId: SESSION, nonce, state: "consumed" }).ok).toBe(true);
		expect(readPending({ stateRoot, sessionId: SESSION, nonce, state: "approved" }).ok).toBe(false);
	});

	// The same checks checkResume applies out of session (pending.test.ts),
	// against the configuration as it is on disk when the decision arrives.
	it.each([
		[
			"a rule added since denies it",
			(p: EffectiveProfile) => p.rules.deny.push("bash(git push *)"),
			"denies this action",
		],
		["the profile was widened", (p: EffectiveProfile) => p.sandbox.writableRoots.push("/etc"), "widened"],
		[
			"a read denial was lifted",
			(p: EffectiveProfile) => {
				p.sandbox.readDeny = p.sandbox.readDeny.filter((path) => !path.endsWith(".ssh"));
			},
			"widened",
		],
		[
			"the tool grant was removed",
			(p: EffectiveProfile) => {
				delete p.tools.allow.bash;
			},
			"no longer authorizes this tool",
		],
		// Narrower is fine out of session, which then runs under the narrower
		// profile. The session cannot, so it refuses instead of running wider.
		[
			"the profile was narrowed",
			(p: EffectiveProfile) => {
				p.sandbox.readDeny.push("/work/secrets");
			},
			"changed while this call waited",
		],
	])("refuses when %s, and returns the record to pending", async (_name, edit, reason) => {
		const { run, events, queued } = escalation(() => profile(edit));
		expect(await run(action(), "needs a person")).toBe("declined");
		const nonce = queued[0]?.nonce ?? "";
		expect(events.find((event) => event.event === "resume-refused")?.reason).toContain(reason);
		expect(readPending({ stateRoot, sessionId: SESSION, nonce }).ok).toBe(true);
		expect(readPending({ stateRoot, sessionId: SESSION, nonce, state: "consumed" }).ok).toBe(false);
	});

	it("refuses when the configuration cannot be reloaded", async () => {
		const { run, events } = escalation(() => undefined);
		expect(await run(action(), "needs a person")).toBe("declined");
		expect(events.find((event) => event.event === "resume-refused")?.reason).toContain("could not be reloaded");
	});

	it("refuses an approved record whose action was edited on disk", async () => {
		const events: Record<string, unknown>[] = [];
		const run = createQueueEscalation({
			stateRoot: () => stateRoot,
			sessionId: () => SESSION,
			profile: () => profile(),
			reload: () => profile(),
			home: HOME,
			timeoutMs: () => 5_000,
			audit: (_kind, fields) => events.push(fields),
			onQueued: (record, path) => {
				const edited = JSON.parse(readFileSync(path, "utf8")) as PendingRecord;
				edited.action.input = { command: "rm -rf /" };
				writeFileSync(path, JSON.stringify(edited), { mode: 0o600 });
				setTimeout(() => claimQueued(stateRoot, SESSION, record.nonce, "approved"), 10);
			},
			stderr: () => {},
			pollMs: 5,
		});
		expect(await run(action(), "needs a person")).toBe("declined");
		expect(String(events.find((event) => event.event === "resume-refused")?.reason)).toMatch(
			/not the action this call is holding|was edited/,
		);
	});

	it("times out to a refusal and leaves the record for an out-of-session approval", async () => {
		const run = createQueueEscalation({
			stateRoot: () => stateRoot,
			sessionId: () => SESSION,
			profile: () => profile(),
			reload: () => profile(),
			home: HOME,
			timeoutMs: () => 30,
			stderr: () => {},
			pollMs: 5,
		});
		expect(await run(action(), "needs a person")).toBe("timeout");
		const [name] = readdirSync(dirFor(stateRoot, SESSION, "pending"));
		expect(name).toMatch(/^[0-9a-f]{32}\.json$/);
	});
});

describe("the gate in queue mode", () => {
	const PROFILE = profile();
	const queueAttendance = resolveAttendance("queue", { mode: "print", hasUI: false, hasTty: false });

	function gate(escalator: Escalator) {
		return decide(
			{ toolName: "bash", toolCallId: "call-1", input: { command: "git push --force origin main" } },
			{ profile: PROFILE, cwd: "/work", home: HOME, lock: new ActionLock(), owned: OWNED_TOOLS, escalator },
		);
	}

	function queued(answer: "approved" | "declined" | "timeout") {
		return createConfirmEscalator({
			ui: () => undefined,
			attendance: () => queueAttendance,
			confirmTimeoutMs: () => 1_000,
			queue: async () => answer,
		});
	}

	it("holds in every pi mode, headless included", () => {
		for (const mode of ["tui", "rpc", "json", "print"] as const) {
			expect(resolveAttendance("queue", { mode, hasUI: false, hasTty: false }).effective).toBe("queue");
		}
	});

	it("lets an approved call through to run in the session", async () => {
		const decision = await gate(queued("approved"));
		expect(decision).toMatchObject({ outcome: "ask-approved", block: false });
	});

	it.each(["declined", "timeout"] as const)("refuses a %s request with today's denial text", async (answer) => {
		const today = await gate(DENY_ESCALATOR);
		const decision = await gate(queued(answer));
		expect(decision).toMatchObject({ outcome: "ask-denied", block: true, terminate: true, adverse: true });
		expect(decision.reason).toBe(today.reason);
	});
});

describe("answering from another terminal", () => {
	const io = () => {
		const out: string[] = [];
		const err: string[] = [];
		return {
			out,
			err,
			io: { out: (t: string) => out.push(t), err: (t: string) => err.push(t), ask: async () => true },
		};
	};

	it("records an approval for a waiting session without running anything", async () => {
		const { record } = queue();
		const audit: Record<string, unknown>[] = [];
		const { io: terminal, out } = io();
		const result = await approveQueued({
			record,
			stateRoot,
			current: profile(),
			home: HOME,
			io: terminal,
			audit: (fields) => audit.push(fields),
			approver: () => ({ uid: 1000, user: "ops", tty: "/dev/pts/3" }),
			pickupMs: 0,
		});
		expect(result).toEqual({ outcome: "approved", ran: false });
		expect(at("approved")).toBe(true);
		expect(out.join("\n")).toContain(`"git push --force origin main"`);
		expect(audit).toEqual([
			expect.objectContaining({ event: "queue-approved", nonce: NONCE, uid: 1000, user: "ops", tty: "/dev/pts/3" }),
		]);
	});

	it("does not decide for a session that stopped waiting", async () => {
		const { record } = queue();
		const result = await approveQueued({
			record,
			stateRoot,
			current: profile(),
			home: HOME,
			io: io().io,
			alive: () => false,
			pickupMs: 0,
		});
		expect(result).toEqual({ outcome: "not-waiting" });
		expect(at("approved")).toBe(false);
	});

	it("refuses before asking when the session would refuse", async () => {
		const { record } = queue();
		const asked: string[] = [];
		const terminal = {
			...io().io,
			ask: async (question: string) => {
				asked.push(question);
				return true;
			},
		};
		const result = await approveQueued({
			record,
			stateRoot,
			current: profile((p) => p.rules.deny.push("bash(git push *)")),
			home: HOME,
			io: terminal,
			pickupMs: 0,
		});
		expect(result.outcome).toBe("refused");
		expect(asked).toEqual([]);
		expect(at("queued")).toBe(true);
	});

	it("decides nothing when audit.required cannot record the approval", async () => {
		const { record } = queue();
		const result = await approveQueued({
			record,
			stateRoot,
			current: profile(),
			home: HOME,
			io: io().io,
			audit: () => false,
			pickupMs: 0,
		});
		expect(result.outcome).toBe("refused");
		expect(at("queued")).toBe(true);
	});

	// Review of #69: a decision that lost the rename was logged as if it had
	// taken effect.
	it("logs an approval that lost the race with the session giving up", async () => {
		const { record } = queue();
		const audit: Record<string, unknown>[] = [];
		const { io: terminal, err } = io();
		const result = await approveQueued({
			record,
			stateRoot,
			current: profile(),
			home: HOME,
			io: terminal,
			audit: (fields) => {
				audit.push(fields);
				// The session times out between the log line and the claim.
				if (fields.event === "queue-approved") claimQueued(stateRoot, SESSION, NONCE, "pending");
			},
			pickupMs: 0,
		});
		expect(result).toEqual({ outcome: "not-waiting" });
		expect(audit.map((entry) => entry.event)).toEqual(["queue-approved", "queue-approved-lost"]);
		expect(err.join("\n")).toContain("Nothing was decided");
	});

	it("logs a decline that lost the race, and says the record is pending now", async () => {
		const { record } = queue();
		const audit: Record<string, unknown>[] = [];
		const { io: terminal, err } = io();
		const result = await decline({
			record,
			state: "queued",
			stateRoot,
			current: profile(),
			home: HOME,
			io: terminal,
			audit: (fields) => {
				audit.push(fields);
				if (fields.event === "declined") claimQueued(stateRoot, SESSION, NONCE, "pending");
			},
		});
		expect(result).toEqual({ outcome: "not-waiting" });
		expect(audit.map((entry) => entry.event)).toEqual(["declined", "declined-lost"]);
		expect(err.join("\n")).toContain("the record is pending now");
		expect(err.join("\n")).toContain(`pi-enclave decline ${NONCE}\` again`);
		expect(at("pending")).toBe(true);
	});

	it("says a narrowed configuration may be refused, not that it will be", async () => {
		const { record } = queue();
		const { io: terminal, out } = io();
		await approveQueued({
			record,
			stateRoot,
			current: profile((p) => p.sandbox.readDeny.push("/work/secrets")),
			home: HOME,
			io: terminal,
			pickupMs: 0,
		});
		expect(out.join("\n")).toContain("so it may refuse this");
	});

	// Review of #69: an approved record its session never took up could not be
	// found by approve, decline or pending.
	describe("an approval whose session ended before running it", () => {
		const approveFor = async () => {
			const { record } = queue();
			await approveQueued({ record, stateRoot, current: profile(), home: HOME, io: io().io, pickupMs: 0 });
			expect(at("approved")).toBe(true);
		};

		it("goes back to pending without its waiter, where approve and decline find it", async () => {
			await approveFor();
			// Still waited on: left where it is, for the session to take up.
			expect(locateUndecided(stateRoot, NONCE, Date.now, () => true)).toBeUndefined();
			expect(at("approved")).toBe(true);
			const located = locateUndecided(stateRoot, NONCE, Date.now, () => false);
			expect(located).toMatchObject({ state: "pending", recovered: true });
			expect(located?.record.waiter).toBeUndefined();
			expect(at("approved")).toBe(false);
			expect(at("pending")).toBe(true);
		});

		it("is not taken back once the session has consumed it", async () => {
			await approveFor();
			transition(stateRoot, SESSION, NONCE, "approved", "consumed");
			expect(locateUndecided(stateRoot, NONCE, Date.now, () => false)).toBeUndefined();
			expect(at("consumed")).toBe(true);
			expect(at("pending")).toBe(false);
		});

		it("leaves an out-of-session approval alone, even of a record that once waited", async () => {
			// Queued, timed out (back to pending), then approved out of session:
			// that one may have run, so nothing may take it back.
			queue();
			expect(
				await waitForDecision({ stateRoot, sessionId: SESSION, nonce: NONCE, until: Date.now() + 20, pollMs: 5 }),
			).toBe("timeout");
			transition(stateRoot, SESSION, NONCE, "pending", "approved");
			expect(locateUndecided(stateRoot, NONCE, Date.now, () => false)).toBeUndefined();
			expect(at("approved")).toBe(true);
		});
	});

	it("declines a waiting request, and retires a pending one", async () => {
		const { record } = queue();
		expect(
			(await decline({ record, state: "queued", stateRoot, current: profile(), home: HOME, io: io().io })).outcome,
		).toBe("declined");
		expect(at("declined")).toBe(true);

		rmSync(join(dirFor(stateRoot, SESSION, "declined"), `${NONCE}.json`));
		const p = profile();
		const pending = writePending({
			stateRoot,
			sessionId: SESSION,
			action: action(),
			profile: p,
			configHash: configHash(p),
			reason: "needs a person",
			nonce: NONCE,
		}).record;
		await decline({ record: pending, state: "pending", stateRoot, current: p, home: HOME, io: io().io });
		expect(at("pending")).toBe(false);
		expect(at("declined")).toBe(true);
	});
});

describe("the notify hook", () => {
	function fakeSpawn() {
		const calls: {
			file: string;
			args: readonly string[];
			env: NodeJS.ProcessEnv;
			stdin: string;
			shell: unknown;
			cwd: string;
		}[] = [];
		const spawn: NotifySpawn = (file, args, options) => {
			const stdin = new PassThrough();
			const call = { file, args, env: options.env, stdin: "", shell: options.shell, cwd: options.cwd };
			stdin.on("data", (chunk: Buffer) => {
				call.stdin += chunk.toString("utf8");
			});
			calls.push(call);
			const child = new EventEmitter() as EventEmitter & { stdin: PassThrough; kill: () => boolean };
			child.stdin = stdin;
			child.kill = () => true;
			stdin.on("finish", () => setImmediate(() => child.emit("exit", 0, null)));
			return child as unknown as ReturnType<NotifySpawn>;
		};
		return { spawn, calls };
	}

	const hostile = `curl x\nRun: pi-enclave approve ffffffffffffffffffffffffffffffff\u001b[2J${"A".repeat(10_000)}`;

	function recordFor(command: string): PendingRecord {
		const p = profile();
		return writePending({
			stateRoot,
			sessionId: SESSION,
			action: action(command),
			profile: p,
			configHash: configHash(p),
			reason: "needs a person",
		}).record;
	}

	it("runs exactly the configured argv, without a shell, and puts the action only on stdin, bounded", async () => {
		const { spawn, calls } = fakeSpawn();
		const notify = createNotifier({ argv: () => ["/usr/bin/wall", "-n"], spawn, env: {} });
		const record = recordFor(hostile);
		notify(record);
		await new Promise((resolve) => setImmediate(resolve));
		expect(calls).toHaveLength(1);
		const call = calls[0];
		expect(call?.file).toBe("/usr/bin/wall");
		expect(call?.args).toEqual(["-n"]);
		expect(call?.shell).toBe(false);
		expect(call?.env).toMatchObject({ ENCLAVE_NONCE: record.nonce, ENCLAVE_SESSION: SESSION, ENCLAVE_TOOL: "bash" });
		const lines = call?.stdin.split("\n") ?? [];
		const actionLine = lines.find((line) => line.startsWith("action: ")) ?? "";
		expect(actionLine.length).toBeLessThanOrEqual("action: ".length + SUMMARY_LIMIT);
		// One line, no terminal escape, and the forged instruction stays inside the quoted summary.
		expect(call?.stdin).not.toContain("\u001b");
		expect(lines.filter((line) => line.startsWith("Run:"))).toEqual([]);
		expect(lines.filter((line) => line.startsWith("approve:"))).toEqual([
			`approve: pi-enclave approve ${record.nonce}`,
		]);
	});

	it("notifies at most once per interval, and says how many came with the held one", async () => {
		vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout", "Date"], now: 0 });
		try {
			const { spawn, calls } = fakeSpawn();
			const events: Record<string, unknown>[] = [];
			const notify = createNotifier({
				argv: () => ["/usr/bin/true"],
				spawn,
				env: {},
				now: () => Date.now(),
				minIntervalMs: 30_000,
				onEvent: (fields) => events.push(fields),
			});
			notify(recordFor("echo one"));
			vi.setSystemTime(1_000);
			notify(recordFor("echo two"));
			const three = recordFor("echo three");
			notify(three);
			expect(calls).toHaveLength(1);
			// The end of the interval announces the newest, with the count.
			await vi.advanceTimersByTimeAsync(29_000);
			expect(calls).toHaveLength(2);
			expect(calls[1]?.env.ENCLAVE_NONCE).toBe(three.nonce);
			expect(calls[1]?.stdin).toContain("(and 1 other request(s) since the last notification");
			// The next one inside the new interval waits for its end, too.
			vi.setSystemTime(31_000);
			notify(recordFor("echo four"));
			expect(calls).toHaveLength(2);
			await vi.advanceTimersByTimeAsync(30_000);
			expect(calls).toHaveLength(3);
			expect(calls[2]?.stdin).not.toContain("other request(s)");
			expect(events.filter((event) => event.event === "notify-deferred")).toHaveLength(3);
		} finally {
			vi.useRealTimers();
		}
	});

	// Review of #69: a request inside the interval was never announced, and the
	// session waited its whole timeout with nobody told.
	it("announces a request held by the rate limit with no further ask", async () => {
		vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout", "Date"], now: 0 });
		try {
			const { spawn, calls } = fakeSpawn();
			const notify = createNotifier({ argv: () => ["/usr/bin/true"], spawn, env: {}, now: () => Date.now() });
			notify(recordFor("echo first"));
			vi.setSystemTime(20_000);
			const second = recordFor("echo second");
			notify(second);
			await vi.advanceTimersByTimeAsync(10_000);
			expect(calls.map((call) => call.env.ENCLAVE_NONCE)).toContain(second.nonce);
			await vi.advanceTimersByTimeAsync(3_600_000);
			expect(calls).toHaveLength(2);
		} finally {
			vi.useRealTimers();
		}
	});

	it("sends a held request at once on flush, as at session shutdown", () => {
		const { spawn, calls } = fakeSpawn();
		let clock = 0;
		const notify = createNotifier({ argv: () => ["/usr/bin/true"], spawn, env: {}, now: () => clock });
		notify(recordFor("echo first"));
		clock = 5_000;
		const second = recordFor("echo second");
		notify(second);
		expect(calls).toHaveLength(1);
		notify.flush();
		expect(calls).toHaveLength(2);
		expect(calls[1]?.env.ENCLAVE_NONCE).toBe(second.nonce);
		notify.flush();
		expect(calls).toHaveLength(2);
	});

	it("runs the hook in /, never in the workspace", () => {
		const { spawn, calls } = fakeSpawn();
		createNotifier({ argv: () => ["/usr/bin/true"], spawn, env: {} })(recordFor("echo one"));
		expect(calls[0]?.cwd).toBe("/");
	});

	// Review of #69: `python3 -m notifymod` loaded a module the agent wrote in
	// the workspace, outside the sandbox.
	it.skipIf(!existsSync("/usr/bin/python3"))(
		"does not load a module from the process's working directory (real spawn)",
		async () => {
			const workspace = join(stateRoot, "workspace");
			const marker = join(stateRoot, "marker");
			mkdirSync(workspace);
			writeFileSync(join(workspace, "notifymod.py"), `open(${JSON.stringify(marker)}, "w").write("ran")\n`);
			const before = process.cwd();
			process.chdir(workspace);
			try {
				const done = new Promise<Record<string, unknown>>((resolve) => {
					const notify = createNotifier({
						argv: () => ["/usr/bin/python3", "-m", "notifymod"],
						onEvent: (fields) => {
							if (fields.event !== "notify-deferred") resolve(fields);
						},
					});
					notify(recordFor("echo one"));
				});
				const event = await done;
				expect(event.event).toBe("notify-sent");
				expect(event.exitCode).not.toBe(0);
				expect(existsSync(marker)).toBe(false);
			} finally {
				process.chdir(before);
			}
		},
	);

	it("puts the tool name in the environment only when it is a plain identifier", () => {
		expect(envToolName("bash")).toBe("bash");
		expect(envToolName("mcp__github__get_file")).toBe("mcp__github__get_file");
		expect(envToolName("mcp__x\n$(id)")).toBe("other");
		expect(envToolName("x".repeat(65))).toBe("other");
		const { spawn, calls } = fakeSpawn();
		const p = profile();
		const odd = canonicalize({
			tool: "mcp__x\n$(id)",
			input: { path: "a" },
			cwd: "/work",
			home: HOME,
			profileName: "dev",
		});
		const record = writePending({
			stateRoot,
			sessionId: SESSION,
			action: odd,
			profile: p,
			configHash: configHash(p),
			reason: "needs a person",
		}).record;
		createNotifier({ argv: () => ["/usr/bin/true"], spawn, env: {} })(record);
		expect(calls[0]?.env.ENCLAVE_TOOL).toBe("other");
	});

	it("warns at session start when the program is missing or cannot run", () => {
		expect(checkNotifyProgram([])).toBeUndefined();
		expect(checkNotifyProgram(["/bin/sh"])).toBeUndefined();
		expect(checkNotifyProgram([join(stateRoot, "missing")])).toContain("which does not exist");
		const plain = join(stateRoot, "plain");
		writeFileSync(plain, "#!/bin/sh\n");
		chmodSync(plain, 0o600);
		expect(checkNotifyProgram([plain])).toContain("which is not executable");
		expect(checkNotifyProgram([stateRoot])).toContain("which is not a file");
	});

	it("does nothing without a configured command", () => {
		const { spawn, calls } = fakeSpawn();
		createNotifier({ argv: () => [], spawn })(recordFor("echo one"));
		expect(calls).toEqual([]);
	});

	it("tells a waiting session's approver how to decline", () => {
		const { record } = queue();
		expect(notificationText(record, 0)).toContain(`decline: pi-enclave decline ${NONCE}`);
	});
});
