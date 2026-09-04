import { describe, expect, it } from "vitest";
import type { AttendedMode } from "../../src/config/types.ts";
import {
	type AttendanceEnvironment,
	type AttendanceState,
	describeAttendance,
	recheckAttendance,
	resolveAttendance,
} from "../../src/escalate/attendance.ts";
import { createConfirmEscalator, type EscalationEvent } from "../../src/escalate/confirm.ts";
import { describeHandshakeFailure, expectedProof, runHandshake } from "../../src/escalate/handshake.ts";
import { canonicalize } from "../../src/policy/canonical.ts";
import { FakeUI } from "../harness/fake-pi.ts";

const env = (overrides: Partial<AttendanceEnvironment> = {}): AttendanceEnvironment => ({
	mode: "tui",
	hasUI: true,
	hasTty: true,
	...overrides,
});

describe("resolving attendance", () => {
	it("off is always off", () => {
		expect(resolveAttendance("off", env()).effective).toBe("off");
	});

	it("tui at a terminal is attended", () => {
		expect(resolveAttendance("tui", env()).effective).toBe("tui");
	});

	// The user said a person would be at a terminal. If that is not true, the
	// configuration describes a different situation from the real one, and
	// continuing as "off" would leave them waiting for a dialog never coming.
	it("tui without a terminal is fatal, not a downgrade", () => {
		const state = resolveAttendance("tui", env({ hasTty: false }));
		expect(state.effective).toBe("off");
		expect(state.fatal).toBe(true);
	});

	it("tui in rpc mode is fatal", () => {
		expect(resolveAttendance("tui", env({ mode: "rpc" })).fatal).toBe(true);
	});

	// hasUI is true in rpc mode too, which is exactly why attendance cannot be
	// inferred from it. Without a handshake the client is not a console.
	it("rpc without a handshake degrades to off", () => {
		const state = resolveAttendance("rpc", env({ mode: "rpc" }));
		expect(state.effective).toBe("off");
		expect(state.fatal).toBeUndefined();
		expect(state.reason).toContain("handshake");
	});

	it("rpc with a verified handshake is attended", () => {
		expect(resolveAttendance("rpc", env({ mode: "rpc", handshakeVerified: true })).effective).toBe("rpc");
	});

	it.each(["json", "print"] as const)("%s mode is always off, whatever was configured", (mode) => {
		for (const configured of ["tui", "rpc"] as AttendedMode[]) {
			const state = resolveAttendance(configured, env({ mode, hasUI: false }));
			expect(state.effective).toBe("off");
			expect(state.reason).toContain(mode);
		}
	});

	it("says what is in force and what was asked for", () => {
		const state = resolveAttendance("rpc", env({ mode: "rpc" }));
		expect(describeAttendance(state)).toContain("configured rpc");
		expect(describeAttendance(resolveAttendance("tui", env()))).toBe("tui");
	});
});

describe("rechecking attendance mid-session", () => {
	const attended = (effective: AttendedMode): AttendanceState => ({ configured: effective, effective });

	it("degrades when the terminal is lost", () => {
		const state = recheckAttendance(attended("tui"), env({ hasTty: false }));
		expect(state.effective).toBe("off");
		expect(state.reason).toContain("terminal was lost");
	});

	it("degrades when the RPC client disconnects", () => {
		const state = recheckAttendance(attended("rpc"), env({ mode: "rpc", hasUI: false }));
		expect(state.effective).toBe("off");
	});

	// A channel that dropped once is not one to start trusting again mid-run.
	it("never recovers toward attended", () => {
		const degraded: AttendanceState = { configured: "tui", effective: "off", reason: "lost" };
		expect(recheckAttendance(degraded, env()).effective).toBe("off");
	});

	it("leaves a healthy session alone", () => {
		expect(recheckAttendance(attended("tui"), env()).effective).toBe("tui");
	});
});

describe("the handshake", () => {
	const SECRET = Buffer.alloc(32, 7).toString("base64");
	const NONCE = "abcdef0123456789";
	const SESSION = "session-1";

	function handshake(answer: string | undefined, overrides = {}) {
		const ui = new FakeUI({ input: () => answer });
		return {
			ui,
			run: () =>
				runHandshake({
					ui,
					sessionId: SESSION,
					secretPath: "/state/attend.secret",
					nonce: NONCE,
					readSecret: () => SECRET,
					checkFile: () => undefined,
					...overrides,
				}),
		};
	}

	it("verifies a correct proof", async () => {
		const proof = expectedProof(Buffer.from(SECRET, "base64"), NONCE, SESSION);
		const { run } = handshake(proof);
		expect(await run()).toEqual({ verified: true });
	});

	it("puts the nonce where a client can find it", async () => {
		const { ui, run } = handshake("x");
		await run();
		expect(ui.inputs[0]?.title).toContain(NONCE);
		expect(ui.inputs[0]?.placeholder).toBe(NONCE);
		expect(ui.inputs[0]?.timeout).toBe(10_000);
	});

	it("rejects a wrong proof", async () => {
		const { run } = handshake(Buffer.alloc(44, 1).toString("base64"));
		expect(await run()).toEqual({ verified: false, reason: "bad-mac" });
	});

	// A client that knows nothing about the protocol sees a prompt it cannot
	// answer. That is the expected state today and the safe one.
	it("treats no answer as a failure", async () => {
		expect(await handshake(undefined).run()).toEqual({ verified: false, reason: "timeout" });
	});

	it("binds the proof to the session", async () => {
		const proof = expectedProof(Buffer.from(SECRET, "base64"), NONCE, "a-different-session");
		expect(await handshake(proof).run()).toEqual({ verified: false, reason: "bad-mac" });
	});

	it("binds the proof to the nonce, so a recorded one cannot be replayed", async () => {
		const proof = expectedProof(Buffer.from(SECRET, "base64"), "an-older-nonce", SESSION);
		expect(await handshake(proof).run()).toEqual({ verified: false, reason: "bad-mac" });
	});

	// Once, deliberately: a retry loop lets a client brute-force the proof.
	it("asks exactly once", async () => {
		const { ui, run } = handshake("wrong");
		await run();
		expect(ui.inputs).toHaveLength(1);
	});

	describe("the secret file", () => {
		it("reports a missing secret distinctly from an insecure one", async () => {
			const missing = await handshake("x", { checkFile: () => "/state/attend.secret does not exist" }).run();
			expect(missing).toEqual({ verified: false, reason: "no-secret" });

			const insecure = await handshake("x", { checkFile: () => "/state/attend.secret has mode 644" }).run();
			expect(insecure).toEqual({ verified: false, reason: "insecure-secret" });
		});

		it("refuses a short secret", async () => {
			const short = await handshake("x", { readSecret: () => Buffer.alloc(8).toString("base64") }).run();
			expect(short).toEqual({ verified: false, reason: "insecure-secret" });
		});

		it("never asks the client when the secret is unusable", async () => {
			const { ui, run } = handshake("x", { checkFile: () => "does not exist" });
			await run();
			expect(ui.inputs).toHaveLength(0);
		});
	});

	it("explains every failure in terms the operator can act on", () => {
		for (const reason of ["no-secret", "insecure-secret", "timeout", "cancelled", "bad-mac"] as const) {
			expect(describeHandshakeFailure(reason).length).toBeGreaterThan(20);
		}
		expect(describeHandshakeFailure("no-secret")).toContain("attend-secret");
	});
});

describe("the confirm escalator", () => {
	const action = canonicalize({
		tool: "bash",
		input: { command: "git push --force origin main" },
		cwd: "/work",
		home: "/home/u",
		profileName: "dev",
	});

	/** `answer` is always a thunk, so a slow reply and a plain yes take one path. */
	function escalator(options: { attended: AttendedMode; answer?: () => Promise<boolean>; timeoutMs?: number }) {
		const events: EscalationEvent[] = [];
		const unattended: string[] = [];
		const ui = new FakeUI();
		const answer = options.answer ?? (() => Promise.resolve(false));

		return {
			ui,
			events,
			unattended,
			escalator: createConfirmEscalator({
				ui: () => ({
					confirm: async (title, message, opts) => {
						ui.confirms.push({ title, message, ...(opts?.timeout !== undefined ? { timeout: opts.timeout } : {}) });
						return answer();
					},
				}),
				attendance: () => ({ configured: options.attended, effective: options.attended }),
				confirmTimeoutMs: () => options.timeoutMs ?? 300_000,
				onEscalation: (event) => events.push(event),
				onUnattended: (a, reason, toolSource) => {
					unattended.push(`${a.hash}:${reason}:${toolSource ?? "unknown"}`);
				},
			}),
		};
	}

	it("approves when the person says yes", async () => {
		const { escalator: esc, events } = escalator({ attended: "tui", answer: async () => true });
		expect(await esc.confirm(action, "matches ask rule")).toBe(true);
		expect(events[0]?.outcome).toBe("approved");
	});

	it("shows complete terminal-safe input in the attended confirmation", async () => {
		const content = `${"A".repeat(300)}ERASE-PRODUCTION${"Z".repeat(300)}`;
		const reviewed = canonicalize({
			tool: "write",
			input: { path: "/work/prod", content, note: "safe\u202Eliated" },
			cwd: "/work",
			home: "/home/u",
			profileName: "dev",
		});
		const { escalator: esc, ui } = escalator({ attended: "tui", answer: async () => false });
		await esc.confirm(reviewed, "matches protected path");
		const message = ui.confirms[0]?.message ?? "";
		expect(message).toContain(content);
		expect(message).toContain("\\u202e");
		expect(message).not.toContain("\u202E");
		expect(message).not.toContain("redacted:sha256");
	});

	it("denies when the person says no", async () => {
		const { escalator: esc, events, unattended } = escalator({ attended: "tui", answer: async () => false });
		expect(await esc.confirm(action, "matches ask rule")).toBe(false);
		expect(events[0]?.outcome).toBe("declined");
		// A declined action still needs a record: the human said no *now*, and
		// resuming it later is a separate decision they may want to make.
		expect(unattended).toHaveLength(1);
	});

	// The whole reason attendance is a setting: nobody is there, so nothing is
	// asked, and a pending record is written instead.
	it("never draws a dialog when unattended", async () => {
		const { escalator: esc, ui, events, unattended } = escalator({ attended: "off" });
		expect(await esc.confirm(action, "matches ask rule")).toBe(false);
		expect(ui.confirms).toHaveLength(0);
		expect(events[0]?.outcome).toBe("unattended");
		expect(unattended).toHaveLength(1);
	});

	it("carries the independently observed tool source into an unattended record callback", async () => {
		const { escalator: esc, unattended } = escalator({ attended: "off" });
		await esc.confirm(action, "matches ask rule", "/ext/pi-enclave.ts");
		expect(unattended[0]).toContain(":/ext/pi-enclave.ts");
	});

	it("shows the complete input with command newlines escaped", async () => {
		const multiline = canonicalize({
			tool: "bash",
			input: { command: "echo harmless\nrm -rf /work" },
			cwd: "/work",
			home: "/home/u",
			profileName: "dev",
		});
		const { escalator: esc, ui } = escalator({ attended: "tui", answer: async () => true });
		await esc.confirm(multiline, "unparsed");
		// The raw newline is inert JSON text, so an embedded command cannot create
		// a fake field or hide below an apparently harmless first line.
		expect(ui.confirms[0]?.message).toContain("echo harmless\\nrm -rf /work");
		expect(ui.confirms[0]?.message).not.toContain("echo harmless\nrm -rf /work");
	});

	it("tells the person that silence is a refusal", async () => {
		const { escalator: esc, ui } = escalator({ attended: "tui", answer: async () => true, timeoutMs: 60_000 });
		await esc.confirm(action, "reason");
		expect(ui.confirms[0]?.message).toContain("No answer within 60s is a refusal");
		expect(ui.confirms[0]?.timeout).toBe(60_000);
	});

	// pi reports a timeout and a decline identically. The distinction exists for
	// the audit record and never for the verdict.
	it("records a timeout distinctly, and denies either way", async () => {
		const { escalator: esc, events } = escalator({
			attended: "tui",
			timeoutMs: 1,
			answer: () => new Promise((resolve) => setTimeout(() => resolve(false), 30)),
		});
		expect(await esc.confirm(action, "reason")).toBe(false);
		expect(events[0]?.outcome).toBe("timeout");
	});

	it("denies when the client throws", async () => {
		const { escalator: esc, events } = escalator({
			attended: "rpc",
			answer: () => Promise.reject(new Error("disconnected")),
		});
		expect(await esc.confirm(action, "reason")).toBe(false);
		expect(events[0]?.outcome).toBe("declined");
	});
});
