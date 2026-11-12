import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import type { CompiledProfile, Profile, Violation } from "../../src/backend/types.ts";
import {
	type EnclaveState,
	handleEnclaveCommand,
	renderBackend,
	renderStatus,
	renderStatusLine,
	renderViolations,
} from "../../src/commands/enclave.ts";
import { defaultProfile } from "../../src/config/defaults.ts";
import { TripwireLedger } from "../../src/persistence/ledger.ts";
import type { ProbeReport } from "../../src/probe.ts";

const OK_REPORT: ProbeReport = {
	ok: true,
	platform: "darwin",
	backend: "seatbelt",
	piVersion: "1.5.2",
	checks: [{ id: "platform", title: "Platform", status: "ok", detail: "darwin -> seatbelt backend" }],
};

const FAILED_REPORT: ProbeReport = {
	...OK_REPORT,
	ok: false,
	checks: [
		{
			id: "pi-version",
			title: "pi version",
			status: "fail",
			detail: "0.1.0 out of range",
			remediation: "install a supported pi",
		},
	],
};

const PROFILE: Profile = {
	mode: "workspace-write",
	writableRoots: ["/work", "/tmp"],
	readDeny: ["/home/u/.ssh", "/home/u/.aws"],
	network: "off",
	allowPty: true,
};

const COMPILED: CompiledProfile = {
	backend: "seatbelt",
	profile: PROFILE,
	describe: () => "(version 1)\n(deny default)\n(allow file-read*)",
};

const violation = (over: Partial<Violation> = {}): Violation => ({
	kind: "write",
	source: "kernel-log",
	op: "file-write-create",
	path: "/etc/passwd",
	backend: "seatbelt",
	...over,
});

function state(over: Partial<EnclaveState> = {}): EnclaveState {
	return {
		report: OK_REPORT,
		backendName: "seatbelt",
		weakened: false,
		profile: PROFILE,
		compiled: COMPILED,
		violations: [],
		...over,
	};
}

describe("renderStatusLine", () => {
	it("names the backend, mode and network", () => {
		expect(renderStatusLine(state())).toBe("enclave: seatbelt · workspace-write · net off");
	});

	it("says every tool is refused when the probe failed", () => {
		// The most important line in the whole UI: with no sandbox the tools are
		// still pi-enclave's and refuse every call, and nothing on screen should
		// suggest either that they are enforcing or that they have fallen back to
		// pi's unsandboxed built-ins.
		expect(renderStatusLine(state({ report: FAILED_REPORT, compiled: undefined }))).toContain("REFUSING ALL TOOLS");
	});

	it("shows that the profile has not compiled yet", () => {
		expect(renderStatusLine(state({ compiled: undefined }))).toContain("starting");
	});

	it("reports an active sandbox even when the probe failed", () => {
		// A weakened run legitimately fails the namespace-nesting check while the
		// sandbox is demonstrably enforcing. Claiming NOT ACTIVE there invites
		// someone to assume nothing is enforced and act on it.
		const line = renderStatusLine(state({ report: FAILED_REPORT, weakened: true }));
		expect(line).not.toContain("REFUSING");
		expect(line).toContain("WEAKENED");
		expect(line).toContain("seatbelt");
	});

	it("shouts about weakened mode without being asked", () => {
		// A weakened sandbox that looks identical to a real one is the failure
		// this line exists to prevent.
		expect(renderStatusLine(state({ weakened: true }))).toContain("WEAKENED");
	});

	it("counts denials once there are any, and stays quiet when there are none", () => {
		expect(renderStatusLine(state())).not.toContain("denied");
		expect(renderStatusLine(state({ violations: [violation(), violation()] }))).toContain("2 denied");
	});
});

describe("renderStatus", () => {
	it("shows which layer settled the session's decisions, and rules.onUncertain (#18)", () => {
		const effective = defaultProfile({ cwd: "/work", home: "/home/u", tmp: "/tmp", agentDir: "/home/u/.pi/agent" });
		expect(renderStatus(state({ effective }))).toContain("decided:    no gate decisions yet");
		const text = renderStatus(
			state({ effective, layers: { L1: 6, L3: 3, L4: 1, askDenied: 1, sandboxedUncertain: 0, other: 0 } }),
		);
		expect(text).toContain("decided:    L1 6 (60%), L3 3 (30%), L4 1 (10%), ask-denied 1");
	});

	it("lists every tool that runs outside the sandbox without a person (#22)", () => {
		const effective = defaultProfile({ cwd: "/work", home: "/home/u", tmp: "/tmp", agentDir: "/home/u/.pi/agent" });
		expect(renderStatus(state({ effective }))).toContain("no tool runs outside the sandbox without a person");
		effective.tools.allow.mcp__docs__search = { readOnly: true };
		effective.tools.allow.deploy = {};
		effective.tools.allow.notify = { reviewed: true };
		effective.rules.skipReview.push("deploy(preview)", "bash(npm test)");
		const text = renderStatus(state({ effective }));
		expect(text).toContain("2 route(s)");
		expect(text).toContain("mcp__docs__search (readOnly grant)");
		expect(text).toContain("deploy (skipReview deploy(preview))");
		expect(text).not.toContain("notify (");
		expect(text).not.toContain("bash (");
	});

	it("includes the probe report, profile and coverage", () => {
		const text = renderStatus(state());
		expect(text).toContain("pi-enclave probe");
		expect(text).toContain("workspace-write");
		expect(text).toContain("/work, /tmp");
		expect(text).toContain("2 path(s)");
	});

	it("lists every readable root in allowlist mode, not only a count (review of #55)", () => {
		const allowlisted = { ...PROFILE, readMode: "allowlist" as const, readAllow: ["/usr", "/home/u/.cargo"] };
		const text = renderStatus(state({ compiled: { ...COMPILED, profile: allowlisted } }));
		expect(text).toContain("readable:   /usr, /home/u/.cargo");
		expect(renderStatus(state())).not.toContain("readable:");
	});

	it("states what the sandbox does NOT cover", () => {
		// Someone reading this needs to know MCP and third-party tools are
		// outside the boundary; leaving it out would imply total coverage.
		expect(renderStatus(state())).toMatch(/MCP.*not|not.*MCP/s);
	});

	it("explains the weakened mode rather than just flagging it", () => {
		const text = renderStatus(state({ weakened: true }));
		expect(text).toContain("WEAKENED");
		expect(text).toContain("capabilities");
	});

	it("lists the directories the persistence scan could not look into (#33)", () => {
		const text = renderStatus(state({ profile: { ...PROFILE, unscanned: ["/work/pgdata"] } }));
		expect(text).toContain("unscanned:  1 directory(ies) owned by another account");
		expect(text).toContain("/work/pgdata");
		expect(renderStatus(state())).not.toContain("unscanned");
	});

	it("marks the backend as not started before the first compile", () => {
		expect(renderStatus(state({ compiled: undefined }))).toContain("not started");
	});
});

describe("renderBackend", () => {
	it("returns the compiled profile verbatim", () => {
		// Anyone checking whether the sandbox does what it claims needs the
		// artefact the kernel was given, not a summary of it.
		expect(renderBackend(state())).toBe("(version 1)\n(deny default)\n(allow file-read*)");
	});

	it("says so when nothing has compiled yet", () => {
		expect(renderBackend(state({ compiled: undefined }))).toContain("not started");
	});
});

describe("renderViolations", () => {
	it("reports none plainly", () => {
		expect(renderViolations(state())).toBe("no denials this session");
	});

	it("lists kind, operation and target", () => {
		const text = renderViolations(state({ violations: [violation()] }));
		expect(text).toContain("write");
		expect(text).toContain("file-write-create");
		expect(text).toContain("/etc/passwd");
	});

	it("shows network denials by host", () => {
		const net = violation({ kind: "network", op: "network-outbound", host: "example.com:443" });
		delete (net as { path?: string }).path;
		expect(renderViolations(state({ violations: [net] }))).toContain("example.com:443");
	});

	it("keeps the most recent and says how many it dropped", () => {
		// Silently truncating would understate the count someone is trying to read.
		const many = Array.from({ length: 25 }, (_, i) => violation({ path: `/p${i}` }));
		const text = renderViolations(state({ violations: many }), 20);
		expect(text).toContain("25 denial(s)");
		expect(text).toContain("5 earlier denial(s) not shown");
		expect(text).toContain("/p24");
		expect(text).not.toContain("/p4 ");
	});
});

describe("/enclave tripwire (#19)", () => {
	it("lists unacknowledged changes, shows them in status, and clears them on ack", () => {
		const dir = mkdtempSync(join(tmpdir(), "enclave-tripwire-cmd-"));
		try {
			const tripwireLedger = TripwireLedger.forWorkspace(dir, "/work");
			const withLedger = state({ tripwireLedger });
			expect(handleEnclaveCommand(withLedger, "tripwire").text).toBe("no unacknowledged changes");
			tripwireLedger.add([{ path: "/work/sub/.pi", change: "created" }], true);
			const listed = handleEnclaveCommand(withLedger, "tripwire");
			expect(listed.level).toBe("warning");
			expect(listed.text).toContain("created: /work/sub/.pi");
			expect(renderStatus(withLedger)).toContain("tripwire:   1 unacknowledged change(s)");
			expect(handleEnclaveCommand(withLedger, "tripwire ack").text).toBe("acknowledged 1 change(s)");
			expect(renderStatus(withLedger)).not.toContain("tripwire:");
			expect(handleEnclaveCommand(state(), "tripwire").text).toBe("the tripwire is not running");
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	});
});

describe("handleEnclaveCommand", () => {
	it("defaults to status", () => {
		expect(handleEnclaveCommand(state(), "").text).toContain("pi-enclave probe");
	});

	it("routes each subcommand", () => {
		expect(handleEnclaveCommand(state(), "backend").text).toContain("(version 1)");
		expect(handleEnclaveCommand(state(), "violations").text).toContain("no denials");
	});

	it("tolerates surrounding whitespace and extra words", () => {
		expect(handleEnclaveCommand(state(), "  backend  extra ").text).toContain("(version 1)");
	});

	it("reports status at error level when the probe failed", () => {
		expect(handleEnclaveCommand(state({ report: FAILED_REPORT }), "status").level).toBe("error");
	});

	it("names the valid subcommands when given an unknown one", () => {
		const output = handleEnclaveCommand(state(), "frobnicate");
		expect(output.level).toBe("warning");
		expect(output.text).toContain("status|backend|violations");
	});
});
