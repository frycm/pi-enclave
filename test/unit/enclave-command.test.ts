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
import type { ProbeReport } from "../../src/probe.ts";

const OK_REPORT: ProbeReport = {
	ok: true,
	platform: "darwin",
	backend: "seatbelt",
	piVersion: "0.84.2",
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

	it("says NOT ACTIVE when nothing compiled and the probe refused", () => {
		// The most important line in the whole UI: if the sandbox is not running,
		// nothing else on screen should suggest otherwise.
		expect(renderStatusLine(state({ report: FAILED_REPORT, compiled: undefined }))).toContain("NOT ACTIVE");
	});

	it("shows that the profile has not compiled yet", () => {
		expect(renderStatusLine(state({ compiled: undefined }))).toContain("starting");
	});

	it("reports an active sandbox even when the probe failed", () => {
		// A weakened run legitimately fails the namespace-nesting check while the
		// sandbox is demonstrably enforcing. Claiming NOT ACTIVE there invites
		// someone to assume nothing is enforced and act on it.
		const line = renderStatusLine(state({ report: FAILED_REPORT, weakened: true }));
		expect(line).not.toContain("NOT ACTIVE");
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
	it("includes the probe report, profile and coverage", () => {
		const text = renderStatus(state());
		expect(text).toContain("pi-enclave probe");
		expect(text).toContain("workspace-write");
		expect(text).toContain("/work, /tmp");
		expect(text).toContain("2 path(s)");
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
