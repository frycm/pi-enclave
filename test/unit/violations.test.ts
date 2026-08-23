import { describe, expect, it } from "vitest";
import type { Violation } from "../../src/backend/types.ts";
import {
	dedupeViolations,
	formatViolations,
	isNoise,
	parseViolationLine,
	parseViolations,
} from "../../src/backend/violations.ts";

// Lines copied verbatim from the step-0 spike output, so the parsers are tested
// against what the backends actually emit rather than what we imagine.
const SEATBELT_WRITE = "bash(22824) deny(1) file-write-create /private/var/folders/hl/T/enclave-home/pwned.txt";
const SEATBELT_READ = "cat(22842) deny(1) file-read-data /private/var/folders/hl/T/enclave-home/.ssh/id_ed25519";
const SEATBELT_SOCKET = "Python(23070) deny(1) network-outbound /private/var/run/com.apple.launchd.X/Listeners";
const SEATBELT_NOISE = "bash(22824) deny(1) sysctl-read kern.iossupportversion";
const BWRAP_WRITE = "deny openat /tmp/enclave-home-YfDTzO/pwned.txt";
const BWRAP_NOISE = "deny openat /dev/shm/sem.7uOPDx";
const PROXY_DENY = "deny network-outbound example.com:443 (host is not on the allow list)";

describe("noise filtering", () => {
	it("drops the sysctl denial nearly every macOS command emits", () => {
		expect(isNoise(SEATBELT_NOISE, "seatbelt")).toBe(true);
		expect(parseViolationLine(SEATBELT_NOISE, "seatbelt")).toBeNull();
	});

	it("drops the /dev/shm semaphore denials from Linux multiprocessing", () => {
		// 30 of these came from one call that SUCCEEDED. Counting them as
		// violations would trip phase 2's circuit breaker on working code.
		expect(isNoise(BWRAP_NOISE, "bwrap")).toBe(true);
		expect(parseViolationLine(BWRAP_NOISE, "bwrap")).toBeNull();
	});

	it("drops __pycache__ writes on both backends", () => {
		const line = "Python(1) deny(1) file-write-create /usr/lib/python3.14/__pycache__/x.pyc";
		expect(isNoise(line, "seatbelt")).toBe(true);
		expect(isNoise("deny openat /usr/lib/python3/__pycache__/x.pyc", "bwrap")).toBe(true);
	});

	it("does not drop a real denial", () => {
		expect(isNoise(SEATBELT_WRITE, "seatbelt")).toBe(false);
		expect(isNoise(BWRAP_WRITE, "bwrap")).toBe(false);
	});

	it("applies each backend's own noise list", () => {
		// The macOS sysctl line is not a thing bwrap emits; it should not be
		// silently ignored there just because the other backend ignores it.
		expect(isNoise(BWRAP_NOISE, "seatbelt")).toBe(false);
	});
});

describe("seatbelt log lines", () => {
	it("parses a write denial", () => {
		const v = parseViolationLine(SEATBELT_WRITE, "seatbelt");
		expect(v).toMatchObject({
			kind: "write",
			source: "kernel-log",
			op: "file-write-create",
			path: "/private/var/folders/hl/T/enclave-home/pwned.txt",
			backend: "seatbelt",
		});
	});

	it("parses a read denial", () => {
		expect(parseViolationLine(SEATBELT_READ, "seatbelt")).toMatchObject({
			kind: "read",
			op: "file-read-data",
		});
	});

	it("parses a unix socket denial as a network kind with the socket path", () => {
		const v = parseViolationLine(SEATBELT_SOCKET, "seatbelt");
		expect(v?.kind).toBe("network");
		expect(v?.path).toContain("Listeners");
	});

	it("keeps the raw line for the audit log", () => {
		expect(parseViolationLine(SEATBELT_WRITE, "seatbelt")?.raw).toBe(SEATBELT_WRITE);
	});
});

describe("bwrap observer lines", () => {
	it("parses a denied openat as a write", () => {
		// bwrap reports the syscall, not the intent: a denied write fails at
		// openat because the ro-bind is what refuses it.
		expect(parseViolationLine(BWRAP_WRITE, "bwrap")).toMatchObject({
			kind: "write",
			source: "kernel-log",
			op: "openat",
			path: "/tmp/enclave-home-YfDTzO/pwned.txt",
			backend: "bwrap",
		});
	});

	it("parses other write syscalls", () => {
		expect(parseViolationLine("deny linkat /tmp/x", "bwrap")?.kind).toBe("write");
		expect(parseViolationLine("deny mkdirat /tmp/x", "bwrap")?.kind).toBe("write");
	});
});

describe("proxy lines", () => {
	it("parses a host denial with its port", () => {
		expect(parseViolationLine(PROXY_DENY, "seatbelt")).toMatchObject({
			kind: "network",
			source: "proxy",
			op: "network-outbound",
			host: "example.com:443",
		});
	});

	it("is recognised on both backends", () => {
		// The egress proxy is shared, so its wording is identical on macOS and
		// Linux even though everything else about the two differs.
		expect(parseViolationLine(PROXY_DENY, "bwrap")?.source).toBe("proxy");
	});

	it("marks the source as proxy, not kernel-log", () => {
		// This distinction is not cosmetic: a proxy denial is a userspace
		// decision, so it is weaker evidence than a kernel one.
		expect(parseViolationLine(PROXY_DENY, "seatbelt")?.source).toBe("proxy");
	});
});

describe("unparseable input", () => {
	it("never invents a violation from a line it cannot parse", () => {
		// A fabricated denial is worse than a missed log line: the raw stream is
		// still in the audit log, but a false violation reaches the agent.
		for (const line of ["", "   ", "some unrelated log output", "Traceback (most recent call last):"]) {
			expect(parseViolationLine(line, "seatbelt"), line).toBeNull();
			expect(parseViolationLine(line, "bwrap"), line).toBeNull();
		}
	});
});

describe("parseViolations", () => {
	it("filters noise and keeps real denials, in order", () => {
		const parsed = parseViolations([SEATBELT_NOISE, SEATBELT_WRITE, SEATBELT_NOISE, SEATBELT_READ], "seatbelt");
		expect(parsed.map((v) => v.op)).toEqual(["file-write-create", "file-read-data"]);
	});

	it("returns an empty array when everything is noise", () => {
		expect(parseViolations([SEATBELT_NOISE, SEATBELT_NOISE], "seatbelt")).toEqual([]);
	});
});

describe("dedupeViolations", () => {
	it("collapses identical denials", () => {
		const v = parseViolations([SEATBELT_WRITE, SEATBELT_WRITE, SEATBELT_WRITE], "seatbelt");
		expect(v).toHaveLength(3);
		expect(dedupeViolations(v)).toHaveLength(1);
	});

	it("keeps denials that differ in path", () => {
		const a = parseViolationLine(SEATBELT_WRITE, "seatbelt") as Violation;
		const b = { ...a, path: "/other/path" };
		expect(dedupeViolations([a, b])).toHaveLength(2);
	});
});

describe("formatViolations", () => {
	it("is empty for no violations, so callers can append unconditionally", () => {
		expect(formatViolations([])).toBe("");
	});

	it("renders backend-neutral text", () => {
		// An agent that learns one platform's vocabulary would not recognise the
		// other's, so the rendering names the kind and target, not the mechanism.
		const seatbelt = formatViolations(parseViolations([SEATBELT_WRITE], "seatbelt"));
		const bwrap = formatViolations(parseViolations([BWRAP_WRITE], "bwrap"));
		for (const text of [seatbelt, bwrap]) {
			expect(text).toContain("sandbox denied:");
			expect(text).toContain("write:");
		}
		expect(seatbelt).not.toMatch(/seatbelt|sandbox-exec|deny\(1\)/);
		expect(bwrap).not.toMatch(/bwrap|bubblewrap/);
	});
});
