import { describe, expect, it } from "vitest";
import { classifyErrno, isDenial, kindForOp } from "../../src/backend/errno.ts";
import { isUnder, isUnderAny, normalizePath } from "../../src/backend/paths.ts";
import type { BackendName, Profile } from "../../src/backend/types.ts";

const PROFILE: Profile = {
	mode: "workspace-write",
	writableRoots: ["/work", "/tmp/box"],
	readDeny: ["/home/u/.ssh", "/home/u/.aws"],
	network: "off",
	allowPty: true,
};

function classify(code: string, op: string, path: string, backend: BackendName = "seatbelt") {
	return classifyErrno({ error: { code, syscall: "open", path }, op, path, profile: PROFILE, backend });
}

describe("path containment", () => {
	it("treats a root as containing itself", () => {
		expect(isUnder("/home/u/.ssh", "/home/u/.ssh")).toBe(true);
	});

	it("compares whole segments, not string prefixes", () => {
		// The bug this guards: /home/u/.sshfoo must not count as inside /home/u/.ssh.
		expect(isUnder("/home/u/.sshfoo", "/home/u/.ssh")).toBe(false);
		expect(isUnder("/home/u/.ssh/id_ed25519", "/home/u/.ssh")).toBe(true);
	});

	it("ignores trailing separators on either side", () => {
		expect(isUnder("/home/u/.ssh/", "/home/u/.ssh")).toBe(true);
		expect(isUnder("/home/u/.ssh/key", "/home/u/.ssh/")).toBe(true);
	});

	it("normalizes traversal before comparing", () => {
		expect(normalizePath("/work/../home/u/.ssh")).toBe("/home/u/.ssh");
		expect(isUnder("/work/../home/u/.ssh/key", "/home/u/.ssh")).toBe(true);
	});

	it("matches nothing against an empty root list", () => {
		expect(isUnderAny("/anything", [])).toBe(false);
	});
});

describe("kindForOp", () => {
	it("separates reads from writes", () => {
		expect(kindForOp("readFile")).toBe("read");
		expect(kindForOp("grep")).toBe("read");
		expect(kindForOp("access:read")).toBe("read");
		expect(kindForOp("writeFile")).toBe("write");
		expect(kindForOp("mkdir")).toBe("write");
		expect(kindForOp("access:write")).toBe("write");
	});
});

describe("classifyErrno: errnos that always mean denial", () => {
	it("classifies EPERM as a denial (the macOS shape)", () => {
		const v = classify("EPERM", "readFile", "/home/u/.ssh/id_ed25519");
		expect(v?.kind).toBe("read");
		expect(v?.source).toBe("errno");
	});

	it("classifies EACCES as a denial", () => {
		expect(classify("EACCES", "readFile", "/x")).not.toBeNull();
	});

	it("classifies EROFS as a WRITE denial (the Linux shape)", () => {
		// The regression this guards: checking only for EPERM silently misses
		// every write denial on bwrap, where --ro-bind / / yields EROFS.
		const v = classify("EROFS", "writeFile", "/etc/passwd", "bwrap");
		expect(v).not.toBeNull();
		expect(v?.kind).toBe("write");
	});

	it("classifies network unreachability as a network denial (the Linux shape)", () => {
		// --unshare-net removes the network rather than forbidding it.
		const v = classify("ENETUNREACH", "connect", "/x", "bwrap");
		expect(v?.kind).toBe("network");
	});

	it("carries the backend, op and path onto the violation", () => {
		const v = classify("EPERM", "writeFile", "/etc/hosts", "bwrap");
		expect(v).toMatchObject({ backend: "bwrap", op: "writeFile", path: "/etc/hosts", source: "errno" });
	});

	it("keeps the raw errno as audit evidence", () => {
		expect(classify("EROFS", "writeFile", "/x", "bwrap")?.raw).toContain("EROFS");
	});
});

describe("classifyErrno: the ambiguous ENOENT", () => {
	it("treats ENOENT under a read-denied root as a denial", () => {
		// On bwrap a denied read region is an empty tmpfs, so its contents are
		// absent rather than forbidden. Without this, every Linux read denial is
		// reported to the agent as "no such file".
		const v = classify("ENOENT", "readFile", "/home/u/.ssh/id_ed25519", "bwrap");
		expect(v).not.toBeNull();
		expect(v?.kind).toBe("read");
	});

	it("treats ENOENT anywhere else as an ordinary missing file", () => {
		// The opposite failure: reporting a typo'd filename as a security event.
		expect(classify("ENOENT", "readFile", "/work/typo.txt", "bwrap")).toBeNull();
		expect(classify("ENOENT", "readFile", "/work/typo.txt", "seatbelt")).toBeNull();
	});

	it("does not fire on a path that merely shares a prefix with a denied root", () => {
		expect(classify("ENOENT", "readFile", "/home/u/.sshfoo/x", "bwrap")).toBeNull();
	});

	it("resolves the denied root itself as denied", () => {
		expect(classify("ENOENT", "readdir", "/home/u/.ssh", "bwrap")).not.toBeNull();
	});
});

describe("classifyErrno: ordinary errors", () => {
	it("passes through errors that are not denials", () => {
		for (const code of ["ENOTDIR", "EISDIR", "ENOSPC", "EMFILE", "EINVAL"]) {
			expect(classify(code, "readFile", "/work/x"), code).toBeNull();
		}
	});

	it("returns null when there is no errno at all", () => {
		const v = classifyErrno({
			error: {},
			op: "readFile",
			path: "/work/x",
			profile: PROFILE,
			backend: "seatbelt",
		});
		expect(v).toBeNull();
	});
});

describe("isDenial", () => {
	it("agrees with classifyErrno", () => {
		const input = {
			error: { code: "EROFS" },
			op: "writeFile",
			path: "/etc/x",
			profile: PROFILE,
			backend: "bwrap" as const,
		};
		expect(isDenial(input)).toBe(true);
		expect(isDenial({ ...input, error: { code: "ENOSPC" } })).toBe(false);
	});
});

describe("cross-backend parity", () => {
	// The point of the classifier: the same policy violation, expressed with the
	// errno each backend actually produces, must classify identically.
	const cases: Array<{ what: string; seatbelt: string; bwrap: string; op: string; path: string; kind: string }> = [
		{
			what: "write outside a writable root",
			seatbelt: "EPERM",
			bwrap: "EROFS",
			op: "writeFile",
			path: "/etc/passwd",
			kind: "write",
		},
		{
			what: "read a denied path",
			seatbelt: "EPERM",
			bwrap: "ENOENT",
			op: "readFile",
			path: "/home/u/.ssh/id_ed25519",
			kind: "read",
		},
	];

	for (const c of cases) {
		it(`${c.what} classifies the same on both backends`, () => {
			const a = classify(c.seatbelt, c.op, c.path, "seatbelt");
			const b = classify(c.bwrap, c.op, c.path, "bwrap");
			expect(a?.kind, "seatbelt").toBe(c.kind);
			expect(b?.kind, "bwrap").toBe(c.kind);
		});
	}
});
