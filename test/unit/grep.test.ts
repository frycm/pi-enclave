import { describe, expect, it } from "vitest";
import type { FsClient, Violation } from "../../src/backend/types.ts";
import { SandboxDenied } from "../../src/backend/types.ts";
import { parseRipgrepJson, runSandboxedGrep } from "../../src/tools/grep.ts";

const rgMatch = (path: string, line: number) =>
	JSON.stringify({ type: "match", data: { path: { text: path }, line_number: line } });

/** A helper stub that records what it was asked and answers from a fake tree. */
function fakeFs(files: Record<string, string>, stdout: string, options: { grepThrows?: Error } = {}) {
	const calls: { grep: string[][]; reads: string[] } = { grep: [], reads: [] };
	const fs: FsClient = {
		async grep(args) {
			calls.grep.push([...args]);
			if (options.grepThrows) throw options.grepThrows;
			return { stdout, exitCode: 0 };
		},
		async readFile(path) {
			calls.reads.push(path);
			const content = files[path];
			if (content === undefined) throw Object.assign(new Error("missing"), { code: "ENOENT" });
			return Buffer.from(content, "utf8");
		},
		writeFile: async () => {},
		mkdir: async () => {},
		access: async () => {},
		stat: async () => ({ isDirectory: () => true }),
		readdir: async () => [],
		exists: async () => true,
		glob: async () => [],
	};
	return { fs, calls };
}

describe("parseRipgrepJson", () => {
	it("extracts matches and ignores non-match events", () => {
		const stdout = [
			JSON.stringify({ type: "begin", data: { path: { text: "/a.txt" } } }),
			rgMatch("/a.txt", 3),
			JSON.stringify({ type: "end", data: {} }),
		].join("\n");
		expect(parseRipgrepJson(stdout, 100).matches).toEqual([{ filePath: "/a.txt", lineNumber: 3 }]);
	});

	it("skips unparseable lines rather than failing the search", () => {
		const stdout = ["not json at all", rgMatch("/a.txt", 1)].join("\n");
		expect(parseRipgrepJson(stdout, 100).matches).toHaveLength(1);
	});

	it("stops at the limit and reports it", () => {
		const stdout = Array.from({ length: 50 }, (_, i) => rgMatch("/a.txt", i + 1)).join("\n");
		const result = parseRipgrepJson(stdout, 10);
		expect(result.matches).toHaveLength(10);
		expect(result.limitReached).toBe(true);
	});
});

describe("runSandboxedGrep", () => {
	it("runs the search through the helper, never in the pi process", async () => {
		// The whole point of this module: pi's grep spawns rg itself, which would
		// read a credential directory with the user's full privileges.
		const { fs, calls } = fakeFs({ "/w/a.txt": "one\ntwo\nthree\n" }, rgMatch("/w/a.txt", 2));
		await runSandboxedGrep({ fs, cwd: "/w" }, { pattern: "two" });
		expect(calls.grep).toHaveLength(1);
		expect(calls.grep[0]).toContain("--json");
		expect(calls.grep[0]).toContain("two");
	});

	it("formats a match the way pi does", async () => {
		const { fs } = fakeFs({ "/w/a.txt": "one\ntwo\nthree\n" }, rgMatch("/w/a.txt", 2));
		const result = await runSandboxedGrep({ fs, cwd: "/w" }, { pattern: "two" });
		expect(result.content[0].text).toBe("a.txt:2: two");
	});

	it("formats context lines with the dash form", async () => {
		const { fs } = fakeFs({ "/w/a.txt": "one\ntwo\nthree\n" }, rgMatch("/w/a.txt", 2));
		const result = await runSandboxedGrep({ fs, cwd: "/w" }, { pattern: "two", context: 1 });
		expect(result.content[0].text).toBe(["a.txt-1- one", "a.txt:2: two", "a.txt-3- three"].join("\n"));
	});

	it("reads context lines through the helper too", async () => {
		// Reading them in the pi process would reopen exactly the hole this
		// module closes: rg confined, its surrounding lines fetched unsandboxed.
		const { fs, calls } = fakeFs({ "/w/a.txt": "one\ntwo\nthree\n" }, rgMatch("/w/a.txt", 2));
		await runSandboxedGrep({ fs, cwd: "/w" }, { pattern: "two", context: 1 });
		expect(calls.reads).toEqual(["/w/a.txt"]);
	});

	it("reads each file once however many times it matches", async () => {
		const stdout = [rgMatch("/w/a.txt", 1), rgMatch("/w/a.txt", 2), rgMatch("/w/a.txt", 3)].join("\n");
		const { fs, calls } = fakeFs({ "/w/a.txt": "x\nx\nx\n" }, stdout);
		await runSandboxedGrep({ fs, cwd: "/w" }, { pattern: "x" });
		expect(calls.reads).toEqual(["/w/a.txt"]);
	});

	it("passes ignoreCase, literal and glob through to ripgrep", async () => {
		const { fs, calls } = fakeFs({}, "");
		await runSandboxedGrep({ fs, cwd: "/w" }, { pattern: "p", ignoreCase: true, literal: true, glob: "*.ts" });
		const args = calls.grep[0] ?? [];
		expect(args).toContain("--ignore-case");
		expect(args).toContain("--fixed-strings");
		expect(args).toEqual(expect.arrayContaining(["--glob", "*.ts"]));
	});

	it("reports no matches plainly", async () => {
		const { fs } = fakeFs({}, "");
		expect((await runSandboxedGrep({ fs, cwd: "/w" }, { pattern: "nope" })).content[0].text).toBe("No matches found");
	});

	it("notes the match limit in the output and the details", async () => {
		const stdout = Array.from({ length: 20 }, (_, i) => rgMatch("/w/a.txt", i + 1)).join("\n");
		const { fs } = fakeFs({ "/w/a.txt": "x\n".repeat(20) }, stdout);
		const result = await runSandboxedGrep({ fs, cwd: "/w" }, { pattern: "x", limit: 5 });
		expect(result.content[0].text).toContain("5 match limit reached");
		expect(result.details?.matchLimitReached).toBe(5);
	});

	it("truncates long lines and records that it did", async () => {
		const { fs } = fakeFs({ "/w/a.txt": `${"z".repeat(2000)}\n` }, rgMatch("/w/a.txt", 1));
		const result = await runSandboxedGrep({ fs, cwd: "/w" }, { pattern: "z" });
		expect(result.content[0].text).toContain("[truncated]");
		expect(result.details?.linesTruncated).toBe(true);
	});

	it("reports a file it cannot read inline instead of failing the search", async () => {
		const { fs } = fakeFs({}, rgMatch("/w/gone.txt", 1));
		const result = await runSandboxedGrep({ fs, cwd: "/w" }, { pattern: "x" });
		expect(result.content[0].text).toContain("(unable to read file)");
	});

	it("surfaces a denied search as a denial, not an empty result", async () => {
		// An empty result would tell the agent the directory has no matches, which
		// is a different and misleading claim.
		const violation: Violation = {
			kind: "read",
			source: "errno",
			op: "grep",
			path: "/secrets",
			backend: "bwrap",
		};
		const { fs } = fakeFs({}, "", { grepThrows: new SandboxDenied(violation) });
		const result = await runSandboxedGrep({ fs, cwd: "/w" }, { pattern: "x", path: "/secrets" });
		expect(result.isError).toBe(true);
		expect(result.content[0].text).toContain("sandbox denied");
	});
});
