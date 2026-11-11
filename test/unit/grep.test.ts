import { describe, expect, it } from "vitest";
import type { FsClient, Violation } from "../../src/backend/types.ts";
import { SandboxDenied } from "../../src/backend/types.ts";
import { GrepExecutionQueue, parseRipgrepJson, runSandboxedGrep } from "../../src/tools/grep.ts";

const rgMatch = (path: string, line: number, text = "x", type = "match") =>
	JSON.stringify({ type, data: { path: { text: path }, line_number: line, lines: { text: `${text}\n` } } });

const rgMatchWithText = (path: string, line: number, text: string) =>
	JSON.stringify({ type: "match", data: { path: { text: path }, line_number: line, lines: { text: `${text}\n` } } });

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
		head: async (path, bytes) => Buffer.from(files[path] ?? "", "utf8").subarray(0, bytes),
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
		expect(parseRipgrepJson(stdout, 100).matches).toEqual([
			{ filePath: "/a.txt", lineNumber: 3, lineText: "x\n", isMatch: true },
		]);
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
	it("serializes the complete parent-side grep lifetime", async () => {
		const queue = new GrepExecutionQueue();
		let active = 0;
		let peak = 0;
		let releaseFirst!: () => void;
		const firstBlocked = new Promise<void>((resolve) => {
			releaseFirst = resolve;
		});
		const run = (blocked = false) =>
			queue.run(async () => {
				active++;
				peak = Math.max(peak, active);
				if (blocked) await firstBlocked;
				active--;
			});

		const first = run(true);
		const second = run();
		await Promise.resolve();
		expect(active).toBe(1);
		releaseFirst();
		await Promise.all([first, second]);
		expect(peak).toBe(1);
	});

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
		const { fs } = fakeFs({ "/w/a.txt": "one\ntwo\nthree\n" }, rgMatch("/w/a.txt", 2, "two"));
		const result = await runSandboxedGrep({ fs, cwd: "/w" }, { pattern: "two" });
		expect(result.content[0].text).toBe("a.txt:2: two");
	});

	it("formats context lines with the dash form", async () => {
		const stdout = [
			rgMatch("/w/a.txt", 1, "one", "context"),
			rgMatch("/w/a.txt", 2, "two"),
			rgMatch("/w/a.txt", 3, "three", "context"),
		].join("\n");
		const { fs } = fakeFs({}, stdout);
		const result = await runSandboxedGrep({ fs, cwd: "/w" }, { pattern: "two", context: 1 });
		expect(result.content[0].text).toBe(["a.txt-1- one", "a.txt:2: two", "a.txt-3- three"].join("\n"));
	});

	it("requests context from rg without reopening matched files", async () => {
		const { fs, calls } = fakeFs({}, rgMatch("/w/a.txt", 2));
		await runSandboxedGrep({ fs, cwd: "/w" }, { pattern: "two", context: 1 });
		expect(calls.grep[0]).toEqual(expect.arrayContaining(["--no-config", "--context", "1"]));
		expect(calls.reads).toEqual([]);
	});

	it("uses rg's sandboxed line payload without reading the complete file when context is zero", async () => {
		const { fs, calls } = fakeFs({}, rgMatchWithText("/w/a.txt", 2, "two"));
		const result = await runSandboxedGrep({ fs, cwd: "/w" }, { pattern: "two" });
		expect(result.content[0].text).toBe("a.txt:2: two");
		expect(calls.reads).toEqual([]);
	});

	it("does not read a file again however many times it matches", async () => {
		const stdout = [rgMatch("/w/a.txt", 1), rgMatch("/w/a.txt", 2), rgMatch("/w/a.txt", 3)].join("\n");
		const { fs, calls } = fakeFs({ "/w/a.txt": "x\nx\nx\n" }, stdout);
		await runSandboxedGrep({ fs, cwd: "/w" }, { pattern: "x" });
		expect(calls.reads).toEqual([]);
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
		expect(result.content[0].text).toContain("5 matches limit reached");
		expect(result.details?.matchLimitReached).toBe(5);
	});

	it("truncates long lines and records that it did", async () => {
		const { fs } = fakeFs({}, rgMatch("/w/a.txt", 1, "z".repeat(2000)));
		const result = await runSandboxedGrep({ fs, cwd: "/w" }, { pattern: "z" });
		expect(result.content[0].text).toContain("[truncated]");
		expect(result.details?.linesTruncated).toBe(true);
	});

	it("bounds aggregate output without reading matched files", async () => {
		const files = Object.fromEntries(
			Array.from({ length: 100 }, (_, index) => [`/w/${index}.txt`, `${"x".repeat(4_000)}\n`]),
		);
		const stdout = Array.from({ length: 100 }, (_, index) => rgMatch(`/w/${index}.txt`, 1, "x".repeat(4_000))).join(
			"\n",
		);
		const { fs, calls } = fakeFs(files, stdout);
		const result = await runSandboxedGrep({ fs, cwd: "/w" }, { pattern: "x", context: 1, limit: 100 });
		expect(calls.reads).toEqual([]);
		expect(result.details?.truncation).toBeDefined();
		expect(Buffer.byteLength(result.content[0].text)).toBeLessThan(60 * 1024);
	});

	it("keeps the original matched line if the file disappears after rg reads it", async () => {
		const { fs } = fakeFs({}, rgMatch("/w/gone.txt", 1, "original"));
		const result = await runSandboxedGrep({ fs, cwd: "/w" }, { pattern: "x" });
		expect(result.content[0].text).toBe("gone.txt:1: original");
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
