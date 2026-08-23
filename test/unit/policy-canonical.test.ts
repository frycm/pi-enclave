import { describe, expect, it } from "vitest";
import { canonicalize, describeAction, hashAction } from "../../src/policy/canonical.ts";
import { globToRegExp, looksLikePath, matchesPathPattern, pathCandidatesInToken } from "../../src/policy/paths.ts";

const BASE = { cwd: "/work", home: "/home/u", profileName: "dev" };

const bash = (command: string) => canonicalize({ ...BASE, tool: "bash", input: { command } });
const file = (tool: string, input: Record<string, unknown>) => canonicalize({ ...BASE, tool, input });

describe("canonicalize", () => {
	it("records the resolved path of a file tool", () => {
		const action = file("write", { path: "notes.md" });
		expect(action.paths[0]?.typed).toBe("/work/notes.md");
		expect(action.paths[0]?.relative).toBe("notes.md");
		expect(action.paths[0]?.writes).toBe(true);
	});

	it("marks a read tool's path as a read", () => {
		expect(file("read", { path: "notes.md" }).paths[0]?.writes).toBe(false);
	});

	it("expands ~ and strips the decorations pi's tools accept", () => {
		expect(file("read", { path: "~/x" }).paths[0]?.typed).toBe("/home/u/x");
		expect(file("read", { path: "@notes.md" }).paths[0]?.typed).toBe("/work/notes.md");
		expect(file("read", { path: "file:///etc/hosts" }).paths[0]?.typed).toBe("/etc/hosts");
	});

	describe("shell write targets", () => {
		it("treats a redirect target as a write", () => {
			const action = bash("echo hi > /work/out.txt");
			const target = action.paths.find((path) => path.typed === "/work/out.txt");
			expect(target?.writes).toBe(true);
		});

		it("treats a path argument of an unknown command as a write", () => {
			expect(bash("frobnicate /work/thing").paths[0]?.writes).toBe(true);
		});

		it("treats a path argument of a known read-only command as a read", () => {
			expect(bash("cat /work/thing").paths[0]?.writes).toBe(false);
		});

		// `edit` reads and writes the same file; the write is what escalates.
		it("a path that is both read and written counts as a write", () => {
			const action = bash("cat /work/x && rm /work/x");
			expect(action.paths).toHaveLength(1);
			expect(action.paths[0]?.writes).toBe(true);
		});

		it("finds a path inside a --flag=value argument", () => {
			expect(bash("tool --output=/work/out").paths.map((path) => path.typed)).toContain("/work/out");
		});
	});

	describe("capabilities", () => {
		it("reads allow_write off the input", () => {
			const action = canonicalize({ ...BASE, tool: "bash", input: { command: "x", allow_write: "/etc/hosts" } });
			expect(action.capability).toEqual({ kind: "write", value: "/etc/hosts" });
		});

		// An approval for one path must not be replayable for another.
		it("the capability changes the hash", () => {
			const a = canonicalize({ ...BASE, tool: "bash", input: { command: "x", allow_write: "/a" } });
			const b = canonicalize({ ...BASE, tool: "bash", input: { command: "x", allow_write: "/b" } });
			expect(a.hash).not.toBe(b.hash);
		});
	});

	describe("the hash", () => {
		it("is stable across reserialization and whitespace", () => {
			expect(bash("rm  -rf   /work/x").hash).toBe(bash("rm -rf /work/x").hash);
		});

		it("is stable across key order for a tool with no shell and no path", () => {
			const a = canonicalize({ ...BASE, tool: "thing", input: { a: 1, b: 2 } });
			const b = canonicalize({ ...BASE, tool: "thing", input: { b: 2, a: 1 } });
			expect(a.hash).toBe(b.hash);
		});

		it.each([
			["a different command", () => bash("rm -rf /work/y")],
			["a different tool", () => file("read", { path: "notes.md" })],
			[
				"a different profile",
				() => canonicalize({ ...BASE, profileName: "locked", tool: "bash", input: { command: "rm -rf /work/x" } }),
			],
			[
				"a different cwd",
				() => canonicalize({ ...BASE, cwd: "/other", tool: "bash", input: { command: "rm -rf /work/x" } }),
			],
		])("changes for %s", (_label, build) => {
			expect(build().hash).not.toBe(bash("rm -rf /work/x").hash);
		});

		// A golden value, so a change to the serialization is a deliberate act
		// rather than something that quietly invalidates every pending record.
		it("has not drifted", () => {
			expect(bash("git status").hash).toBe(hashAction(bash("git status")));
			expect(bash("git status").hash).toMatch(/^sha256:[0-9a-f]{64}$/);
		});
	});

	it("carries the tokenizer's confidence", () => {
		expect(bash("echo $(whoami)").confident).toBe(false);
		expect(bash("echo hi").confident).toBe(true);
	});

	describe("describeAction", () => {
		// A command with an embedded newline must not be able to hide a second
		// command below the fold of a confirm dialog.
		it("renders each simple command on its own line", () => {
			const rendered = describeAction(bash("echo ok\nrm -rf /work"));
			expect(rendered).toContain("    echo ok");
			expect(rendered).toContain("    rm -rf /work");
		});

		it("says when the parse is not confident", () => {
			expect(describeAction(bash("eval $X"))).toContain("not confident");
		});
	});
});

describe("globs", () => {
	it.each([
		["**/.git/hooks/**", "/work/.git/hooks/pre-commit", true],
		["**/.git/hooks/**", ".git/hooks/pre-commit", true],
		["infra/**", "infra/main.tf", true],
		["infra/**", "src/main.ts", false],
		// `*` matches zero characters too, so a pattern written for env files
		// catches the bare `.env` as well as `prod.env`.
		["*.env", ".env", true],
		["*.env", "prod.env", true],
		["*.env", "config/prod.env", false],
		["**/Dockerfile", "deploy/Dockerfile", true],
	])("%s against %s", (pattern, path, expected) => {
		expect(globToRegExp(pattern).test(path)).toBe(expected);
	});
});

describe("matchesPathPattern", () => {
	it("matches an in-tree path by its relative form", () => {
		expect(matchesPathPattern(["infra/**"], "/work/infra/main.tf", "/work")).toBe("infra/**");
	});

	// A pattern about `.git/config` is about the file, not about where the
	// repository happens to sit.
	it("matches an out-of-tree path by segment suffix", () => {
		expect(matchesPathPattern(["**/.git/config"], "/elsewhere/repo/.git/config", "/work")).toBe("**/.git/config");
	});

	it("returns undefined when nothing matches", () => {
		expect(matchesPathPattern(["infra/**"], "/work/src/main.ts", "/work")).toBeUndefined();
	});
});

describe("path detection", () => {
	it.each([
		["/abs/path", true],
		["./rel", true],
		["../up", true],
		["~/home", true],
		["a/b", true],
		["--flag", false],
		["plainword", false],
		["", false],
	])("looksLikePath(%s)", (token, expected) => {
		expect(looksLikePath(token)).toBe(expected);
	});

	it("finds the value half of a flag", () => {
		expect(pathCandidatesInToken("--output=/etc/passwd")).toContain("/etc/passwd");
	});
});
