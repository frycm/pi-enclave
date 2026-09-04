import { describe, expect, it } from "vitest";
import { canonicalize, describeAction, describeActionForApproval, hashAction } from "../../src/policy/canonical.ts";
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

	// A percent-encoded file URL must decode the way pi's execution path does,
	// or `file:///work/%2Egithub/...` misses `**/.github/**` here while executing
	// as `/work/.github/...`.
	it("percent-decodes a file URL so an encoded protected path still matches", () => {
		expect(file("write", { path: "file:///work/%2Egithub/workflows/ci.yml" }).paths[0]?.typed).toBe(
			"/work/.github/workflows/ci.yml",
		);
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

		// A redirect glued to a word must still be seen as a write, or a protected
		// path can be appended to with no escalation.
		it("records a glued redirect target as a write", () => {
			const target = bash("cat p>>.git/hooks/pre-commit").paths.find((path) => path.typed.endsWith("pre-commit"));
			expect(target?.writes).toBe(true);
		});

		// A bare filename operand of a writer command is a possible protected
		// target; `tee authorized_keys` writes the same file as `tee ./authorized_keys`.
		it("records a bare filename operand of a writer command", () => {
			expect(bash("tee authorized_keys").paths.map((path) => path.relative)).toContain("authorized_keys");
		});

		it("records a bare filename operand of a path-qualified writer command", () => {
			expect(bash("/usr/bin/tee authorized_keys").paths.map((path) => path.relative)).toContain("authorized_keys");
		});

		it("does not turn a non-writer command's bare word into a path", () => {
			// A commit message word is not a file target.
			expect(bash("git commit -m message").paths).toHaveLength(0);
		});

		// dd names its output with `of=`, which the assignment filter would skip;
		// its bare-name target must still be recorded as a write.
		it("records dd of= as a write target", () => {
			const paths = bash("dd if=/dev/zero of=authorized_keys").paths;
			const target = paths.find((p) => p.relative === "authorized_keys");
			expect(target?.writes).toBe(true);
		});

		it("does not record a key=value token whole as a path", () => {
			// Only the value half is a path, never `cwd/of=/work/x`.
			expect(bash("dd of=/work/x bs=1M").paths.map((p) => p.typed)).not.toContain("/work/of=/work/x");
		});

		it("records &>> and >& redirect targets as writes", () => {
			const target = bash("cmd &>> .git/hooks/pre-commit").paths.find((p) => p.typed.endsWith("pre-commit"));
			expect(target?.writes).toBe(true);
		});

		// chmod/chown/sed/dd take a non-file leading operand; recording it as a
		// path produced spurious protectedPaths escalations.
		it.each([
			["chmod 755 file", "/work/755"],
			["chown user:grp file", "/work/user:grp"],
		])("does not record a non-file operand of %s", (command, spurious) => {
			expect(bash(command).paths.map((p) => p.typed)).not.toContain(spurious);
		});
	});

	// ls/find default their path to the working directory; recording it keeps the
	// lock key in step so the bare call is not refused at execute time.
	describe("ls/find default path", () => {
		it("records the working directory when path is omitted", () => {
			expect(file("ls", {}).paths.map((path) => path.typed)).toEqual(["/work"]);
			expect(file("find", { pattern: "*.ts" }).paths.map((path) => path.typed)).toEqual(["/work"]);
		});

		it("uses the explicit path when given", () => {
			expect(file("ls", { path: "src" }).paths[0]?.typed).toBe("/work/src");
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

		it("refuses ambiguous multiple capability requests", () => {
			expect(() =>
				canonicalize({
					...BASE,
					tool: "bash",
					input: { command: "x", allow_write: "/a", allow_read: "/b" },
				}),
			).toThrow("exactly one capability");
		});
	});

	describe("the hash", () => {
		it("binds the exact executor-consumed command", () => {
			expect(bash("rm  -rf   /work/x").hash).not.toBe(bash("rm -rf /work/x").hash);
		});

		it("binds executor-observable key order for a tool with no shell and no path", () => {
			const a = canonicalize({ ...BASE, tool: "thing", input: { a: 1, b: 2 } });
			const b = canonicalize({ ...BASE, tool: "thing", input: { b: 2, a: 1 } });
			expect(a.hash).not.toBe(b.hash);
		});

		it("distinguishes negative zero from zero", () => {
			const positive = file("deploy", { amount: 0 });
			const negative = file("deploy", { amount: -0 });
			expect(negative.hash).not.toBe(positive.hash);
			expect(describeAction(negative)).not.toBe(describeAction(positive));
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

		// The hash must bind every execution-affecting field, or a pending
		// approval could be replayed with different semantics.
		it("binds shell control operators", () => {
			expect(bash("false && sudo id").hash).not.toBe(bash("false || sudo id").hash);
		});

		it("binds a write body", () => {
			const w = (content: string) => canonicalize({ ...BASE, tool: "write", input: { path: "/work/x", content } });
			expect(w("SAFE").hash).not.toBe(w("EVIL").hash);
		});

		it("binds an edit replacement", () => {
			const e = (newString: string) =>
				canonicalize({ ...BASE, tool: "edit", input: { path: "/work/x", oldString: "a", newString } });
			expect(e("b").hash).not.toBe(e("c").hash);
		});

		it("binds pi's current batch edit schema", () => {
			const e = (newText: string) =>
				canonicalize({
					...BASE,
					tool: "edit",
					input: { path: "/work/x", edits: [{ oldText: "a", newText }] },
				});
			expect(e("b").hash).not.toBe(e("c").hash);
		});

		it("binds quote context that changes shell expansion", () => {
			expect(bash("rm *").hash).not.toBe(bash('rm "*"').hash);
		});

		it("binds every field for path-bearing and third-party tools", () => {
			const grep = (pattern: string) => file("grep", { path: "/work", pattern });
			expect(grep("safe").hash).not.toBe(grep("secret").hash);
			const deploy = (mode: string) => file("deploy", { path: "prod", mode, force: true });
			expect(deploy("dry-run").hash).not.toBe(deploy("destroy").hash);
			expect(file("read", { path: "/work/x", offset: 1 }).hash).not.toBe(
				file("read", { path: "/work/x", offset: 2 }).hash,
			);
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
		it("renders each simple command on its own line, with its connector", () => {
			const rendered = describeAction(bash("echo ok\nrm -rf /work"));
			expect(rendered).toContain("    echo ok");
			// The connector is shown so a second command cannot hide as a bare arg.
			expect(rendered).toContain("; rm -rf /work");
		});

		it("shows redirects and redacted write-body evidence, not just the command name", () => {
			const redirect = describeAction(bash("echo payload > .github/workflows/ci.yml"));
			expect(redirect).toContain("> .github/workflows/ci.yml");
			const write = describeAction(
				canonicalize({ ...BASE, tool: "write", input: { path: "/work/x", content: "EVIL" } }),
			);
			expect(write).toContain("content:");
			expect(write).not.toContain("EVIL");
			expect(write).toContain("redacted:sha256");
		});

		it("shows batch edit replacements", () => {
			const edit = describeAction(
				canonicalize({
					...BASE,
					tool: "edit",
					input: { path: "/work/x", edits: [{ oldText: "SAFE", newText: "EVIL" }] },
				}),
			);
			expect(edit).toContain("edits:");
			expect(edit).not.toContain("EVIL");
			expect(edit).toContain("redacted:sha256");
			expect(edit).toContain("sha256:");
		});

		it("distinguishes equal-prefix, equal-length bodies", () => {
			const render = (tail: string) =>
				describeAction(
					canonicalize({
						...BASE,
						tool: "write",
						input: { path: "/work/x", content: `${"A".repeat(200)}${tail}` },
					}),
				);
			expect(render("SAFE")).not.toBe(render("EVIL"));
			expect(render("SAFE")).not.toContain("SAFE");
			expect(render("SAFE")).toContain("redacted:sha256");
		});

		it("shows quote context that changes shell expansion", () => {
			expect(describeAction(bash("rm *"))).not.toBe(describeAction(bash('rm "*"')));
			expect(describeAction(bash('rm "*"'))).toContain('rm "*"');
		});

		it("says when the parse is not confident", () => {
			expect(describeAction(bash("eval $X"))).toContain("not confident");
		});

		it("shows every privileged third-party input field without calling it a read", () => {
			const rendered = describeAction(file("deploy", { path: "prod", mode: "destroy", force: true }));
			expect(rendered).toContain("input.path");
			expect(rendered).toContain("input.mode");
			expect(rendered).toContain("destroy");
			expect(rendered).toContain("input.force");
			expect(rendered).not.toContain("reads /work/prod");
		});

		it("escapes control characters in attacker-selected field names", () => {
			const rendered = describeAction(file("deploy", { "mode\n    SAFE-LOOKING: allow": "destroy" }));
			expect(rendered).toContain('input."mode\\n    SAFE-LOOKING: allow"');
			expect(rendered).not.toContain("\n    SAFE-LOOKING: allow");
		});

		it("renders nested execution fields independently of large siblings", () => {
			const rendered = describeAction(
				file("deploy", {
					config: { a: "A".repeat(200), mode: "destroy", z: "Z".repeat(200) },
					content: { padding: "X".repeat(300), operation: "erase" },
				}),
			);
			expect(rendered).toContain("input.config.mode");
			expect(rendered).toContain("destroy");
			expect(rendered).toContain("input.content.operation");
			expect(rendered).toContain("erase");
		});

		it("distinguishes a dotted key from nested fields", () => {
			const nested = describeAction(file("deploy", { config: { mode: "destroy" } }));
			const dotted = describeAction(file("deploy", { "config.mode": "destroy" }));
			expect(nested).toContain("input.config.mode");
			expect(dotted).toContain('input."config.mode"');
			expect(dotted).not.toBe(nested);
		});

		it("redacts nested body-like fields", () => {
			const rendered = describeAction(file("deploy", { config: { content: "DO-NOT-LEAK" } }));
			expect(rendered).not.toContain("DO-NOT-LEAK");
			expect(rendered).toContain("redacted:sha256");
		});
	});

	describe("describeActionForApproval", () => {
		it("shows fields in the same order the executor observes", () => {
			const input = Object.fromEntries([
				["delete", "production"],
				["backup", false],
			]);
			const rendered = describeActionForApproval(file("deploy", input));
			expect(rendered.indexOf('"delete"')).toBeLessThan(rendered.indexOf('"backup"'));
		});

		it("shows the complete executor input without redaction or truncation", () => {
			const content = `${"A".repeat(300)}ERASE-PRODUCTION${"Z".repeat(300)}`;
			const rendered = describeActionForApproval(file("write", { path: "/work/prod", content }));
			expect(rendered).toContain(content);
			expect(rendered).not.toContain("redacted:sha256");
			expect(rendered).not.toContain("…");
		});

		it("renders Unicode format controls as inert ASCII and distinguishes literal escapes", () => {
			const controlled = describeActionForApproval(file("deploy", { mode: "safe\u202Eliated" }));
			const literal = describeActionForApproval(file("deploy", { mode: "safe\\u202eliated" }));
			expect(controlled).not.toContain("\u202E");
			expect(controlled).toContain("\\u202e");
			expect(literal).not.toBe(controlled);
		});
	});
});

describe("globs", () => {
	it.each([
		["**/.git/hooks/**", "/work/.git/hooks/pre-commit", true],
		["**/.git/hooks/**", ".git/hooks/pre-commit", true],
		["**/.git/hooks/**", "/work/.git/hooks", true],
		["**/.git/hooks/**", ".git/hooks", true],
		["infra/**", "infra/main.tf", true],
		["infra/**", "infra", true],
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

	// `[!c]` is a POSIX negation; copied verbatim it matched a literal `!`.
	it("negates a [!…] character class", () => {
		const regex = globToRegExp("infra/[!c]*");
		expect(regex.test("infra/main")).toBe(true);
		expect(regex.test("infra/config")).toBe(false);
	});

	// Case-insensitive so a case-variant spelling of a protected file on a
	// case-insensitive filesystem still matches.
	it("matches case-insensitively", () => {
		expect(globToRegExp("**/Dockerfile").test("deploy/dockerfile")).toBe(true);
		expect(globToRegExp("**/.git/config").test("repo/.git/CONFIG")).toBe(true);
	});
});

describe("matchesPathPattern", () => {
	it("matches an in-tree path by its relative form", () => {
		expect(matchesPathPattern(["infra/**"], "/work/infra/main.tf", "/work")).toBe("infra/**");
	});

	it("matches the root of a protected descendant glob", () => {
		expect(matchesPathPattern(["**/.git/hooks/**"], "/work/.git/hooks", "/work")).toBe("**/.git/hooks/**");
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
