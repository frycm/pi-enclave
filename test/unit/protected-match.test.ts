/**
 * #72: L1's protected-path matching for patterns with an ordinary ancestor.
 * The table of the issue is policy row P16; these are the parts of it.
 */
import { linkSync, mkdirSync, mkdtempSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { DEFAULT_PROTECTED_ASK, DEFAULT_PROTECTED_DENY } from "../../src/config/defaults.ts";
import { canonicalize } from "../../src/policy/canonical.ts";
import { ancestorPatterns, protectedMatches } from "../../src/policy/protected-match.ts";

const HOME = "/nonexistent-home/u";
const RULES = { deny: [...DEFAULT_PROTECTED_DENY], ask: [...DEFAULT_PROTECTED_ASK, "infra/**", "deploy/prod/*.yml"] };

let ws: string;
beforeEach(() => {
	ws = realpathSync(mkdtempSync(join(tmpdir(), "enclave-l1-")));
});
afterEach(() => rmSync(ws, { recursive: true, force: true }));

function put(relative: string): string {
	const path = join(ws, relative);
	mkdirSync(dirname(path), { recursive: true });
	writeFileSync(path, "x\n");
	return path;
}

function asks(tool: string, input: Record<string, unknown>, options: { maxEntries?: number } = {}) {
	const action = canonicalize({ tool, input, cwd: ws, home: HOME, profileName: "dev" });
	return protectedMatches(action, RULES.ask, "ask", { cwd: ws, home: HOME, rules: RULES, ...options });
}
const bash = (command: string, options: { maxEntries?: number } = {}) => asks("bash", { command }, options);

describe("which patterns have an ordinary ancestor", () => {
	it("are the multi-segment ones whose first segment is not protected by itself", () => {
		expect(ancestorPatterns(RULES, ws).map((entry) => entry.pattern)).toEqual([
			"**/.github/workflows/**",
			"**/.vscode/tasks.json",
			"deploy/prod/*.yml",
		]);
	});

	it("drop a pattern once its first segment is protected", () => {
		const rules = { ...RULES, ask: [...RULES.ask, "**/.github/**"] };
		expect(ancestorPatterns(rules, ws).map((entry) => entry.pattern)).not.toContain("**/.github/workflows/**");
	});
});

describe("a directory operand", () => {
	beforeEach(() => {
		put(".github/workflows/ci.yml");
		put("deploy/prod/a.yml");
		put("docs/readme.md");
	});

	it.each([
		"mv .github gh2",
		"rm -rf .github",
		"rm -r -f deploy",
		"mv -- deploy d",
		"mv -t dest .github",
		"mv --target-directory=dest .github",
		"mv -S .bak .github gh2",
		"cp -al .github gh-backup",
		"cp --link -r deploy d5",
	])("asks when it moves, removes or links a tree holding a protected path: %s", (command) => {
		expect(bash(command)).not.toEqual([]);
	});

	it.each(["mv docs d3", "rm -rf docs", "cp -r .github backup", "cp -a deploy d6", "ln -s .github gh"])(
		"allows %s, which moves or removes nothing protected",
		(command) => {
			expect(bash(command)).toEqual([]);
		},
	);

	it("reads an operand after -- as one, even when it starts with a dash", () => {
		put("-g/.github/workflows/ci.yml");
		expect(bash("rm -rf -- -g")).not.toEqual([]);
	});

	it("asks when the tree is too large to look through", () => {
		for (let i = 0; i < 20; i++) put(`big/f${i}`);
		expect(bash("rm -rf big", { maxEntries: 10 })).toEqual([
			expect.objectContaining({ pattern: "(more than 10 entries to check)", target: join(ws, "big") }),
		]);
		expect(bash("rm -rf big")).toEqual([]);
	});
});

describe("a copy or move into place", () => {
	it.each([
		// [command, source to plant, directory that already exists]
		["cp -r s/workflows .github/", "s/workflows/ci.yml", ".github"],
		["mv gh2 .github", "gh2/workflows/ci.yml", undefined],
		["cp -r gh2 .github", "gh2/workflows/ci.yml", undefined],
		["mv gh2 sub/.github", "gh2/workflows/ci.yml", "sub"],
		["mv v .vscode", "v/tasks.json", undefined],
		["cp s/tasks.json .vscode/", "s/tasks.json", ".vscode"],
		["mv d deploy", "d/prod/a.yml", undefined],
		["cp -r d/prod deploy", "d/prod/a.yml", "deploy"],
		["mv -t deploy d/prod", "d/prod/a.yml", undefined],
		["mv --target-directory=deploy d/prod", "d/prod/a.yml", undefined],
		["mv --target-directory deploy d/prod", "d/prod/a.yml", undefined],
		["mv -T gh2 .github", "gh2/workflows/ci.yml", ".github"],
		["ln -s gh2 .github", "gh2/workflows/ci.yml", undefined],
	])("asks for what %s would create", (command, source, existing) => {
		put(source);
		if (existing) mkdirSync(join(ws, existing), { recursive: true });
		expect(bash(command)).not.toEqual([]);
	});

	it.each([
		// Into an existing directory, so the tree lands one level down.
		["mv gh2 .github", "gh2/workflows/ci.yml", ".github"],
		["cp -r d/prod deploy", "d/prod/a.yml", undefined],
		["cp -r .github backup", ".github/workflows/ci.yml", undefined],
		["cp -a deploy d6", "deploy/prod/a.yml", undefined],
		["ln -s .github gh", ".github/workflows/ci.yml", undefined],
		["cp -r src src2", "src/a.ts", undefined],
	])("allows %s, which creates nothing protected", (command, source, existing) => {
		put(source);
		if (existing) mkdirSync(join(ws, existing), { recursive: true });
		expect(bash(command)).toEqual([]);
	});

	it("does not read the value of -S as an operand", () => {
		// Read as one, `.github` would be the destination of a move of two
		// missing sources, which could hold a workflow.
		expect(bash("mv a b -S .github")).toEqual([]);
	});

	it("asks when the source does not exist yet, by where it goes", () => {
		expect(bash("mv later .github")).not.toEqual([]);
		expect(bash("mv later deploy/prod")).not.toEqual([]);
		expect(bash("mv later/.github .")).not.toEqual([]);
		expect(bash("mv later elsewhere")).toEqual([]);
	});

	it("judges a line of several commands by where it moves to", () => {
		put("g/readme.md");
		expect(bash("mv g .github")).toEqual([]);
		expect(bash("mkdir -p g/workflows && mv g .github")).not.toEqual([]);
		expect(bash("mkdir -p dist && cp -r g dist/")).toEqual([]);
	});
});

describe("a copy of a directory's contents", () => {
	it.each([
		["cp -r s/. .github/", "s/workflows/ci.yml", ".github"],
		["cp -a s/. .github", "s/workflows/ci.yml", ".github"],
		["cp -R s/. .github", "s/workflows/ci.yml", ".github"],
		["cp -r s/./ .github/", "s/workflows/ci.yml", ".github"],
		["cp -r prod2/. deploy/prod", "prod2/a.yml", "deploy/prod"],
		["cp -r prod2/. deploy/prod", "prod2/a.yml", undefined],
	])("asks for what %s puts into the destination itself", (command, source, existing) => {
		put(source);
		if (existing) mkdirSync(join(ws, existing), { recursive: true });
		expect(bash(command)).not.toEqual([]);
	});

	it("reads `.` alone as the contents of the working directory", () => {
		put("workflows/ci.yml");
		mkdirSync(join(ws, "sub", ".github"), { recursive: true });
		expect(bash("cp -r . sub/.github")).not.toEqual([]);
	});

	it("allows a contents copy that creates nothing protected", () => {
		put("s/workflows/ci.yml");
		mkdirSync(join(ws, "backup"));
		expect(bash("cp -r s/. backup/")).toEqual([]);
		// The contents of `.github` land as `backup/workflows`, not `backup/.github`.
		put(".github/workflows/ci.yml");
		expect(bash("cp -r .github/. backup/")).toEqual([]);
	});

	it.each(["cp -r s/workflows/.. .github", "cp -r s/workflows/../ .github/"])(
		"reads a source ending in `..` as the contents of the directory it names: %s",
		(command) => {
			put("s/workflows/ci.yml");
			mkdirSync(join(ws, ".github"));
			expect(bash(command)).not.toEqual([]);
			mkdirSync(join(ws, "backup"));
			expect(bash(command.replace(".github", "backup"))).toEqual([]);
		},
	);

	it("does not read a name that only ends in a dot as its contents", () => {
		put("g./workflows/ci.yml");
		mkdirSync(join(ws, ".github"));
		expect(bash("cp -r g. .github")).toEqual([]);
	});
});

describe("a symlink into place", () => {
	beforeEach(() => mkdirSync(join(ws, "v")));

	it.each(["ln -s v .vscode", "ln -s g .github", "ln -s dreal deploy", "ln -sT v .vscode", "ln -s -- v .vscode"])(
		"asks for %s whatever its source holds now, since a later write goes through it",
		(command) => {
			expect(bash(command)).not.toEqual([]);
		},
	);

	it("allows a symlink whose name could hold nothing protected", () => {
		expect(bash("ln -s v vv")).toEqual([]);
		expect(bash("ln -s v docs")).toEqual([]);
	});

	it("keeps judging a hard link by what its source holds", () => {
		put("v2/readme.md");
		expect(bash("ln v2/readme.md .vscode")).toEqual([]);
	});
});

describe("a destination reached through a symlink", () => {
	beforeEach(() => {
		put("t/tasks.json");
		put("t/readme.md");
		put("s/workflows/ci.yml");
		mkdirSync(join(ws, "v"));
		symlinkSync("v", join(ws, ".vscode"));
		mkdirSync(join(ws, "g"));
		mkdirSync(join(ws, "r"));
		symlinkSync("../g", join(ws, "r", ".github"));
	});

	it.each([
		"cp t/tasks.json .vscode/",
		"mv t/tasks.json .vscode/",
		"cp t/tasks.json .vscode",
		"cp -r t/. .vscode",
		"cp -r s/workflows r/.github/",
	])("is judged by the name as written too: %s", (command) => {
		expect(bash(command)).not.toEqual([]);
	});

	it("allows what creates nothing protected under either name", () => {
		expect(bash("cp t/readme.md .vscode/")).toEqual([]);
		expect(bash("cp -r t r/.github/")).toEqual([]);
	});
});

describe("a protected name that is a symlink", () => {
	beforeEach(() => {
		put("docs/ai/instructions.md");
		symlinkSync("docs/ai/instructions.md", join(ws, "AGENTS.md"));
		put("v/readme.md");
		symlinkSync("v", join(ws, ".vscode"));
		put("scripts/hook.sh");
		mkdirSync(join(ws, ".husky"));
		symlinkSync("../scripts/hook.sh", join(ws, ".husky", "pre-push"));
	});

	it.each([
		"echo x > AGENTS.md",
		"rm AGENTS.md",
		"mv AGENTS.md x.md",
		"echo x > .husky/pre-push",
		"echo '{}' > .vscode/tasks.json",
	])("asks for %s by the name as written", (command) => {
		expect(bash(command)).not.toEqual([]);
	});

	it("asks for the write and edit tools", () => {
		expect(asks("write", { path: "AGENTS.md", content: "x" })).toEqual([
			expect.objectContaining({ pattern: "**/AGENTS.md", target: join(ws, "AGENTS.md") }),
		]);
		expect(asks("edit", { path: "AGENTS.md", oldText: "x", newText: "y" })).not.toEqual([]);
		expect(asks("write", { path: ".vscode/tasks.json", content: "{}" })).not.toEqual([]);
	});

	it("does not ask for the target written by its own name", () => {
		expect(bash("echo x > docs/ai/instructions.md")).toEqual([]);
	});

	it.each([
		["echo x > notes.md", "bash"],
		["notes.md", "write"],
	])("asks for %s through a chain whose middle name is protected", (target, tool) => {
		symlinkSync("AGENTS.md", join(ws, "notes.md"));
		const result = tool === "bash" ? bash(target) : asks("write", { path: target, content: "x" });
		expect(result).toEqual([expect.objectContaining({ pattern: "**/AGENTS.md", target: join(ws, "AGENTS.md") })]);
	});

	it("still asks for an ordinary name that leads to a protected one", () => {
		put("sub/AGENTS.md");
		symlinkSync("sub/AGENTS.md", join(ws, "notes.md"));
		expect(bash("echo x > notes.md")).not.toEqual([]);
	});

	it("is denied by name on the deny list too", () => {
		put("px/extensions/readme.md");
		symlinkSync("px", join(ws, ".pi"));
		const action = canonicalize({
			tool: "write",
			input: { path: ".pi/extensions/e.ts", content: "x" },
			cwd: ws,
			home: HOME,
			profileName: "dev",
		});
		expect(protectedMatches(action, RULES.deny, "deny", { cwd: ws, home: HOME, rules: RULES })).not.toEqual([]);
	});
});

describe("git mv and git rm", () => {
	beforeEach(() => {
		put(".github/workflows/ci.yml");
		put("gh2/workflows/ci.yml");
		put("deploy/prod/a.yml");
		put("docs/readme.md");
	});

	it.each([
		"git mv .github gh3",
		"git mv gh2 r/.github",
		"git mv -f -k -v deploy d9",
		"git mv -- .github gh3",
		"git rm -r .github",
		"git rm -rf -q -- deploy",
		"git rm -r -n --cached .github",
	])("reads %s like mv or rm", (command) => {
		expect(bash(command)).not.toEqual([]);
	});

	it.each(["git mv docs d3", "git rm -r docs", "git status", "git log -- .github"])("allows %s", (command) => {
		expect(bash(command)).toEqual([]);
	});

	it.each([
		"git rm -r :/.github",
		"git rm -r :/",
		"git rm -r ':!src'",
		"git rm -r -- ':(top).github'",
		"git rm -r --pathspec-from-file=list.txt",
		"git rm --pathspec-from-file list.txt",
		"git rm --pathspec-from list.txt",
		"git rm --pathspec-file-nul --pathspec-from-file=list.txt",
	])("asks for a pathspec L1 cannot list: %s", (command) => {
		expect(bash(command)).toEqual([expect.objectContaining({ pattern: "(a Git pathspec)" })]);
	});

	it("does not read the subcommand as an operand", () => {
		put("rm/.github/workflows/ci.yml");
		expect(bash("git rm -r docs")).toEqual([]);
	});
});

describe("a second hard link", () => {
	let other: string;
	beforeEach(() => {
		const ci = put(".github/workflows/ci.yml");
		other = join(ws, "gh-backup", "workflows", "ci.yml");
		mkdirSync(dirname(other), { recursive: true });
		linkSync(ci, other);
	});

	it.each([
		"echo x > gh-backup/workflows/ci.yml",
		"echo x >> gh-backup/workflows/ci.yml",
		"tee gh-backup/workflows/ci.yml",
		"truncate -s 0 gh-backup/workflows/ci.yml",
		"dd if=/dev/zero of=gh-backup/workflows/ci.yml",
		"cp s.yml gh-backup/workflows/ci.yml",
		"cp ci.yml gh-backup/workflows/",
	])("asks for a write through it: %s", (command) => {
		expect(bash(command)).toEqual([
			expect.objectContaining({ pattern: "(a file with 2 hard links)", target: realpathSync(other) }),
		]);
	});

	it("asks for the write and edit tools", () => {
		expect(asks("write", { path: "gh-backup/workflows/ci.yml", content: "x" })).not.toEqual([]);
		expect(asks("edit", { path: "gh-backup/workflows/ci.yml", oldText: "x", newText: "y" })).not.toEqual([]);
	});

	it("does not ask for removing or renaming a name, which leaves the content alone", () => {
		expect(bash("rm gh-backup/workflows/ci.yml")).toEqual([]);
		expect(bash("mv gh-backup/workflows/ci.yml old.yml")).toEqual([]);
	});

	it("does not ask for a file with one name", () => {
		put("notes.txt");
		expect(bash("echo x > notes.txt")).toEqual([]);
		expect(asks("write", { path: "notes.txt", content: "x" })).toEqual([]);
	});
});

describe("the deny list", () => {
	it("gets only what an operand names; what a directory holds is an ask", () => {
		put(".github/workflows/ci.yml");
		const rules = { ...RULES, deny: [...RULES.deny, "**/.github/workflows/**"] };
		const match = (command: string, list: "deny" | "ask") =>
			protectedMatches(
				canonicalize({ tool: "bash", input: { command }, cwd: ws, home: HOME, profileName: "dev" }),
				rules[list],
				list,
				{ cwd: ws, home: HOME, rules },
			);
		expect(match("rm -rf .github", "deny")).toEqual([]);
		expect(match("rm -rf .github", "ask")).not.toEqual([]);
		expect(match("rm -rf .github/workflows", "deny")).not.toEqual([]);
	});
});
