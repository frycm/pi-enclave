import { spawnSync } from "node:child_process";
import { existsSync, linkSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { shellWriteCapabilityIssue, validateWriteCapability } from "../../src/backend/capability.ts";
import { canonical } from "../../src/backend/paths.ts";
import {
	effectiveProfile,
	linuxWriteMountPins,
	materializeWriteDenyAnchors,
	srtTmpDir,
	toSrtConfig,
} from "../../src/backend/srt.ts";
import { type Profile, SANDBOX_TMPDIR } from "../../src/backend/types.ts";
import { defaultProfile } from "../../src/config/defaults.ts";
import { toBackendProfile } from "../../src/config/profile.ts";

const roots: string[] = [];
afterEach(() => {
	for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

const profile = (writableRoots: string[]): Profile => ({
	mode: "workspace-write",
	writableRoots,
	readDeny: [],
	network: "off",
	allowPty: true,
});

function initGit(root: string): void {
	const result = spawnSync("git", ["init", "-q", root], { encoding: "utf8" });
	if (result.status !== 0) throw new Error(result.stderr || "git init failed");
}

function expectWriteDenied(profile: Profile, path: string): void {
	expect((profile.writeDeny ?? []).map(canonical)).toContain(canonical(path));
}

function expectWriteAllowed(profile: Profile, path: string): void {
	expect((profile.writeDeny ?? []).map(canonical)).not.toContain(canonical(path));
}

describe("sandbox profile authority", () => {
	it("fails closed for shell write grants whose process lifetime cannot be contained on macOS", () => {
		expect(shellWriteCapabilityIssue("darwin")).toContain("could outlive the invocation");
		expect(shellWriteCapabilityIssue("linux")).toBeUndefined();
	});

	it("refuses write capabilities that could re-expose a read-denied subtree", () => {
		const base = { ...profile(["/work"]), readDeny: ["/home/u/.ssh"], writeDeny: ["/work/.pi"] };
		for (const target of ["/home/u/.ssh", "/home/u/.ssh/out", "/home/u", "/work/.pi/cache"]) {
			expect(() => validateWriteCapability(base, "/work", target), target).toThrow(/immutable denied path/);
		}
		expect(validateWriteCapability(base, "/work", "/srv/result")).toBe("/srv/result");
	});
	it("does not derive the default writable root from ambient TMPDIR", () => {
		const previous = process.env.TMPDIR;
		process.env.TMPDIR = "/";
		try {
			const configured = defaultProfile({ cwd: "/work", home: "/home/u", agentDir: "/home/u/.pi/agent" });
			expect(configured.sandbox.writableRoots).toEqual(["/work", SANDBOX_TMPDIR]);
		} finally {
			if (previous === undefined) delete process.env.TMPDIR;
			else process.env.TMPDIR = previous;
		}
	});

	it("refuses an SRT temp override outside configured writable roots", () => {
		expect(() => effectiveProfile(profile(["/work"]), "linux", { CLAUDE_CODE_TMPDIR: "/home/u" })).toThrow(
			"refusing ambient sandbox TMPDIR",
		);
	});

	it("allows an SRT temp override already contained by a writable root", () => {
		const compiled = effectiveProfile(profile(["/work"]), "linux", { CLAUDE_CODE_TMPDIR: "/work/.tmp" });
		expect(compiled.tmpDir).toBe("/work/.tmp");
		expect(compiled.writableRoots).toEqual(["/work"]);
	});

	it("uses the fixed SRT scratch path when no trusted override exists", () => {
		expect(srtTmpDir({ TMPDIR: "/" })).toBe(SANDBOX_TMPDIR);
	});

	it("lowers persistence and credential paths into kernel write denials", () => {
		const effective = defaultProfile({ cwd: "/work", home: "/home/u", tmp: SANDBOX_TMPDIR, agentDir: "/agent" });
		const backend = toBackendProfile(effective, "/work");
		expect(backend.writeDeny).toContain("/work/.pi");
		expect(backend.writeDeny).toContain("/work/.git/hooks");
		expect(backend.writeDeny).toContain("/home/u/.ssh");
		expect(toSrtConfig(backend, false, "linux").filesystem.denyWrite).toContain("/work/.pi");
	});

	it("pins every writable ancestor of a Linux write denial shallow-first", () => {
		expect(
			linuxWriteMountPins(
				["/work", "/work/nested"],
				["/work/.git/hooks", "/work/a/b/config", "/work/nested/x/config", "/home/u/.ssh"],
				"linux",
			),
		).toEqual(["/work/.git", "/work/a", "/work/a/b", "/work/nested/x"]);
		expect(linuxWriteMountPins(["/work"], ["/work/.git/hooks"], "darwin")).toEqual([]);
	});

	it("emits Linux ancestor pins after their writable roots and before write denials", () => {
		const config = toSrtConfig(
			{
				...profile(["/work/deeper", "/work"]),
				writeDeny: ["/work/deeper/a/hooks"],
			},
			false,
			"linux",
		);
		expect(config.filesystem.allowWrite).toEqual(["/work", "/work/deeper", "/work/deeper/a"]);
		expect(config.filesystem.denyWrite).toContain("/work/deeper/a/hooks");
	});

	it("materializes a real deny mount point and refuses a symlink", () => {
		const root = mkdtempSync(join(tmpdir(), "enclave-deny-anchor-"));
		roots.push(root);
		const anchor = join(root, ".pi");
		materializeWriteDenyAnchors({ ...profile([root]), materializeWriteDeny: [anchor] });
		expect(() => mkdirSync(anchor)).toThrow();

		const outside = join(root, "outside");
		mkdirSync(outside);
		const link = join(root, "link");
		symlinkSync(outside, link);
		expect(() => materializeWriteDenyAnchors({ ...profile([root]), materializeWriteDeny: [link] })).toThrow(
			"not a real directory",
		);
	});

	it("refuses to materialize through a symlink ancestor outside the writable roots", () => {
		const root = mkdtempSync(join(tmpdir(), "enclave-deny-root-"));
		const outside = mkdtempSync(join(tmpdir(), "enclave-deny-outside-"));
		roots.push(root, outside);
		symlinkSync(outside, join(root, "link"));
		const escaped = join(root, "link", "protected");

		expect(() => materializeWriteDenyAnchors({ ...profile([root]), materializeWriteDeny: [escaped] })).toThrow(
			"outside writable roots",
		);
		expect(existsSync(join(outside, "protected"))).toBe(false);
	});

	it("materializes missing Git hooks in an existing repository", () => {
		const root = mkdtempSync(join(tmpdir(), "enclave-git-anchor-"));
		roots.push(root);
		mkdirSync(join(root, ".git"));
		const effective = defaultProfile({ cwd: root, home: "/home/u", tmp: SANDBOX_TMPDIR, agentDir: "/agent" });
		const backend = toBackendProfile(effective, root);
		materializeWriteDenyAnchors(backend);
		expect(() => mkdirSync(join(root, ".git", "hooks"))).toThrow();
		expect(() => writeFileSync(join(root, ".git", "config"), "", { flag: "wx" })).toThrow();
		expectWriteDenied(backend, join(root, ".git", "hooks"));
		expectWriteDenied(backend, join(root, ".git", "config"));
	});

	it("protects the active metadata behind a gitfile", () => {
		const root = mkdtempSync(join(tmpdir(), "enclave-gitfile-anchor-"));
		roots.push(root);
		const actual = join(root, ".actualgit");
		mkdirSync(actual);
		writeFileSync(join(root, ".git"), "gitdir: .actualgit\n");
		const effective = defaultProfile({ cwd: root, home: "/home/u", tmp: SANDBOX_TMPDIR, agentDir: "/agent" });
		const backend = toBackendProfile(effective, root);
		materializeWriteDenyAnchors(backend);
		expectWriteDenied(backend, join(root, ".git"));
		expectWriteDenied(backend, join(actual, "hooks"));
		expectWriteDenied(backend, join(actual, "config"));
		expect(() => mkdirSync(join(actual, "hooks"))).toThrow();
	});

	it("materializes inert Git anchors before the first repository operation", () => {
		const root = mkdtempSync(join(tmpdir(), "enclave-no-git-anchor-"));
		roots.push(root);
		const effective = defaultProfile({ cwd: root, home: "/home/u", tmp: SANDBOX_TMPDIR, agentDir: "/agent" });
		const backend = toBackendProfile(effective, root);
		materializeWriteDenyAnchors(backend);
		expectWriteDenied(backend, join(root, ".git", "hooks"));
		expectWriteDenied(backend, join(root, ".git", "config"));
		expect(existsSync(join(root, ".git"))).toBe(true);
		expect(existsSync(join(root, ".git", "hooks"))).toBe(true);
		expect(existsSync(join(root, ".git", "config"))).toBe(true);
		expectWriteAllowed(backend, join(root, ".git", "index"));
		writeFileSync(join(root, ".git", "index"), "ordinary metadata stays writable");
	});

	it("protects effective and conditionally reachable Git configs and hook paths", () => {
		const root = mkdtempSync(join(tmpdir(), "enclave-git-includes-"));
		roots.push(root);
		initGit(root);
		const activeConfig = join(root, "agent-controlled.cfg");
		const conditionalConfig = join(root, "conditional.cfg");
		writeFileSync(activeConfig, "[core]\n\thooksPath = .githooks\n");
		writeFileSync(conditionalConfig, "[core]\n\thooksPath = .conditional-hooks\n");
		writeFileSync(
			join(root, ".git", "config"),
			"[core]\n\trepositoryFormatVersion = 0\n\tbare = false\n" +
				"[include]\n\tpath = ../agent-controlled.cfg\n" +
				'[includeIf "onbranch:release/**"]\n\tpath = ../conditional.cfg\n',
		);

		const effective = defaultProfile({ cwd: root, home: "/home/u", tmp: SANDBOX_TMPDIR, agentDir: "/agent" });
		const backend = toBackendProfile(effective, root);
		materializeWriteDenyAnchors(backend);

		expectWriteDenied(backend, activeConfig);
		expectWriteDenied(backend, conditionalConfig);
		expectWriteDenied(backend, join(root, ".githooks"));
		expectWriteDenied(backend, join(root, ".conditional-hooks"));
		expect(existsSync(join(root, ".githooks"))).toBe(true);
		expect(existsSync(join(root, ".conditional-hooks"))).toBe(true);
		expectWriteAllowed(backend, join(root, ".git", "index"));
	});

	it("honors /dev/null as an explicit hook-disable path", () => {
		const root = mkdtempSync(join(tmpdir(), "enclave-git-hooks-disabled-"));
		roots.push(root);
		initGit(root);
		const configured = spawnSync("git", ["-C", root, "config", "core.hooksPath", "/dev/null"]);
		expect(configured.status).toBe(0);
		const effective = defaultProfile({ cwd: root, home: "/home/u", tmp: SANDBOX_TMPDIR, agentDir: "/agent" });
		const backend = toBackendProfile(effective, root);
		expect(backend.writeDeny).not.toContain("/dev/null");
		expect(backend.materializeWriteDeny).not.toContain("/dev/null");
	});

	it("protects config and hooks at the root of a bare repository", () => {
		const root = mkdtempSync(join(tmpdir(), "enclave-bare-git-"));
		roots.push(root);
		const initialized = spawnSync("git", ["init", "--bare", "-q", root], { encoding: "utf8" });
		if (initialized.status !== 0) throw new Error(initialized.stderr || "git init --bare failed");
		const effective = defaultProfile({ cwd: root, home: "/home/u", tmp: SANDBOX_TMPDIR, agentDir: "/agent" });
		const backend = toBackendProfile(effective, root);
		expectWriteDenied(backend, join(root, "config"));
		expectWriteDenied(backend, join(root, "hooks"));
		expectWriteAllowed(backend, join(root, "objects"));
		expectWriteAllowed(backend, join(root, "refs"));
	});

	it("protects existing submodule config and hooks using the submodule worktree as the hook base", () => {
		const root = mkdtempSync(join(tmpdir(), "enclave-submodule-git-"));
		roots.push(root);
		initGit(root);
		const worktree = join(root, "demo");
		mkdirSync(worktree);
		const metadata = join(root, ".git", "modules", "demo");
		mkdirSync(join(root, ".git", "modules"));
		const initialized = spawnSync("git", ["init", "--bare", "-q", metadata], { encoding: "utf8" });
		if (initialized.status !== 0) throw new Error(initialized.stderr || "git init submodule metadata failed");
		writeFileSync(
			join(metadata, "config"),
			"[core]\n\trepositoryFormatVersion = 0\n\tbare = false\n\tworktree = ../../../demo\n\thooksPath = .githooks\n",
		);
		writeFileSync(join(worktree, ".git"), "gitdir: ../.git/modules/demo\n");

		const effective = defaultProfile({ cwd: root, home: "/home/u", tmp: SANDBOX_TMPDIR, agentDir: "/agent" });
		const backend = toBackendProfile(effective, root);
		materializeWriteDenyAnchors(backend);

		expectWriteDenied(backend, join(metadata, "config"));
		expectWriteDenied(backend, join(metadata, "hooks"));
		expectWriteDenied(backend, join(worktree, ".git"));
		expectWriteDenied(backend, join(worktree, ".githooks"));
		expect(existsSync(join(metadata, "hooks"))).toBe(true);
		expect(existsSync(join(worktree, ".githooks"))).toBe(true);
		expectWriteAllowed(backend, join(metadata, "objects"));
		expectWriteAllowed(backend, join(metadata, "refs"));
	});

	it("infers a submodule worktree from its validated gitfile when core.worktree is absent", () => {
		const root = mkdtempSync(join(tmpdir(), "enclave-inferred-submodule-"));
		roots.push(root);
		initGit(root);
		const worktree = join(root, "demo");
		mkdirSync(worktree);
		const metadata = join(root, ".git", "modules", "demo");
		mkdirSync(join(root, ".git", "modules"));
		const initialized = spawnSync("git", ["init", "--bare", "-q", metadata], { encoding: "utf8" });
		if (initialized.status !== 0) throw new Error(initialized.stderr || "git init submodule metadata failed");
		writeFileSync(
			join(metadata, "config"),
			"[core]\n\trepositoryFormatVersion = 0\n\tbare = false\n\thooksPath = .githooks\n",
		);
		writeFileSync(join(worktree, ".git"), "gitdir: ../.git/modules/demo\n");
		writeFileSync(join(root, ".gitmodules"), '[submodule "demo"]\n\tpath = demo\n\turl = ../source\n');

		const effective = defaultProfile({ cwd: root, home: "/home/u", tmp: SANDBOX_TMPDIR, agentDir: "/agent" });
		const backend = toBackendProfile(effective, root);
		materializeWriteDenyAnchors(backend);

		expectWriteDenied(backend, join(worktree, ".git"));
		expectWriteDenied(backend, join(worktree, ".githooks"));
		expectWriteAllowed(backend, join(metadata, ".githooks"));
	});

	it("materializes a missing reachable include before the sandbox starts", () => {
		const root = mkdtempSync(join(tmpdir(), "enclave-git-future-include-"));
		roots.push(root);
		initGit(root);
		const future = join(root, "future.cfg");
		writeFileSync(join(root, ".git", "config"), "[include]\n\tpath = ../future.cfg\n");
		const effective = defaultProfile({ cwd: root, home: "/home/u", tmp: SANDBOX_TMPDIR, agentDir: "/agent" });
		const backend = toBackendProfile(effective, root);
		materializeWriteDenyAnchors(backend);
		expectWriteDenied(backend, future);
		expect(existsSync(future)).toBe(true);
	});

	it("fails closed for a writable symlinked include path", () => {
		const root = mkdtempSync(join(tmpdir(), "enclave-git-symlinked-include-"));
		roots.push(root);
		initGit(root);
		writeFileSync(join(root, "real.cfg"), "[core]\n\thooksPath = .githooks\n");
		symlinkSync(join(root, "real.cfg"), join(root, "linked.cfg"));
		writeFileSync(join(root, ".git", "config"), "[include]\n\tpath = ../linked.cfg\n");
		const effective = defaultProfile({ cwd: root, home: "/home/u", tmp: SANDBOX_TMPDIR, agentDir: "/agent" });
		expect(() => toBackendProfile(effective, root)).toThrow("not a real file");
	});

	it("fails closed for a hard-linked Git configuration", () => {
		const root = mkdtempSync(join(tmpdir(), "enclave-git-hardlink-config-"));
		roots.push(root);
		initGit(root);
		linkSync(join(root, ".git", "config"), join(root, "config-alias"));
		const effective = defaultProfile({ cwd: root, home: "/home/u", tmp: SANDBOX_TMPDIR, agentDir: "/agent" });

		expect(() => toBackendProfile(effective, root)).toThrow("multiple hard links");
	});

	it("fails closed for a symlinked or hard-linked Git hook entry", () => {
		const root = mkdtempSync(join(tmpdir(), "enclave-git-hook-alias-"));
		roots.push(root);
		initGit(root);
		writeFileSync(join(root, "hook-target"), "#!/bin/sh\n");
		symlinkSync(join(root, "hook-target"), join(root, ".git", "hooks", "pre-commit"));
		const effective = defaultProfile({ cwd: root, home: "/home/u", tmp: SANDBOX_TMPDIR, agentDir: "/agent" });
		expect(() => toBackendProfile(effective, root)).toThrow("symlinked Git hook entry");

		rmSync(join(root, ".git", "hooks", "pre-commit"));
		linkSync(join(root, "hook-target"), join(root, ".git", "hooks", "pre-commit"));
		expect(() => toBackendProfile(effective, root)).toThrow("multiple hard links");
	});

	it("fails closed when a declared deny anchor has no trusted parent", () => {
		const root = mkdtempSync(join(tmpdir(), "enclave-missing-parent-"));
		roots.push(root);
		expect(() =>
			materializeWriteDenyAnchors({
				...profile([root]),
				materializeWriteDeny: [join(root, "missing", "anchor")],
			}),
		).toThrow("protected write-deny parent does not exist");
	});
});
