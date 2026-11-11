import {
	chmodSync,
	existsSync,
	lstatSync,
	mkdirSync,
	mkdtempSync,
	rmSync,
	statSync,
	symlinkSync,
	utimesSync,
	writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
	type LstatFn,
	ScratchDirError,
	SessionScratch,
	scratchBase,
	sweepStaleScratch,
	verifyPrivateDir,
} from "../../src/backend/scratch.ts";

const roots: string[] = [];
afterEach(() => {
	for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function workdir(): string {
	const root = mkdtempSync(join(tmpdir(), "enclave-scratch-test-"));
	roots.push(root);
	return root;
}

const uid = process.getuid?.();

describe("scratch directory checks (#20)", () => {
	it("refuses a pre-existing symlink", () => {
		const root = workdir();
		const target = join(root, "attacker");
		mkdirSync(target, { mode: 0o700 });
		const link = join(root, "pi-enclave-1000");
		symlinkSync(target, link);
		expect(() => verifyPrivateDir(link)).toThrow(/is a symlink/);
	});

	it("refuses a directory owned by another uid", () => {
		const root = workdir();
		mkdirSync(join(root, "other"), { mode: 0o700 });
		const real = lstatSync(join(root, "other"));
		const foreign: LstatFn = () => ({
			uid: (uid ?? 1000) + 1,
			mode: real.mode,
			mtimeMs: real.mtimeMs,
			isDirectory: () => true,
			isSymbolicLink: () => false,
		});
		expect(() => verifyPrivateDir(join(root, "other"), { lstat: foreign, uid: uid ?? 1000 })).toThrow(/owned by uid/);
	});

	it("refuses a 0777 directory instead of repairing it", () => {
		const root = workdir();
		const open = join(root, "open");
		mkdirSync(open);
		chmodSync(open, 0o777);
		expect(() => verifyPrivateDir(open)).toThrow(/mode 777/);
		expect(statSync(open).mode & 0o777).toBe(0o777);
	});

	it("refuses something that is not a directory", () => {
		const root = workdir();
		writeFileSync(join(root, "file"), "");
		expect(() => verifyPrivateDir(join(root, "file"))).toThrow(/not a directory/);
	});

	it("refuses to start when the per-user base was pre-created unsafely", () => {
		const root = workdir();
		const base = join(root, "pi-enclave-base");
		mkdirSync(base);
		chmodSync(base, 0o777);
		expect(() => SessionScratch.create({ base })).toThrow(ScratchDirError);

		const linkBase = join(root, "pi-enclave-link");
		symlinkSync(root, linkBase);
		expect(() => SessionScratch.create({ base: linkBase })).toThrow(/symlink/);
	});
});

describe("session scratch lifecycle (#20)", () => {
	it("gives two concurrent sessions different private directories", () => {
		const base = join(workdir(), "pi-enclave-u");
		const first = SessionScratch.create({ base });
		const second = SessionScratch.create({ base });
		try {
			expect(first.path).not.toBe(second.path);
			for (const scratch of [first, second]) {
				const stats = lstatSync(scratch.path);
				expect(stats.isDirectory()).toBe(true);
				expect(stats.mode & 0o777).toBe(0o700);
				if (uid !== undefined) expect(stats.uid).toBe(uid);
			}
			expect(lstatSync(base).mode & 0o777).toBe(0o700);
		} finally {
			first.dispose();
			second.dispose();
		}
	});

	it("removes the directory and its contents on dispose", () => {
		const base = join(workdir(), "pi-enclave-u");
		const scratch = SessionScratch.create({ base });
		const outside = join(workdir(), "keep");
		writeFileSync(outside, "keep");
		mkdirSync(join(scratch.path, "nested"));
		writeFileSync(join(scratch.path, "nested", "tmpfile"), "x");
		// A link planted by the agent must be removed, not followed.
		symlinkSync(outside, join(scratch.path, "link"));
		scratch.dispose();
		expect(existsSync(scratch.path)).toBe(false);
		expect(existsSync(outside)).toBe(true);
		scratch.dispose();
	});

	it("sweeps a dead session's directory at the next start, and keeps live or recent ones", () => {
		const base = join(workdir(), "pi-enclave-u");
		mkdirSync(base, { mode: 0o700 });
		const old = Date.now() / 1000 - 2 * 3600;
		const dead = join(base, "session-999991-abc");
		const alive = join(base, "session-999992-abc");
		const recent = join(base, "session-999993-abc");
		const unrelated = join(base, "notes");
		for (const dir of [dead, alive, recent, unrelated]) mkdirSync(dir);
		for (const dir of [dead, alive, unrelated]) utimesSync(dir, old, old);
		const removed = sweepStaleScratch(base, { isAlive: (pid) => pid === 999992 });
		expect(removed).toEqual([dead]);
		expect(existsSync(dead)).toBe(false);
		for (const dir of [alive, recent, unrelated]) expect(existsSync(dir), dir).toBe(true);
	});
});

describe("scratchBase", () => {
	const privateDir: LstatFn = () => ({
		uid: 1000,
		mode: 0o40700,
		mtimeMs: 0,
		isDirectory: () => true,
		isSymbolicLink: () => false,
	});

	it("uses XDG_RUNTIME_DIR when it is this user's private directory, and never TMPDIR", () => {
		expect(scratchBase({ XDG_RUNTIME_DIR: "/run/user/1000", TMPDIR: "/" }, 1000, privateDir)).toBe(
			"/run/user/1000/pi-enclave-1000",
		);
		expect(scratchBase({ TMPDIR: "/home/u/repo" }, 501, privateDir)).toBe("/tmp/pi-enclave-501");
	});

	it("falls back to /tmp for a relative, foreign, missing or open XDG_RUNTIME_DIR", () => {
		expect(scratchBase({ XDG_RUNTIME_DIR: "relative" }, 1000, privateDir)).toBe("/tmp/pi-enclave-1000");
		// Inherited across su: another user's runtime directory.
		expect(scratchBase({ XDG_RUNTIME_DIR: "/run/user/0" }, 1000, () => ({ ...privateDir("/"), uid: 0 }))).toBe(
			"/tmp/pi-enclave-1000",
		);
		expect(
			scratchBase({ XDG_RUNTIME_DIR: "/run/user/1000" }, 1000, () => {
				throw new Error("ENOENT");
			}),
		).toBe("/tmp/pi-enclave-1000");
		expect(
			scratchBase({ XDG_RUNTIME_DIR: "/run/user/1000" }, 1000, () => ({ ...privateDir("/"), mode: 0o40777 })),
		).toBe("/tmp/pi-enclave-1000");
	});
});
