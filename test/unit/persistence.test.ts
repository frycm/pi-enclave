import { spawnSync } from "node:child_process";
import {
	mkdirSync,
	mkdtempSync,
	readFileSync,
	realpathSync,
	rmSync,
	statSync,
	symlinkSync,
	utimesSync,
	writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { findGitEntries, gitPersistenceSurface, readGitfile } from "../../src/persistence/git.ts";
import { fingerprint, PersistenceScanError, scanRoots, walkableRoots } from "../../src/persistence/scan.ts";
import { formatTripwireHits, PersistenceTripwire } from "../../src/persistence/tripwire.ts";

const dirs: string[] = [];
function tempDir(prefix: string): string {
	const dir = realpathSync(mkdtempSync(join(tmpdir(), prefix)));
	dirs.push(dir);
	return dir;
}
afterEach(() => {
	for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

function git(args: string[]) {
	const result = spawnSync("git", args, { encoding: "utf8" });
	if (result.status !== 0) throw new Error(result.stderr || `git ${args.join(" ")} failed`);
}

describe("persistence scan (#33)", () => {
	it("walks each root once, even when one writable root is inside another", () => {
		const root = tempDir("enclave-scan-");
		mkdirSync(join(root, "inner"));
		expect(walkableRoots([join(root, "inner"), root, join(root, "missing")])).toEqual([root]);
	});

	it("finds matches at any depth and does not follow symlinks", () => {
		const root = tempDir("enclave-scan-");
		const elsewhere = tempDir("enclave-scan-outside-");
		mkdirSync(join(root, "a", "b", ".git"), { recursive: true });
		mkdirSync(join(elsewhere, "c", ".git"), { recursive: true });
		symlinkSync(elsewhere, join(root, "link"));
		const found = scanRoots([root], { match: (name) => name === ".git" });
		expect(found).toEqual([{ path: join(root, "a", "b", ".git"), kind: "dir" }]);
	});

	it("refuses a tree larger than its bound instead of answering for part of it", () => {
		const root = tempDir("enclave-scan-");
		for (let index = 0; index < 20; index++) writeFileSync(join(root, `f${index}`), "");
		expect(() => scanRoots([root], { match: () => false, maxEntries: 10 })).toThrow(PersistenceScanError);
	});

	it("changes a file's fingerprint when it is edited, even with its old mtime restored", () => {
		const root = tempDir("enclave-scan-");
		const file = join(root, "config");
		writeFileSync(file, "[core]\n\tbare = false\n");
		const before = fingerprint(file);
		const { atime, mtime } = statSync(file);
		// Same size, old mtime: only the change time can tell.
		writeFileSync(file, "[core]\n\tbare = fals3\n");
		utimesSync(file, atime, mtime);
		expect(fingerprint(file)).not.toBe(before);
		expect(fingerprint(join(root, "absent"))).toBeUndefined();
	});
});

describe("Git persistence surface (#33)", () => {
	function superproject(): string {
		const root = tempDir("enclave-git-surface-");
		git(["init", "-q", root]);
		mkdirSync(join(root, ".git", "modules"));
		git(["init", "-q", "--separate-git-dir", join(root, ".git", "modules", "lib"), join(root, "lib")]);
		git(["init", "-q", join(root, "vendor", "inner")]);
		return root;
	}

	it("covers the workspace's, each submodule's and each nested repository's config and hooks", () => {
		const root = superproject();
		const surface = gitPersistenceSurface([root]);
		for (const path of [
			join(root, ".git", "config"),
			join(root, ".git", "hooks"),
			join(root, ".git", "modules"),
			join(root, ".git", "modules", "lib", "config"),
			join(root, ".git", "modules", "lib", "hooks"),
			join(root, "lib", ".git"),
			join(root, "vendor", "inner", ".git"),
			join(root, "vendor", "inner", ".git", "config"),
			join(root, "vendor", "inner", ".git", "hooks"),
		]) {
			expect(surface.has(path), path).toBe(true);
		}
		expect(readGitfile(join(root, "lib", ".git"))).toBe(join(root, ".git", "modules", "lib"));
		expect(findGitEntries([root]).map((entry) => entry.path)).toHaveLength(3);
	});

	it("reports a new nested repository, a new submodule directory and an edited config, once each", () => {
		const root = superproject();
		const tripwire = new PersistenceTripwire(() => gitPersistenceSurface([root]), root);
		expect(tripwire.check()).toEqual([]);

		git(["init", "-q", join(root, "planted")]);
		mkdirSync(join(root, ".git", "modules", "added", "hooks"), { recursive: true });
		writeFileSync(join(root, ".git", "modules", "added", "HEAD"), "ref: refs/heads/main\n");
		writeFileSync(join(root, ".git", "modules", "added", "config"), "[core]\n\tfsmonitor = /tmp/x.sh\n");
		const config = join(root, ".git", "modules", "lib", "config");
		writeFileSync(config, `${readFileSync(config, "utf8")}[core]\n\tfsmonitor = /tmp/x.sh\n`);

		const hits = tripwire.check();
		const byPath = new Map(hits.map((hit) => [hit.path, hit.change]));
		expect(byPath.get(join(root, "planted", ".git"))).toBe("created");
		expect(byPath.get(join(root, "planted", ".git", "config"))).toBe("created");
		expect(byPath.get(join(root, ".git", "modules", "added", "config"))).toBe("created");
		expect(byPath.get(join(root, ".git", "modules"))).toBe("modified");
		expect(byPath.get(config)).toBe("modified");
		// Reported once, then part of the baseline.
		expect(tripwire.check()).toEqual([]);
	});

	it("reports a new hook in an existing hooks directory", () => {
		const root = superproject();
		const tripwire = new PersistenceTripwire(() => gitPersistenceSurface([root]), root);
		writeFileSync(join(root, "vendor", "inner", ".git", "hooks", "pre-commit"), "#!/bin/sh\n");
		expect(tripwire.check()).toEqual([{ path: join(root, "vendor", "inner", ".git", "hooks"), change: "modified" }]);
	});

	it("does not report a removal, and accepts a change after rebaseline", () => {
		const root = superproject();
		const tripwire = new PersistenceTripwire(() => gitPersistenceSurface([root]), root);
		rmSync(join(root, "vendor"), { recursive: true });
		expect(tripwire.check()).toEqual([]);
		git(["init", "-q", join(root, "made-by-user")]);
		tripwire.rebaseline();
		expect(tripwire.check()).toEqual([]);
	});

	it("reports an unreadable surface as unverifiable and keeps the old baseline", () => {
		const root = superproject();
		let fail = false;
		const tripwire = new PersistenceTripwire(() => {
			if (fail) throw new PersistenceScanError("too many entries");
			return gitPersistenceSurface([root]);
		}, root);
		fail = true;
		git(["init", "-q", join(root, "hidden")]);
		expect(tripwire.check()).toEqual([{ path: root, change: "unverifiable", detail: "pi-enclave: too many entries" }]);
		fail = false;
		expect(tripwire.check().map((hit) => hit.path)).toContain(join(root, "hidden", ".git"));
	});

	it("treats a bare-shaped directory as a repository whatever its name", () => {
		const root = superproject();
		const tripwire = new PersistenceTripwire(() => gitPersistenceSurface([root]), root);
		// Git accepts `tools/cache` as a repository from `tools/cache/sub` too:
		// with core.bare=false and core.worktree=., its fsmonitor runs there.
		git(["init", "-q", "--bare", join(root, "tools", "cache")]);
		const cache = join(root, "tools", "cache");
		const hits = new Map(tripwire.check().map((hit) => [hit.path, hit.change]));
		expect(hits.get(cache)).toBe("created");
		expect(hits.get(join(cache, "config"))).toBe("created");
		expect(hits.get(join(cache, "hooks"))).toBe("created");
		writeFileSync(join(cache, "config"), "[core]\n\tbare = false\n\tworktree = .\n\tfsmonitor = /tmp/x.sh\n");
		expect(tripwire.check()).toEqual([{ path: join(cache, "config"), change: "modified" }]);
		expect(findGitEntries([root]).find((entry) => entry.path === cache)?.bare).toBe(true);
	});

	it("treats any HEAD content as a repository, as Git accepts more forms than a pattern would", () => {
		// Git 2.43 accepts both of these as a repository and runs core.fsmonitor
		// from a subdirectory.
		for (const head of [
			"4B825DC642CB6EB9A060E54BF8D69288FBEE4904\n",
			"4b825dc642cb6eb9a060e54bf8d69288fbee4904 trailing junk\n",
			"ref: refs/heads/main\n",
		]) {
			const root = tempDir("enclave-git-surface-");
			mkdirSync(join(root, "cache", "objects"), { recursive: true });
			mkdirSync(join(root, "cache", "refs"));
			writeFileSync(join(root, "cache", "HEAD"), head);
			expect(findGitEntries([root]), head).toEqual([{ path: join(root, "cache"), kind: "dir", bare: true }]);
		}
	});

	it("does not take a directory with HEAD but no objects, refs or commondir for a repository", () => {
		const root = tempDir("enclave-git-surface-");
		mkdirSync(join(root, "cache", "objects"), { recursive: true });
		writeFileSync(join(root, "cache", "HEAD"), "ref: refs/heads/main\n");
		expect(findGitEntries([root])).toEqual([]);
		writeFileSync(join(root, "cache", "commondir"), "../elsewhere\n");
		expect(findGitEntries([root])).toEqual([{ path: join(root, "cache"), kind: "dir", bare: true }]);
	});

	it("names each path and a safe way to inspect the tree", () => {
		const message = formatTripwireHits([{ path: "/work/.git/modules/lib/config", change: "modified" }], "now");
		expect(message).toContain("modified: /work/.git/modules/lib/config");
		expect(message).toContain("core.fsmonitor=false");
	});
});
