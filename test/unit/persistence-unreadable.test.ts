/**
 * A workspace that holds a directory owned by another account, such as a
 * database volume, must still compile (#33 review). This only means anything
 * as an unprivileged user, since root lists every directory, so the scan runs
 * in a child: as `nobody` when the tests run as root, and as the current user
 * otherwise, with `sudo` making the foreign-owned directory.
 */
import { spawnSync } from "node:child_process";
import { chmodSync, chownSync, mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";

const REPO = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const NOBODY = 65_534;
const asRoot = process.getuid?.() === 0;
const sudo = !asRoot && process.platform !== "win32" && spawnSync("sudo", ["-n", "true"]).status === 0;
// Root makes another uid by switching to `nobody`; anyone else needs sudo to
// make a directory they do not own.
const runnable = asRoot || sudo;

const roots: string[] = [];
afterEach(() => {
	for (const root of roots.splice(0)) {
		if (sudo) spawnSync("sudo", ["-n", "rm", "-rf", root]);
		else rmSync(root, { recursive: true, force: true });
	}
});

function git(args: string[]) {
	const result = spawnSync("git", args, { encoding: "utf8" });
	if (result.status !== 0) throw new Error(result.stderr || `git ${args.join(" ")} failed`);
}

/** A workspace with an ordinary nested repository, owned by the scanning user. */
function workspace(): string {
	const root = realpathSync(mkdtempSync(join(tmpdir(), "enclave-unreadable-")));
	roots.push(root);
	git(["init", "-q", join(root, "vendor", "inner")]);
	return root;
}

/** Hand the tree to the user the child scans as. */
function ownForScanner(root: string): void {
	if (!asRoot) return;
	chmodSync(root, 0o755);
	spawnSync("chown", ["-R", `${NOBODY}:${NOBODY}`, root]);
}

/** A directory owned by another account, mode 0700, holding a repository. */
function foreignDir(path: string): void {
	git(["init", "-q", join(path, "hidden")]);
	if (asRoot) {
		chownSync(path, 0, 0);
		chmodSync(path, 0o700);
	} else {
		const result = spawnSync("sudo", ["-n", "sh", "-c", `chown 0:0 '${path}' && chmod 700 '${path}'`]);
		if (result.status !== 0) throw new Error(`sudo chown failed: ${result.stderr}`);
	}
}

interface ScanOutcome {
	error?: string;
	entries?: string[];
	unscanned?: string[];
	profileUnscanned?: string[];
	writeDeny?: string[];
	surface?: string[];
}

function scanAs(root: string): ScanOutcome {
	const script = `
		const { findGitEntries, gitPersistenceSurface } = await import(${JSON.stringify(join(REPO, "src/persistence/git.ts"))});
		const { defaultProfile } = await import(${JSON.stringify(join(REPO, "src/config/defaults.ts"))});
		const { toBackendProfile } = await import(${JSON.stringify(join(REPO, "src/config/profile.ts"))});
		const root = ${JSON.stringify(root)};
		try {
			const unscanned = [];
			const entries = findGitEntries([root], { unscanned }).map((entry) => entry.path);
			const surface = [...gitPersistenceSurface([root]).keys()];
			const profile = toBackendProfile(
				defaultProfile({ cwd: root, home: "/nonexistent-home", agentDir: "/nonexistent-agent" }),
				root,
			);
			console.log(JSON.stringify({ entries, unscanned, surface, profileUnscanned: profile.unscanned, writeDeny: profile.writeDeny }));
		} catch (error) {
			console.log(JSON.stringify({ error: error.message }));
		}
	`;
	const result = spawnSync(process.execPath, ["--import", "tsx", "--input-type=module", "-e", script], {
		cwd: REPO,
		encoding: "utf8",
		env: { ...process.env, HOME: "/nonexistent-home", TMPDIR: tmpdir() },
		...(asRoot ? { uid: NOBODY, gid: NOBODY } : {}),
	});
	const line = result.stdout.trim().split("\n").at(-1) ?? "";
	if (!line.startsWith("{")) throw new Error(`scan child failed: ${result.stderr}`);
	return JSON.parse(line) as ScanOutcome;
}

describe.skipIf(!runnable)("a directory this user cannot reach (#33)", () => {
	it("is skipped, and listed, when another account owns it and we cannot search it", () => {
		const root = workspace();
		const pgdata = join(root, "pgdata");
		mkdirSync(pgdata);
		ownForScanner(root);
		foreignDir(pgdata);

		const outcome = scanAs(root);
		expect(outcome.error).toBeUndefined();
		expect(outcome.unscanned).toEqual([pgdata]);
		expect(outcome.profileUnscanned).toEqual([pgdata]);
		// The rest of the tree is still covered.
		expect(outcome.entries).toEqual([join(root, "vendor", "inner", ".git")]);
		expect(outcome.writeDeny).toContain(join(root, "vendor", "inner", ".git", "config"));
		expect(outcome.surface).toContain(pgdata);
	});

	it("still refuses a directory the scanning user owns but cannot list", () => {
		const root = workspace();
		const mine = join(root, "mine");
		mkdirSync(mine);
		writeFileSync(join(mine, "x"), "");
		ownForScanner(root);
		chmodSync(mine, 0o000);

		const outcome = scanAs(root);
		chmodSync(mine, 0o700);
		expect(outcome.error).toMatch(/cannot inspect .*mine/);
	});

	it("still refuses a directory another account owns that we can search but not list", () => {
		const root = workspace();
		const dropbox = join(root, "dropbox");
		mkdirSync(dropbox);
		ownForScanner(root);
		foreignDir(dropbox);
		// Search without read: a name inside can be opened by anyone who knows it.
		if (asRoot) chmodSync(dropbox, 0o711);
		else spawnSync("sudo", ["-n", "chmod", "711", dropbox]);

		const outcome = scanAs(root);
		expect(outcome.error).toMatch(/cannot inspect .*dropbox/);
	});
});
