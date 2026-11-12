/**
 * #64: the existing protected paths an unjudged command could change, found
 * by one bounded walk and write-denied for that call; the gate's decision to
 * ask when they cannot all be denied; and the tripwire watching every
 * protected pattern for what L2 cannot deny before it exists.
 */
import { spawnSync } from "node:child_process";
import { linkSync, mkdirSync, mkdtempSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { withProtectedWrites } from "../../src/backend/capability.ts";
import type { Profile } from "../../src/backend/types.ts";
import {
	DEFAULT_PROTECTED_ASK,
	DEFAULT_PROTECTED_DENY,
	defaultProfile,
	OWNED_TOOLS,
} from "../../src/config/defaults.ts";
import type { EffectiveProfile } from "../../src/config/types.ts";
import { ActionLock, decide, type GateDeps } from "../../src/gate/gate.ts";
import { protectedEntryMatcher, protectedPathMatcher, protectedWriteTargets } from "../../src/gate/protected-writes.ts";
import { persistenceSurface } from "../../src/persistence/agent.ts";
import { countsAgainstTurn, PersistenceTripwire } from "../../src/persistence/tripwire.ts";
import { matchesPathPattern } from "../../src/policy/paths.ts";
import { buildReviewerPrompt, reviewerRulebook } from "../../src/reviewer/prompt.ts";
import { IsolatedReviewer } from "../../src/reviewer/reviewer.ts";

const PATTERNS = [...DEFAULT_PROTECTED_DENY, ...DEFAULT_PROTECTED_ASK];

let ws: string;

beforeEach(() => {
	ws = realpathSync(mkdtempSync(join(tmpdir(), "enclave-protected-")));
});
afterEach(() => rmSync(ws, { recursive: true, force: true }));

function put(relative: string, content = "x\n"): string {
	const path = join(ws, relative);
	mkdirSync(join(path, ".."), { recursive: true });
	writeFileSync(path, content);
	return path;
}

const targets = (extra: Partial<Parameters<typeof protectedWriteTargets>[0]> = {}) =>
	protectedWriteTargets({ writableRoots: [ws], workspace: ws, patterns: PATTERNS, ...extra });

describe("finding the protected paths of an unjudged command", () => {
	it("matches exactly what L1's matcher matches", () => {
		const matcher = protectedPathMatcher([...PATTERNS, "infra/**", "deploy/*.yaml"], ws);
		const paths = [
			"AGENTS.md",
			"docs/CLAUDE.md",
			"agents.md",
			".envrc",
			"a/.husky/pre-commit",
			".github/workflows/ci.yml",
			".github/dependabot.yml",
			"Dockerfile",
			"svc/docker-compose.prod.yaml",
			"infra/main.tf",
			"a/infra/main.tf",
			"deploy/app.yaml",
			"deploy/sub/app.yaml",
			"src/index.ts",
			".git/config",
			"x/.git/hooks/pre-commit",
			".vscode/tasks.json",
			".vscode/settings.json",
			"README.md",
		].map((relative) => join(ws, relative));
		for (const path of [...paths, "/elsewhere/infra/main.tf", "/etc/AGENTS.md"]) {
			expect(matcher(path), path).toBe(
				matchesPathPattern([...PATTERNS, "infra/**", "deploy/*.yaml"], path, ws) !== undefined,
			);
		}
	});

	it("finds existing protected files and directories, and nothing else", () => {
		put("AGENTS.md");
		put("pkg/CLAUDE.md");
		put(".husky/pre-commit");
		put(".github/workflows/ci.yml");
		put(".github/dependabot.yml");
		put("Dockerfile");
		put("src/index.ts");
		put("infra/main.tf");
		const found = targets({ patterns: [...PATTERNS, "infra/**"] });
		expect(found).toEqual({
			ok: true,
			paths: expect.arrayContaining([
				join(ws, "AGENTS.md"),
				join(ws, "pkg", "CLAUDE.md"),
				join(ws, ".husky"),
				join(ws, ".github", "workflows"),
				join(ws, "Dockerfile"),
				join(ws, "infra"),
			]),
		});
		expect(found.ok && found.paths).toHaveLength(6);
	});

	it("covers a user-global pattern only when it is configured", () => {
		put("infra/main.tf");
		expect(targets()).toEqual({ ok: true, paths: [] });
		expect(targets({ patterns: [...PATTERNS, "infra/**"] })).toEqual({ ok: true, paths: [join(ws, "infra")] });
	});

	it("skips what the session profile already denies, and what is outside the writable roots", () => {
		put(".husky/pre-commit");
		put("AGENTS.md");
		expect(targets({ writeDeny: [join(ws, ".husky")] })).toEqual({ ok: true, paths: [join(ws, "AGENTS.md")] });
		const outside = realpathSync(mkdtempSync(join(tmpdir(), "enclave-protected-out-")));
		try {
			writeFileSync(join(outside, "AGENTS.md"), "x\n");
			symlinkSync(join(outside, "AGENTS.md"), join(ws, "CLAUDE.md"));
			// The link's target is outside every writable root: nothing to deny.
			expect(targets({ writeDeny: [join(ws, ".husky")] })).toEqual({ ok: true, paths: [join(ws, "AGENTS.md")] });
		} finally {
			rmSync(outside, { recursive: true, force: true });
		}
	});

	it("protects a symlinked instruction file through its target", () => {
		const target = put("notes/instructions.txt");
		symlinkSync(join("notes", "instructions.txt"), join(ws, "CLAUDE.md"));
		expect(targets()).toEqual({ ok: true, paths: [target] });
		// A dangling one would create its target when written through.
		symlinkSync("missing.md", join(ws, "AGENTS.md"));
		const found = targets();
		expect(found.ok).toBe(false);
		expect(!found.ok && found.reason).toContain("does not exist yet, so writing through it would create it");
	});

	// Review of #71: a read-only bind holds a name, not an inode, so what a
	// directory denied whole holds is looked at too.
	describe("inside a directory denied whole", () => {
		it("refuses a file with another name outside it, as `cp -al .github gh-backup` leaves", () => {
			const ci = put(".github/workflows/ci.yml");
			mkdirSync(join(ws, "gh-backup", "workflows"), { recursive: true });
			linkSync(ci, join(ws, "gh-backup", "workflows", "ci.yml"));
			const found = targets();
			expect(found.ok).toBe(false);
			expect(!found.ok && found.reason).toMatch(/ci\.yml is protected and has 2 hard links/);
		});

		it("holds a symlink through its target", () => {
			const hook = put("scripts/hook.sh");
			put(".husky/pre-commit");
			symlinkSync(join("..", "scripts", "hook.sh"), join(ws, ".husky", "pre-push"));
			expect(targets()).toEqual({ ok: true, paths: [join(ws, ".husky"), hook] });
		});

		it("refuses a symlink whose target does not exist yet", () => {
			put(".husky/pre-commit");
			symlinkSync(join("..", "scripts", "missing.sh"), join(ws, ".husky", "pre-push"));
			const found = targets();
			expect(found.ok).toBe(false);
			expect(!found.ok && found.reason).toContain("would create it");
		});

		it("follows a symlink back into itself once", () => {
			put(".husky/pre-commit");
			symlinkSync(".", join(ws, ".husky", "loop"));
			expect(targets()).toEqual({ ok: true, paths: [join(ws, ".husky")] });
		});

		it("counts what it holds against the bound", () => {
			for (let i = 0; i < 20; i++) put(`.husky/h${i}`);
			// The walk for names sees one entry; the look inside sees twenty.
			const found = targets({ maxEntries: 10 });
			expect(found.ok).toBe(false);
			expect(!found.ok && found.reason).toContain("more than 10 entries");
			expect(targets({ maxEntries: 25 }).ok).toBe(true);
		});

		it("shares one bound between the walk for names and the look inside", () => {
			for (let i = 0; i < 8; i++) put(`src/f${i}`);
			for (let i = 0; i < 5; i++) put(`.husky/h${i}`);
			// Ten for the walk (src, its eight files, .husky) and five inside.
			expect(targets({ maxEntries: 14 }).ok).toBe(false);
			expect(targets({ maxEntries: 15 }).ok).toBe(true);
		});

		it("accepts a symlink to a missing target outside the writable roots", () => {
			put(".husky/pre-commit");
			const outside = join(realpathSync(tmpdir()), "enclave-missing-target", "hook.sh");
			symlinkSync(outside, join(ws, ".husky", "pre-push"));
			expect(targets()).toEqual({ ok: true, paths: [join(ws, ".husky")] });
			// The same through a chain whose middle link is inside the workspace.
			symlinkSync(outside, join(ws, "middle"));
			symlinkSync(join("..", "middle"), join(ws, ".husky", "pre-merge"));
			expect(targets()).toEqual({ ok: true, paths: [join(ws, ".husky")] });
		});
	});

	it("does not walk Git metadata, but adds the config and hooks of a repository it finds", () => {
		const init = spawnSync("git", ["init", "-q", join(ws, "later")], { encoding: "utf8" });
		expect(init.status, init.stderr).toBe(0);
		put("later/.git/objects/zz/AGENTS.md");
		const found = targets();
		expect(found).toEqual({
			ok: true,
			paths: expect.arrayContaining([join(ws, "later", ".git", "config"), join(ws, "later", ".git", "hooks")]),
		});
		expect(found.ok && found.paths.some((path) => path.includes("objects"))).toBe(false);
	});

	it("refuses a protected file with another hard link", () => {
		const agents = put("AGENTS.md");
		linkSync(agents, join(ws, "notes.txt"));
		const found = targets();
		expect(found.ok).toBe(false);
		expect(!found.ok && found.reason).toContain("hard links");
	});

	it("gives up past its bound instead of vouching for what it did not see", () => {
		for (let i = 0; i < 20; i++) put(`d/f${i}`);
		const found = targets({ maxEntries: 10 });
		expect(found.ok).toBe(false);
		expect(!found.ok && found.reason).toContain("more than 10 entries");
	});

	it("drops a path inside another one", () => {
		put(".husky/pre-commit");
		put(".husky/agents.md");
		// The link's target is inside .husky, which is denied whole.
		symlinkSync(join(".husky", "agents.md"), join(ws, "CLAUDE.md"));
		expect(targets()).toEqual({ ok: true, paths: [join(ws, ".husky")] });
	});

	it("denies a directory whole only when a pattern covers what it holds", () => {
		put("infra/main.tf");
		put("build/out.js");
		// `infra/*` covers the directory's entries, so new ones are held too;
		// `**/build` names only the directory, whose contents are ordinary.
		expect(targets({ patterns: [...PATTERNS, "infra/*", "**/build"] })).toEqual({
			ok: true,
			paths: [join(ws, "infra")],
		});
	});
});

describe("the backend's per-call profile", () => {
	const base = (): Profile => ({
		mode: "workspace-write",
		writableRoots: [ws],
		writeDeny: [join(ws, ".pi")],
		readDeny: [],
		network: "off",
		allowPty: true,
	});

	it("adds the paths to writeDeny and changes nothing else", () => {
		const agents = put("AGENTS.md");
		const profile = base();
		const out = withProtectedWrites(profile, [agents]);
		expect(out).toEqual({ ...profile, writeDeny: [join(ws, ".pi"), agents] });
	});

	it.each([
		["a relative path", () => "AGENTS.md", /canonical/],
		["a missing path", () => join(ws, "missing.md"), /cannot protect/],
		[
			"a symlink",
			() => {
				symlinkSync(put("AGENTS.md"), join(ws, "CLAUDE.md"));
				return join(ws, "CLAUDE.md");
			},
			/canonical/,
		],
		["a path outside the writable roots", () => realpathSync(tmpdir()), /outside the writable roots/],
		[
			"a FIFO",
			() => {
				const fifo = join(ws, "AGENTS.md");
				const made = spawnSync("mkfifo", [fifo], { encoding: "utf8" });
				if (made.status !== 0) throw new Error(made.stderr);
				return fifo;
			},
			/not a file or directory/,
		],
	])("refuses %s", (_name, path, message) => {
		expect(() => withProtectedWrites(base(), [path()])).toThrow(message);
	});
});

describe("the gate", () => {
	const HOME = "/nonexistent-home/u";
	const OPTIONS = { cwd: "/work", home: HOME, tmp: "/tmp", agentDir: `${HOME}/.pi/agent` };

	function deps(mode: "sandbox" | "reviewer", issue?: string): GateDeps {
		const profile: EffectiveProfile = defaultProfile(OPTIONS);
		if (mode === "sandbox") profile.rules.onUncertain = "sandbox";
		else {
			profile.reviewer.model = "ollama/reviewer";
			profile.review.trigger = "mutating";
		}
		return {
			profile,
			cwd: "/work",
			home: HOME,
			lock: new ActionLock(),
			owned: OWNED_TOOLS,
			unjudgedWriteIssue: () => issue,
			...(mode === "reviewer"
				? {
						reviewer: new IsolatedReviewer({
							profile,
							prompt: buildReviewerPrompt(reviewerRulebook(profile.review, new Map(), profile.rules)),
							primary: {
								name: "always-allow",
								complete: async () => '{"authorized":false,"decision":"allow","risk":"low","reason":"fine"}',
							},
							timeoutMs: 1_000,
							evidence: { attended: "off" },
							delay: async () => {},
						}),
					}
				: {}),
		};
	}
	const call = (command: string, d: GateDeps) => decide({ toolName: "bash", toolCallId: "c1", input: { command } }, d);

	it.each([
		["sandbox", "sandboxed-uncertain"],
		["reviewer", "review-allow"],
	] as const)("marks an unparsed command run under %s as unjudged", async (mode, outcome) => {
		const decision = await call(`f=AGENTS.md; echo x > "$f"`, deps(mode));
		expect(decision).toMatchObject({ outcome, unjudged: true, block: false });
	});

	it("does not mark a command L1 could read", async () => {
		const decision = await call("git status --short", deps("reviewer"));
		expect(decision.outcome).toBe("review-allow");
		expect(decision.unjudged).toBeUndefined();
	});

	it("does not mark a command a person approved, as in queue mode", async () => {
		const d = deps("sandbox");
		d.profile.rules.onUncertain = "ask";
		const decision = await call(`f=AGENTS.md; echo x > "$f"`, { ...d, escalator: { confirm: async () => true } });
		expect(decision.outcome).toBe("ask-approved");
		expect(decision.unjudged).toBeUndefined();
	});

	it.each(["sandbox", "reviewer"] as const)(
		"asks a person under %s when the protected paths cannot all be denied",
		async (mode) => {
			const decision = await call(`f=AGENTS.md; echo x > "$f"`, deps(mode, "the walk went past its bound"));
			expect(decision.outcome).toBe("ask-denied");
			expect(decision.reason).toContain("cannot all be write-denied for it (the walk went past its bound)");
		},
	);
});

describe("the tripwire on every protected pattern", () => {
	const watch = (patterns: readonly string[]) =>
		new PersistenceTripwire(
			() => persistenceSurface([ws], { isProtectedPath: protectedEntryMatcher(patterns, ws) }),
			ws,
		);

	it("reports a workflow, a Dockerfile and a user-global entry created by an unjudged command, and counts them", () => {
		const tripwire = watch([...PATTERNS, "infra/**"]);
		put(".github/workflows/deploy.yml");
		put("Dockerfile");
		put("svc/docker-compose.yml");
		put("infra/main.tf");
		const hits = tripwire.check();
		const paths = hits.map((hit) => hit.path);
		for (const path of [".github/workflows", "Dockerfile", "svc/docker-compose.yml", "infra"]) {
			expect(paths).toContain(join(ws, path));
		}
		expect(hits.every((hit) => hit.kind === "project")).toBe(true);
		expect(hits.every((hit) => countsAgainstTurn(hit, true))).toBe(true);
		expect(hits.some((hit) => countsAgainstTurn(hit, false))).toBe(false);
	});

	// Review of #71: a protected directory past the fingerprint budget is
	// unverifiable at every check, changed or not, so it counts only once.
	it("counts an unverifiable protected directory once, when it appears, and only when unjudged", () => {
		const vendor = join(ws, "vendor");
		mkdirSync(vendor);
		for (let i = 0; i < 17_000; i++) writeFileSync(join(vendor, `f${i}`), "");
		const tripwire = watch([...PATTERNS, "vendor/**"]);
		for (let turn = 0; turn < 3; turn++) {
			const hits = tripwire.check();
			expect(hits).toEqual([expect.objectContaining({ path: vendor, change: "unverifiable", kind: "project" })]);
			expect(hits.some((hit) => countsAgainstTurn(hit, true))).toBe(false);
		}
		const appeared = { path: vendor, change: "unverifiable", kind: "project", appeared: true } as const;
		expect(countsAgainstTurn(appeared, true)).toBe(true);
		expect(countsAgainstTurn(appeared, false)).toBe(false);
	}, 30_000);

	it("does not report an ordinary file, or Git metadata as a project file", () => {
		// Even when an entry covers Git's own metadata: that is the Git surface's.
		const tripwire = watch([...PATTERNS, "**/.git/**"]);
		put("src/index.ts");
		spawnSync("git", ["init", "-q", join(ws, "repo")]);
		const hits = tripwire.check();
		expect(hits.filter((hit) => hit.kind === "project")).toEqual([]);
	});
});
