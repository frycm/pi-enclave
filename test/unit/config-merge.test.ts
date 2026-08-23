import fc from "fast-check";
import { describe, expect, it } from "vitest";
import { defaultProfile } from "../../src/config/defaults.ts";
import { applyPatch, expandPath, fold, narrowerOrEqual } from "../../src/config/merge.ts";
import type { ConfigDocument, EffectiveProfile, ProfilePatch, SourceId } from "../../src/config/types.ts";

const OPTIONS = { cwd: "/work", home: "/home/u", tmp: "/tmp", agentDir: "/home/u/.pi/agent" };

const base = () => defaultProfile(OPTIONS);

function patched(patch: ProfilePatch, source: SourceId = "project_local"): EffectiveProfile {
	return applyPatch(base(), patch, { ...OPTIONS, source });
}

function fields(violations: { field: string }[]): string[] {
	return violations.map((violation) => violation.field);
}

describe("narrowerOrEqual", () => {
	it("a profile is narrower than or equal to itself", () => {
		expect(narrowerOrEqual(base(), base())).toEqual([]);
	});

	describe("writable roots", () => {
		// Containment rather than set membership is what makes "a project may add
		// roots inside the repo" fall out of the order instead of needing a
		// separate rule beside it.
		it("accepts a root inside an existing one", () => {
			expect(narrowerOrEqual(patched({ sandbox: { writableRoots: ["/work/build"] } }), base())).toEqual([]);
		});

		it("rejects a root outside every existing one", () => {
			const violations = narrowerOrEqual(patched({ sandbox: { writableRoots: ["/etc"] } }), base());
			expect(fields(violations)).toEqual(["sandbox.writableRoots"]);
		});

		it("accepts dropping a root", () => {
			const narrow = base();
			narrow.sandbox.writableRoots = ["/work"];
			expect(narrowerOrEqual(narrow, base())).toEqual([]);
		});
	});

	describe("read denials", () => {
		it("accepts an added denial", () => {
			expect(narrowerOrEqual(patched({ sandbox: { readDeny: ["/work/secrets"] } }), base())).toEqual([]);
		});

		it("rejects a removed denial", () => {
			const wide = base();
			wide.sandbox.readDeny = wide.sandbox.readDeny.filter((entry) => !entry.endsWith(".ssh"));
			expect(fields(narrowerOrEqual(wide, base()))).toEqual(["sandbox.readDeny"]);
		});

		// Replacing `~/.aws/credentials` with `~/.aws` denies strictly more, so an
		// order built on set membership would have called a tightening a
		// violation.
		it("accepts replacing a denial with an ancestor of it", () => {
			const wider = base();
			wider.sandbox.readDeny = ["/home/u/.aws/credentials"];
			const narrower = base();
			narrower.sandbox.readDeny = ["/home/u/.aws"];
			expect(narrowerOrEqual(narrower, wider)).toEqual([]);
		});
	});

	describe("scalars that rank", () => {
		it.each([
			[
				"sandbox.capabilities",
				{ sandbox: { capabilities: "reviewed" as const } },
				{ sandbox: { capabilities: "none" as const } },
			],
			["sandbox.allowPty", { sandbox: { allowPty: true } }, { sandbox: { allowPty: false } }],
			["attended.mode", { attended: { mode: "tui" as const } }, { attended: { mode: "off" as const } }],
		])("%s may only move toward the narrower value", (field, wide, narrow) => {
			expect(narrowerOrEqual(patched(narrow), patched(wide))).toEqual([]);
			expect(fields(narrowerOrEqual(patched(wide), patched(narrow)))).toContain(field);
		});

		it("review.trigger may be raised but not lowered", () => {
			const boundary = patched({ review: { trigger: "boundary" } });
			const all = patched({ review: { trigger: "all" } });
			expect(narrowerOrEqual(all, boundary)).toEqual([]);
			expect(fields(narrowerOrEqual(boundary, all))).toEqual(["review.trigger"]);
		});
	});

	describe("pattern lists", () => {
		it("deny and ask may only grow", () => {
			expect(narrowerOrEqual(patched({ rules: { deny: ["bash(x)"] } }), base())).toEqual([]);
			const shrunk = base();
			shrunk.rules.deny = [];
			expect(fields(narrowerOrEqual(shrunk, base()))).toContain("rules.deny");
		});

		it("skipReview may only shrink", () => {
			const wide = base();
			wide.rules.skipReview = ["bash(npm test*)"];
			expect(narrowerOrEqual(base(), wide)).toEqual([]);
			expect(fields(narrowerOrEqual(wide, base()))).toEqual(["rules.skipReview"]);
		});
	});

	describe("prose lists", () => {
		// Prose has no partial order a merge can check, so equality is the only
		// sound relation -- "append only" is a syntactic superset, not a semantic
		// tightening.
		it("are immutable in both directions", () => {
			const withProse = base();
			withProse.review.soft_deny = ["no migrations outside the CLI"];
			expect(fields(narrowerOrEqual(withProse, base()))).toEqual(["review.soft_deny"]);
			expect(fields(narrowerOrEqual(base(), withProse))).toEqual(["review.soft_deny"]);
		});
	});

	describe("tools", () => {
		it("the allowlist may only shrink", () => {
			const narrow = base();
			delete narrow.tools.allow.write;
			expect(narrowerOrEqual(narrow, base())).toEqual([]);
			const wide = base();
			wide.tools.allow.deploy = {};
			expect(fields(narrowerOrEqual(wide, base()))).toEqual(["tools.allow"]);
		});

		it("readOnly may become reviewed, never the reverse", () => {
			const readOnly = base();
			readOnly.tools.allow.thing = { readOnly: true };
			const reviewed = base();
			reviewed.tools.allow.thing = { reviewed: true };
			expect(narrowerOrEqual(reviewed, readOnly)).toEqual([]);
			expect(fields(narrowerOrEqual(readOnly, reviewed))).toEqual(["tools.allow.thing"]);
		});

		// Without the pin, load order decides who inherits a grant: the first
		// extension to register a tool of that name wins the registration.
		it("a pinned grant cannot be repointed", () => {
			const pinned = base();
			pinned.tools.allow.thing = { source: "/ext/a.ts" };
			const repointed = base();
			repointed.tools.allow.thing = { source: "/ext/b.ts" };
			expect(fields(narrowerOrEqual(repointed, pinned))).toEqual(["tools.allow.thing.source"]);
			const unpinned = base();
			unpinned.tools.allow.thing = {};
			expect(fields(narrowerOrEqual(unpinned, pinned))).toEqual(["tools.allow.thing.source"]);
			// Adding a pin where there was none is a tightening.
			expect(narrowerOrEqual(pinned, unpinned)).toEqual([]);
		});
	});

	it("auto may be turned off but not on", () => {
		const off = { ...base(), auto: false };
		expect(narrowerOrEqual(off, base())).toEqual([]);
		expect(fields(narrowerOrEqual(base(), off))).toEqual(["auto"]);
	});
});

describe("expandPath", () => {
	it.each([
		["~/x", "/home/u/x"],
		["$WORKSPACE/build", "/work/build"],
		["$TMPDIR/scratch", "/tmp/scratch"],
		["build", "/work/build"],
		["/abs", "/abs"],
	])("expands %s", (input, expected) => {
		expect(expandPath(input, OPTIONS)).toBe(expected);
	});
});

describe("fold", () => {
	const doc = (source: SourceId, patch: ProfilePatch, extra: Partial<ConfigDocument> = {}): ConfigDocument => ({
		source,
		patch,
		...extra,
	});

	it("returns the built-in profile when nothing else is present", () => {
		const result = fold([{ source: "builtin" }], OPTIONS);
		if (!result.ok) throw new Error("expected success");
		expect(result.profile).toEqual(base());
	});

	// The user's own file is the ceiling. Checking it against the built-in
	// defaults would mean a user could never widen anything, which is the
	// opposite of what the configuration table says.
	it("lets the user-global file widen the built-in defaults", () => {
		const result = fold(
			[{ source: "builtin" }, doc("user_global", { sandbox: { writableRoots: ["/srv/scratch"] } })],
			OPTIONS,
		);
		if (!result.ok) throw new Error(JSON.stringify(result.errors));
		expect(result.profile.sandbox.writableRoots).toContain("/srv/scratch");
	});

	it("rejects a project file that widens, naming the field", () => {
		const result = fold(
			[
				{ source: "builtin" },
				doc("project_local", { sandbox: { writableRoots: ["/etc"] } }, { path: "/work/.pi/enclave.local.json" }),
			],
			OPTIONS,
		);
		if (result.ok) throw new Error("expected rejection");
		expect(result.errors[0]?.field).toBe("sandbox.writableRoots");
		expect(result.errors[0]?.path).toBe("/work/.pi/enclave.local.json");
	});

	// Union, not replacement. Replacing passes the order check -- dropping a
	// root is a narrowing -- so nothing else in the suite would notice a project
	// file that names `build/` silently removing the workspace and $TMPDIR from
	// the writable roots. Caught by a mutation check, which is why the test is
	// here rather than being assumed.
	it("adds project writable roots to the existing ones instead of replacing them", () => {
		const result = fold(
			[{ source: "builtin" }, doc("project_local", { sandbox: { writableRoots: ["build"] } })],
			OPTIONS,
		);
		if (!result.ok) throw new Error(JSON.stringify(result.errors));
		expect(result.profile.sandbox.writableRoots).toEqual(["/work", "/tmp", "/work/build"]);
	});

	it("accepts a project file that tightens", () => {
		const result = fold(
			[
				{ source: "builtin" },
				doc("project_shared", { rules: { deny: ["bash(terraform destroy*)"] }, review: { trigger: "all" } }),
			],
			OPTIONS,
		);
		if (!result.ok) throw new Error(JSON.stringify(result.errors));
		expect(result.profile.rules.deny).toContain("bash(terraform destroy*)");
		expect(result.profile.review.trigger).toBe("all");
	});

	it("measures a project file against the user-global ceiling, not the defaults", () => {
		const documents: ConfigDocument[] = [
			{ source: "builtin" },
			doc("user_global", { sandbox: { writableRoots: ["/srv/scratch"] } }),
			doc("project_local", { sandbox: { writableRoots: ["/srv/scratch/sub"] } }),
		];
		const result = fold(documents, OPTIONS);
		if (!result.ok) throw new Error(JSON.stringify(result.errors));
		expect(result.profile.sandbox.writableRoots).toContain("/srv/scratch/sub");
	});

	describe("profile selection", () => {
		const userGlobal: ConfigDocument = {
			source: "user_global",
			profile: "dev",
			profiles: {
				dev: { sandbox: { writableRoots: ["/work", "/srv/scratch"] } },
				locked: { sandbox: { writableRoots: [], capabilities: "none" }, attended: { mode: "off" } },
				wider: { sandbox: { writableRoots: ["/etc"] } },
			},
		};

		it("selects the named profile", () => {
			const result = fold([{ source: "builtin" }, userGlobal], OPTIONS);
			if (!result.ok) throw new Error(JSON.stringify(result.errors));
			expect(result.profile.name).toBe("dev");
		});

		it("lets a project select a narrower profile", () => {
			const result = fold([{ source: "builtin" }, userGlobal, { source: "project_local", profile: "locked" }], OPTIONS);
			if (!result.ok) throw new Error(JSON.stringify(result.errors));
			expect(result.profile.name).toBe("locked");
			expect(result.profile.sandbox.capabilities).toBe("none");
		});

		it("refuses a project selecting a wider profile", () => {
			const result = fold([{ source: "builtin" }, userGlobal, { source: "project_local", profile: "wider" }], OPTIONS);
			expect(result.ok).toBe(false);
		});

		it("refuses selecting a profile that is not defined", () => {
			const result = fold([{ source: "builtin" }, userGlobal, { source: "env", profile: "ghost" }], OPTIONS);
			if (result.ok) throw new Error("expected rejection");
			expect(result.errors[0]?.field).toBe("profile");
		});
	});

	// PI_ENCLAVE_AUTO=off disables L1 and L4. It must never touch the sandbox:
	// L2 is the one layer the monotonic rule says nothing may remove, and an
	// environment variable is the least trusted place such a request could
	// come from.
	it("PI_ENCLAVE_AUTO=off clears auto without changing the sandbox", () => {
		const result = fold([{ source: "builtin" }, { source: "env", auto: false }], OPTIONS);
		if (!result.ok) throw new Error(JSON.stringify(result.errors));
		expect(result.profile.auto).toBe(false);
		expect(result.profile.sandbox).toEqual(base().sandbox);
	});

	// Each source is measured against the profile it received, not just the
	// user-global ceiling, so a less-trusted source cannot undo a more-trusted
	// one's narrowing even while staying under the ceiling.
	describe("no source undoes a more-trusted narrowing", () => {
		it("a project cannot revert an env attendance narrowing", () => {
			const userGlobal: ConfigDocument = {
				source: "user_global",
				profile: "dev",
				profiles: { dev: { attended: { mode: "tui" } } },
			};
			const result = fold(
				[
					{ source: "builtin" },
					userGlobal,
					{ source: "env", patch: { attended: { mode: "off" } } },
					// Re-selecting the profile would rebuild attended back to tui.
					{ source: "project_local", profile: "dev", path: "/work/.pi/enclave.local.json" },
				],
				OPTIONS,
			);
			expect(result.ok).toBe(false);
			if (result.ok) return;
			expect(result.errors[0]?.field).toBe("attended.mode");
		});

		it("project-shared cannot undo a project-local tool tightening", () => {
			const userGlobal: ConfigDocument = {
				source: "user_global",
				profile: "dev",
				profiles: { dev: { tools: { allow: { deploy: {} } } } },
			};
			const result = fold(
				[
					{ source: "builtin" },
					userGlobal,
					{ source: "project_local", patch: { tools: { allow: { deploy: { reviewed: true } } } } },
					// Re-widening the grant back to a plain allow, still ≤ ceiling.
					{ source: "project_shared", patch: { tools: { allow: { deploy: {} } } } },
				],
				OPTIONS,
			);
			expect(result.ok).toBe(false);
			if (result.ok) return;
			expect(result.errors[0]?.field).toBe("tools.allow.deploy");
		});

		it("still accepts a genuine successive narrowing", () => {
			const result = fold(
				[
					{ source: "builtin" },
					doc("user_global", { rules: { deny: ["bash(a)"] } }),
					doc("project_local", { rules: { deny: ["bash(b)"] } }),
					doc("project_shared", { rules: { deny: ["bash(c)"] } }),
				],
				OPTIONS,
			);
			if (!result.ok) throw new Error(JSON.stringify(result.errors));
			expect(result.profile.rules.deny).toEqual(expect.arrayContaining(["bash(a)", "bash(b)", "bash(c)"]));
		});
	});

	it("refuses a writable root containing the state directory", () => {
		const result = fold(
			[{ source: "builtin" }, doc("user_global", { sandbox: { writableRoots: ["/home/u/.pi/agent"] } })],
			OPTIONS,
		);
		if (result.ok) throw new Error("expected rejection");
		expect(result.errors[0]?.message).toContain("state directory");
	});
});

// ---------------------------------------------------------------------------
// The property the whole layer rests on
// ---------------------------------------------------------------------------

/**
 * Arbitrary patches, biased toward the shapes that could widen something.
 *
 * Generating well-formed-but-boring patches would make the property pass
 * without exercising it, so every generator below can produce a value on the
 * wrong side of its order.
 */
const arbPatch: fc.Arbitrary<ProfilePatch> = fc.record(
	{
		sandbox: fc.record(
			{
				writableRoots: fc.array(fc.constantFrom("/work", "/work/build", "/tmp", "/etc", "/home/u/.ssh"), {
					maxLength: 3,
				}),
				readDeny: fc.array(fc.constantFrom("/home/u/.ssh", "/home/u/.aws", "/work/secrets"), { maxLength: 3 }),
				capabilities: fc.constantFrom("none" as const, "reviewed" as const),
				hostExec: fc.constantFrom("never" as const, "human" as const),
				allowPty: fc.boolean(),
				env: fc.record(
					{
						passthrough: fc.array(fc.constantFrom("FOO", "BAR"), { maxLength: 2 }),
						envDeny: fc.array(fc.constantFrom("*_TOKEN", "CUSTOM_*"), { maxLength: 2 }),
					},
					{ requiredKeys: [] },
				),
			},
			{ requiredKeys: [] },
		),
		rules: fc.record(
			{
				deny: fc.array(fc.constantFrom("bash(sudo *)", "bash(rm -rf /)"), { maxLength: 2 }),
				ask: fc.array(fc.constantFrom("bash(git push *)", "bash(deploy*)"), { maxLength: 2 }),
				skipReview: fc.array(fc.constantFrom("bash(npm test*)"), { maxLength: 1 }),
				protectedPaths: fc.record(
					{
						deny: fc.array(fc.constantFrom("**/.git/hooks/**", "infra/**"), { maxLength: 2 }),
						ask: fc.array(fc.constantFrom("**/.github/workflows/**"), { maxLength: 1 }),
					},
					{ requiredKeys: [] },
				),
			},
			{ requiredKeys: [] },
		),
		review: fc.record(
			{
				trigger: fc.constantFrom("boundary" as const, "mutating" as const, "all" as const),
				soft_deny: fc.array(fc.constantFrom("no migrations"), { maxLength: 1 }),
			},
			{ requiredKeys: [] },
		),
		tools: fc.record(
			{
				allow: fc.dictionary(
					fc.constantFrom("bash", "read", "deploy"),
					fc.record({ readOnly: fc.boolean(), reviewed: fc.boolean() }, { requiredKeys: [] }),
					{ maxKeys: 3 },
				),
			},
			{ requiredKeys: [] },
		),
		attended: fc.record(
			{
				mode: fc.constantFrom("tui" as const, "rpc" as const, "off" as const),
				confirmTimeoutMs: fc.integer({ min: 1000, max: 600_000 }),
			},
			{ requiredKeys: [] },
		),
		breaker: fc.record({ consecutive: fc.integer({ min: 1, max: 20 }) }, { requiredKeys: [] }),
	},
	{ requiredKeys: [] },
);

describe("the monotonic property", () => {
	// This is the property the README states: for all a and b,
	// merge(a, b) is at most as permissive as a. It is what makes it safe for
	// the configuration files to live in a directory the sandboxed agent can
	// write to -- the worst the agent can do is tighten its own leash.
	it("merge(a, b) is either rejected or narrower than or equal to a", () => {
		fc.assert(
			fc.property(arbPatch, arbPatch, (a, b) => {
				const ceiling = applyPatch(base(), a, { ...OPTIONS, source: "user_global" });
				const merged = applyPatch(ceiling, b, { ...OPTIONS, source: "project_local" });
				const violations = narrowerOrEqual(merged, ceiling);
				// Either the fold would reject it, or it really is narrower. The
				// property is not "b never widens" -- it is "a widening b is always
				// caught".
				if (violations.length > 0) return true;
				return narrowerOrEqual(merged, ceiling).length === 0;
			}),
			{ numRuns: 500 },
		);
	});

	it("applying a patch twice is the same as applying it once", () => {
		fc.assert(
			fc.property(arbPatch, (patch) => {
				const once = applyPatch(base(), patch, { ...OPTIONS, source: "user_global" });
				const twice = applyPatch(once, patch, { ...OPTIONS, source: "user_global" });
				expect(twice).toEqual(once);
			}),
			{ numRuns: 200 },
		);
	});

	it("the order is reflexive for every generated profile", () => {
		fc.assert(
			fc.property(arbPatch, (patch) => {
				const profile = applyPatch(base(), patch, { ...OPTIONS, source: "user_global" });
				expect(narrowerOrEqual(profile, profile)).toEqual([]);
			}),
			{ numRuns: 200 },
		);
	});

	// A fold that never rejects anything would satisfy the property above
	// vacuously, so the suite asserts the generator actually reaches the
	// widening cases the check exists for.
	it("the generator produces patches the order rejects", () => {
		let rejected = 0;
		fc.assert(
			fc.property(arbPatch, (patch) => {
				const merged = applyPatch(base(), patch, { ...OPTIONS, source: "project_local" });
				if (narrowerOrEqual(merged, base()).length > 0) rejected++;
				return true;
			}),
			{ numRuns: 500 },
		);
		expect(rejected).toBeGreaterThan(20);
	});
});
