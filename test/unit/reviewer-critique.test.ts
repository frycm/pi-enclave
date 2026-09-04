import { describe, expect, it } from "vitest";
import { defaultProfile } from "../../src/config/defaults.ts";
import type { Provenance } from "../../src/config/types.ts";
import { critiqueRulebook, deterministicCritique, formatCritique } from "../../src/reviewer/critique.ts";

const profile = () => defaultProfile({ cwd: "/work", home: "/home/u", tmp: "/tmp", agentDir: "/home/u/.pi/agent" });

function provenance(entries: Array<[string, string]>): Provenance {
	const result: Provenance = new Map();
	for (const [list, rule] of entries) result.set(list, new Map([[rule, "user_global"]]));
	return result;
}

describe("rulebook critique", () => {
	it("finds deterministic contradictions and broad review bypasses", () => {
		const configured = profile();
		configured.review.hard_deny = ["never deploy production"];
		configured.review.allow = ["never deploy production"];
		configured.rules.skipReview = ["bash(git *)"];
		const source = provenance([
			["review.hard_deny", "never deploy production"],
			["review.allow", "never deploy production"],
			["rules.skipReview", "bash(git *)"],
		]);

		expect(deterministicCritique(configured, source)).toEqual(
			expect.arrayContaining([
				expect.objectContaining({ kind: "contradiction", list: "review.allow" }),
				expect.objectContaining({ kind: "broad-skip", list: "rules.skipReview" }),
			]),
		);
	});

	it("uses isolated model output only for exact supplied rules", async () => {
		const configured = profile();
		configured.review.soft_deny = ["avoid generated files"];
		const source = provenance([["review.soft_deny", "avoid generated files"]]);
		const result = await critiqueRulebook({
			profile: configured,
			provenance: source,
			timeoutMs: 1_000,
			primary: {
				name: "fake/reviewer",
				complete: async () =>
					'{"findings":[{"list":"review.soft_deny","rule":"avoid generated files","kind":"ambiguous","reason":"generated files is not scoped"}]}',
			},
		});
		expect(result.reviewer).toBe("fake/reviewer");
		expect(formatCritique(result)).toContain("generated files is not scoped");
	});

	it("rejects invented rules from the model", async () => {
		const configured = profile();
		configured.review.soft_deny = ["avoid generated files"];
		const result = await critiqueRulebook({
			profile: configured,
			provenance: provenance([["review.soft_deny", "avoid generated files"]]),
			timeoutMs: 1_000,
			primary: {
				name: "fake/reviewer",
				complete: async () =>
					'{"findings":[{"list":"review.soft_deny","rule":"invented","kind":"ambiguous","reason":"bad"}]}',
			},
		});
		expect(result.findings).toEqual([]);
		expect(result.note).toContain("names a rule that was not supplied");
	});

	it("returns deterministic findings when a critic ignores abort", async () => {
		const configured = profile();
		configured.review.soft_deny = ["avoid generated files"];
		const result = await critiqueRulebook({
			profile: configured,
			provenance: provenance([["review.soft_deny", "avoid generated files"]]),
			timeoutMs: 5,
			primary: {
				name: "hanging/reviewer",
				complete: async () => new Promise<string>(() => {}),
			},
		});
		expect(result.note).toContain("reviewer timeout");
	});
});
