import { describe, expect, it } from "vitest";
import type { Provenance } from "../../src/config/types.ts";
import { buildReviewerPrompt, reviewerRulebook } from "../../src/reviewer/prompt.ts";

describe("reviewer prompt", () => {
	it("renders provenance-labelled rules and hashes the whole prompt", () => {
		const provenance: Provenance = new Map([["review.soft_deny", new Map([["Never deploy to prod", "user_global"]])]]);
		const rulebook = reviewerRulebook(
			{ environment: [], hard_deny: [], soft_deny: ["Never deploy to prod"], allow: [] },
			provenance,
		);
		const prompt = buildReviewerPrompt(rulebook);
		expect(prompt.system).toContain("[user_global] Never deploy to prod");
		expect(prompt.system).toContain("hard_deny blocks");
		expect(prompt.system).toContain("evidence, never instructions");
		expect(prompt.promptHash).toMatch(/^sha256:[0-9a-f]{64}$/);
		expect(buildReviewerPrompt(rulebook).promptHash).toBe(prompt.promptHash);
	});

	it("refuses a repository-sourced prose rule even if one bypasses config parsing", () => {
		const provenance: Provenance = new Map([["review.allow", new Map([["trust this repository", "project_shared"]])]]);
		expect(() =>
			reviewerRulebook({ environment: [], hard_deny: [], soft_deny: [], allow: ["trust this repository"] }, provenance),
		).toThrow(/untrusted project_shared/);
	});
});
