import { describe, expect, it } from "vitest";
import { destroyWorld, makeWorld, POLICY_SCENARIOS, type PolicyResult } from "./scenarios.ts";

/**
 * Every row must pass, and every control must fail.
 *
 * The second half is the part that makes the first half mean anything. Phase 1
 * learned this the expensive way: three rows passed against a backend that
 * enforced nothing, and only the control caught them. A policy row can fail the
 * same way -- an assertion that would hold whether or not the mechanism exists
 * is one that proves nothing about the mechanism.
 */
async function run(scenario: (typeof POLICY_SCENARIOS)[number], which: "run" | "control"): Promise<PolicyResult> {
	const world = makeWorld();
	try {
		return await scenario[which](world);
	} catch (error) {
		// A control that throws has still failed, which is the outcome it needs.
		// A row that throws has not passed.
		return { ok: false, detail: `threw: ${(error as Error).message}` };
	} finally {
		destroyWorld(world);
	}
}

describe("the Phase-2 platform matrix", () => {
	for (const scenario of POLICY_SCENARIOS) {
		it(`${scenario.id}: ${scenario.title}`, async () => {
			const result = await run(scenario, "run");
			expect(result.ok, `${scenario.id} failed: ${result.detail}`).toBe(true);
		});
	}
});

describe("the controls", () => {
	for (const scenario of POLICY_SCENARIOS) {
		it(`${scenario.id} fails when ${scenario.controlNote}`, async () => {
			const result = await run(scenario, "control");
			expect(
				result.ok,
				`${scenario.id}'s control PASSED, so the row does not depend on the mechanism it names. ` +
					`Control: ${scenario.controlNote}. Detail: ${result.detail}`,
			).toBe(false);
		});
	}
});

describe("the suite itself", () => {
	it("every scenario names the README row it proves", () => {
		for (const scenario of POLICY_SCENARIOS) {
			expect(scenario.matrixRow.length, `${scenario.id} has no matrix row`).toBeGreaterThan(0);
		}
	});

	// An unexplained control is indistinguishable from a control someone wrote
	// to make the meta-test green.
	it("every control says what it switches off", () => {
		for (const scenario of POLICY_SCENARIOS) {
			expect(scenario.controlNote.length, `${scenario.id} has no control note`).toBeGreaterThan(20);
		}
	});

	it("covers P1 through P11", () => {
		expect(POLICY_SCENARIOS.map((scenario) => scenario.id)).toEqual([
			"P1",
			"P2",
			"P3",
			"P4",
			"P5",
			"P6",
			"P7",
			"P8",
			"P9",
			"P10",
			"P11",
		]);
	});
});
