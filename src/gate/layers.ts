import type { GateOutcome } from "./gate.ts";

/**
 * Which layer settled a gate decision (#18), so a session can say how often a
 * person was needed and whether a reviewer reduced that.
 *
 * - L1: the deterministic rules settled it (allow, deny, skipReview), or ran it
 *   with L2 as the boundary (`rules.onUncertain: "sandbox"`).
 * - L3: the reviewer settled it.
 * - L4: it went to a person, or to nobody (`ask-denied` with attended off).
 *
 * A breaker-open refusal and a gate error are not decisions about the action,
 * so they are counted apart and not in any layer.
 */
export type DecisionLayer = "L1" | "L3" | "L4";

export function decisionLayer(outcome: GateOutcome): DecisionLayer | undefined {
	switch (outcome) {
		case "allow":
		case "deny":
		case "skip-review":
		case "sandboxed-uncertain":
		case "batch-withheld":
			return "L1";
		case "review-allow":
		case "review-deny":
			return "L3";
		case "ask-approved":
		case "ask-denied":
			return "L4";
		case "breaker-open":
		case "error":
			return undefined;
	}
}

export interface LayerTally {
	L1: number;
	L3: number;
	L4: number;
	/** Of L4: asks nobody approved. With attended off, every L4 decision. */
	askDenied: number;
	/** Of L1: unreadable commands run with the sandbox as the only boundary. */
	sandboxedUncertain: number;
	/** Not in any layer: breaker-open refusals and gate errors. */
	other: number;
}

export function emptyTally(): LayerTally {
	return { L1: 0, L3: 0, L4: 0, askDenied: 0, sandboxedUncertain: 0, other: 0 };
}

export function recordLayer(tally: LayerTally, outcome: GateOutcome): void {
	const layer = decisionLayer(outcome);
	if (layer) tally[layer] += 1;
	else tally.other += 1;
	if (outcome === "ask-denied") tally.askDenied += 1;
	if (outcome === "sandboxed-uncertain") tally.sandboxedUncertain += 1;
}

/** One line for `/enclave` and the audit summary: counts and shares of decided actions. */
export function describeTally(tally: LayerTally): string {
	const decided = tally.L1 + tally.L3 + tally.L4;
	if (decided === 0 && tally.other === 0) return "no gate decisions yet";
	const share = (count: number) => (decided === 0 ? "0%" : `${Math.round((count / decided) * 100)}%`);
	const parts = [
		`L1 ${tally.L1} (${share(tally.L1)})`,
		`L3 ${tally.L3} (${share(tally.L3)})`,
		`L4 ${tally.L4} (${share(tally.L4)})`,
		`ask-denied ${tally.askDenied}`,
	];
	if (tally.sandboxedUncertain > 0) parts.push(`sandboxed-uncertain ${tally.sandboxedUncertain}`);
	if (tally.other > 0) parts.push(`not decided ${tally.other}`);
	return parts.join(", ");
}
