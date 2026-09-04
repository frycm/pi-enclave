/**
 * The denial circuit breaker.
 *
 * Guardian's counters and guardian's reasoning: an agent that has been refused
 * three times in a row is not converging on an approach, it is searching for a
 * way round, and the useful response is to stop the turn rather than to keep
 * saying no. Three consecutive adverse outcomes in a turn, or ten in the last
 * fifty batches.
 *
 * **A batch is a turn.** Guardian walks the session branch backwards to find
 * the assistant message a tool call belongs to, because that is what its pi
 * version gave it. pi 0.84.2 has `turn_start` / `turn_end` carrying a
 * `turnIndex` and the turn's tool results (`types.ts:727-740`), so the batch is
 * already delimited and the walk is unnecessary. One turn collapses to one
 * outcome, so a batch of five denied calls is one strike rather than five --
 * without that, any parallel tool use would trip the breaker immediately.
 *
 * **A trip is three things, not one.** `block` with `terminate` on this and
 * every later call in the batch; `ctx.abort()`, because pi only honours
 * `terminate` when *every* finalized result in the batch carries it and the
 * calls already prepared will not be; and a message telling the agent the
 * *outcome* is off limits rather than the command. That last part is why the
 * breaker is worth having at all: a refusal the agent reads as "not like that"
 * produces another attempt.
 */

export interface BreakerConfig {
	/** Adverse outcomes in a row before the breaker opens. */
	consecutive: number;
	/** `[maxAdverse, windowSize]` over recent turns. */
	window: [number, number];
}

/** What the breaker persists, so a resume does not start with a clean slate. */
export interface BreakerState {
	consecutive: number;
	recent: boolean[];
}

export class CircuitBreaker {
	private consecutive = 0;
	private recent: boolean[] = [];
	/** Outcomes seen so far in each open turn, keyed by turn index. */
	private readonly turns = new Map<number, boolean>();

	constructor(private readonly config: BreakerConfig) {}

	get open(): boolean {
		return this.consecutive >= this.config.consecutive || this.recent.filter(Boolean).length >= this.config.window[0];
	}

	get state(): BreakerState {
		return { consecutive: this.consecutive, recent: [...this.recent] };
	}

	/** True if the turn has any recorded outcome yet. */
	hasOutcome(turnIndex: number): boolean {
		return this.turns.has(turnIndex);
	}

	/**
	 * Would the breaker be open once the current turn's accumulated outcome is
	 * folded in? Computed without mutating.
	 *
	 * The breaker opens in `turn_end`, after a batch has executed, so `open`
	 * alone is still false while the tripping batch's siblings run. Because pi
	 * prepares every call in a batch before executing any of them, the whole
	 * batch's collapsed outcome is already recorded by the time the first sibling
	 * executes -- so the execute-time guard checks this, and the batch that trips
	 * the breaker does not get to run its remaining calls.
	 */
	pendingOpen(turnIndex: number): boolean {
		if (this.open) return true;
		const adverse = this.turns.get(turnIndex);
		if (adverse === undefined) return false;
		return this.projectedOpen(adverse);
	}

	/**
	 * Would one runtime-only adverse outcome in this turn open the breaker?
	 *
	 * Non-owned tools have no execute wrapper where pendingOpen can be checked.
	 * The gate uses this projection to withhold a later non-owned batch sibling
	 * when an earlier owned call could be the runtime event that opens it.
	 */
	wouldOpenOnAdverse(): boolean {
		if (this.open) return true;
		return this.projectedOpen(true);
	}

	private projectedOpen(adverse: boolean): boolean {
		const consecutive = adverse ? this.consecutive + 1 : 0;
		// Project the same bounded window finishTurn() will commit. Counting before
		// evicting the oldest item can report a trip that disappears at turn_end.
		const projectedRecent = [...this.recent, adverse].slice(-this.config.window[1]);
		const recentAdverse = projectedRecent.filter(Boolean).length;
		return consecutive >= this.config.consecutive || recentAdverse >= this.config.window[0];
	}

	/**
	 * Record one decision against its turn.
	 *
	 * Outcomes accumulate rather than counting: within a turn, adverse is
	 * sticky, and the turn contributes exactly one strike when it ends.
	 */
	record(turnIndex: number, adverse: boolean): void {
		this.turns.set(turnIndex, (this.turns.get(turnIndex) ?? false) || adverse);
	}

	/**
	 * Close a turn and fold its collapsed outcome into the counters.
	 *
	 * Returns true when this is the moment the breaker opened, so the caller can
	 * abort and steer exactly once rather than on every subsequent call.
	 */
	finishTurn(turnIndex: number): boolean {
		const adverse = this.turns.get(turnIndex);
		this.turns.delete(turnIndex);
		// A turn in which nothing was gated is not evidence either way. Counting
		// it as a success would let an agent reset the counter with a read.
		if (adverse === undefined) return false;

		const wasOpen = this.open;
		this.consecutive = adverse ? this.consecutive + 1 : 0;
		this.recent.push(adverse);
		if (this.recent.length > this.config.window[1]) this.recent.shift();
		return !wasOpen && this.open;
	}

	/**
	 * A person said something, so the count starts again.
	 *
	 * Only for *direct* input. An extension calling `sendUserMessage` arrives at
	 * the same event with `source: "extension"`, and letting that reset the
	 * breaker would hand the reset to the process the breaker is there to stop.
	 */
	reset(): void {
		this.consecutive = 0;
		this.recent = [];
		this.turns.clear();
	}

	/** Restore from session entries on resume. */
	restore(state: BreakerState): void {
		this.consecutive = state.consecutive;
		this.recent = state.recent.slice(-this.config.window[1]);
	}
}

/**
 * Pi cannot re-check a third-party tool at execution time. Conservatively keep
 * one out of a prepared batch when an earlier owned call could trip the
 * breaker through a runtime-only denial before the third-party call executes.
 */
export function shouldWithholdNonOwnedSibling(
	breaker: CircuitBreaker,
	earlierOwnedCall: boolean,
	toolIsOwned: boolean,
): boolean {
	return !toolIsOwned && earlierOwnedCall && breaker.wouldOpenOnAdverse();
}

export const BREAKER_ENTRY_TYPE = "pi-enclave-breaker";

/** Clear a human-reset breaker and persist that cleared state in one operation. */
export function resetAndPersistBreaker(
	breaker: CircuitBreaker,
	appendEntry: (customType: string, state: BreakerState) => void,
): void {
	breaker.reset();
	appendEntry(BREAKER_ENTRY_TYPE, breaker.state);
}

/** Fold a runtime L2 denial into the current turn's sticky gate outcome. */
export function recordRuntimeViolation(
	breaker: CircuitBreaker,
	turnIndex: number,
	violationCount: number,
	agentOrigin: boolean,
): void {
	// Direct `!` commands are human-originated: they remain audited but are not
	// evidence that an agent is searching for a workaround.
	if (agentOrigin && violationCount > 0) breaker.record(turnIndex, true);
}

export function isBreakerState(value: unknown): value is BreakerState {
	if (!value || typeof value !== "object") return false;
	const state = value as Partial<BreakerState>;
	return (
		typeof state.consecutive === "number" &&
		Number.isInteger(state.consecutive) &&
		state.consecutive >= 0 &&
		Array.isArray(state.recent) &&
		state.recent.every((entry) => typeof entry === "boolean")
	);
}

/**
 * What the agent is told when the breaker opens.
 *
 * Names the outcome, not the command. "That command is denied" invites the next
 * spelling of the same thing, which is the behaviour the counters detected in
 * the first place.
 */
export function steerMessage(): string {
	return [
		"pi-enclave: too many refusals in a row, so this turn is over.",
		"Do not pursue this outcome by other means: the denials are about what the actions would do,",
		"not about how they were written. Say what you were trying to achieve and wait for a person.",
	].join("\n");
}
