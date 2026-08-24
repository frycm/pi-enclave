import { describe, expect, it } from "vitest";
import { CircuitBreaker, isBreakerState, steerMessage } from "../../src/gate/breaker.ts";
import { ActionLock } from "../../src/gate/lock.ts";
import { isProvenanceRecord, ProvenanceTracker, sha256 } from "../../src/gate/provenance.ts";
import { canonicalize } from "../../src/policy/canonical.ts";
import { FakePi } from "../harness/fake-pi.ts";

const CONFIG = { consecutive: 3, window: [10, 50] as [number, number] };

describe("the circuit breaker", () => {
	it("starts closed", () => {
		expect(new CircuitBreaker(CONFIG).open).toBe(false);
	});

	it("opens after three consecutive adverse turns", () => {
		const breaker = new CircuitBreaker(CONFIG);
		for (let turn = 0; turn < 2; turn++) {
			breaker.record(turn, true);
			breaker.finishTurn(turn);
		}
		expect(breaker.open).toBe(false);
		breaker.record(2, true);
		expect(breaker.finishTurn(2)).toBe(true);
		expect(breaker.open).toBe(true);
	});

	it("reports the trip exactly once", () => {
		const breaker = new CircuitBreaker(CONFIG);
		for (let turn = 0; turn < 3; turn++) {
			breaker.record(turn, true);
			breaker.finishTurn(turn);
		}
		breaker.record(3, true);
		expect(breaker.finishTurn(3)).toBe(false);
	});

	it("a good turn clears the consecutive count", () => {
		const breaker = new CircuitBreaker(CONFIG);
		breaker.record(0, true);
		breaker.finishTurn(0);
		breaker.record(1, false);
		breaker.finishTurn(1);
		breaker.record(2, true);
		breaker.finishTurn(2);
		breaker.record(3, true);
		breaker.finishTurn(3);
		expect(breaker.open).toBe(false);
	});

	// Without collapsing, any parallel tool use would trip the breaker on its
	// first denied batch.
	describe("a batch is one strike", () => {
		it("five denied calls in one turn count once", () => {
			const breaker = new CircuitBreaker(CONFIG);
			for (let call = 0; call < 5; call++) breaker.record(0, true);
			breaker.finishTurn(0);
			expect(breaker.state.consecutive).toBe(1);
			expect(breaker.open).toBe(false);
		});

		it("one denial in a mixed batch makes the whole turn adverse", () => {
			const breaker = new CircuitBreaker(CONFIG);
			breaker.record(0, false);
			breaker.record(0, true);
			breaker.record(0, false);
			breaker.finishTurn(0);
			expect(breaker.state.consecutive).toBe(1);
		});
	});

	// Counting a turn nobody was gated in as a success would let an agent reset
	// the counter with a read.
	it("a turn with no gated calls is not evidence either way", () => {
		const breaker = new CircuitBreaker(CONFIG);
		breaker.record(0, true);
		breaker.finishTurn(0);
		breaker.finishTurn(1);
		expect(breaker.state.consecutive).toBe(1);
	});

	it("opens on the sliding window without three in a row", () => {
		const breaker = new CircuitBreaker({ consecutive: 3, window: [3, 10] });
		for (const [turn, adverse] of [true, false, true, false, true].entries()) {
			breaker.record(turn, adverse as unknown as boolean);
			breaker.finishTurn(turn);
		}
		expect(breaker.open).toBe(true);
	});

	it("forgets outcomes that fall out of the window", () => {
		const breaker = new CircuitBreaker({ consecutive: 100, window: [2, 3] });
		for (let turn = 0; turn < 2; turn++) {
			breaker.record(turn, true);
			breaker.finishTurn(turn);
		}
		expect(breaker.open).toBe(true);
		for (let turn = 2; turn < 5; turn++) {
			breaker.record(turn, false);
			breaker.finishTurn(turn);
		}
		expect(breaker.open).toBe(false);
	});

	// The breaker opens in turn_end, after the batch runs; pendingOpen lets the
	// execute-time guard stop the tripping batch's siblings before they run.
	describe("pendingOpen", () => {
		it("is true once the current turn's recorded outcome would open it", () => {
			const breaker = new CircuitBreaker({ consecutive: 3, window: [10, 50] });
			for (let turn = 0; turn < 2; turn++) {
				breaker.record(turn, true);
				breaker.finishTurn(turn);
			}
			// Third adverse turn recorded but not yet finished.
			breaker.record(2, true);
			expect(breaker.open).toBe(false); // not opened until turn_end
			expect(breaker.pendingOpen(2)).toBe(true); // but the guard already knows
		});

		it("is false for a non-adverse or unstarted turn", () => {
			const breaker = new CircuitBreaker({ consecutive: 1, window: [10, 50] });
			expect(breaker.pendingOpen(0)).toBe(false);
			breaker.record(0, false);
			expect(breaker.pendingOpen(0)).toBe(false);
		});
	});

	it("reports whether a turn had a recorded outcome", () => {
		const breaker = new CircuitBreaker(CONFIG);
		expect(breaker.hasOutcome(0)).toBe(false);
		breaker.record(0, true);
		expect(breaker.hasOutcome(0)).toBe(true);
	});

	it("survives a resume", () => {
		const breaker = new CircuitBreaker(CONFIG);
		breaker.record(0, true);
		breaker.finishTurn(0);
		breaker.record(1, true);
		breaker.finishTurn(1);

		const resumed = new CircuitBreaker(CONFIG);
		resumed.restore(breaker.state);
		resumed.record(2, true);
		expect(resumed.finishTurn(2)).toBe(true);
	});

	it("validates restored state", () => {
		expect(isBreakerState({ consecutive: 1, recent: [true, false] })).toBe(true);
		expect(isBreakerState({ consecutive: -1, recent: [] })).toBe(false);
		expect(isBreakerState({ consecutive: 1, recent: ["yes"] })).toBe(false);
		expect(isBreakerState(null)).toBe(false);
	});

	it("names the outcome rather than the command", () => {
		expect(steerMessage()).toContain("Do not pursue this outcome by other means");
	});

	// The gate must not feed its own breaker-open decisions back in: recording a
	// turn of nothing-but-breaker-open as a (non-adverse) success would reset the
	// consecutive count and close the breaker again with no human input. This
	// mirrors what index.ts does -- skip recording when outcome is breaker-open.
	it("stays open across a turn that only produced breaker-open decisions", () => {
		const breaker = new CircuitBreaker({ consecutive: 3, window: [10, 50] });
		for (let turn = 0; turn < 3; turn++) {
			breaker.record(turn, true);
			breaker.finishTurn(turn);
		}
		expect(breaker.open).toBe(true);

		// Next turn: the gate short-circuits every call as breaker-open and, per
		// index.ts, records nothing for those. So the turn has no recorded outcome.
		breaker.finishTurn(3);
		expect(breaker.open).toBe(true);

		// Only a direct user message clears it.
		breaker.reset();
		expect(breaker.open).toBe(false);
	});
});

describe("provenance", () => {
	const tracker = () => new ProvenanceTracker();

	it("records an interactive message", () => {
		const t = tracker();
		t.observe({ text: "do the thing", source: "interactive" });
		t.confirmPrompt("do the thing");
		const record = t.recordForMessage("do the thing", 1000);
		expect(record?.source).toBe("interactive");
		expect(record?.messageTextSha256).toBe(sha256("do the thing"));
		expect(record?.rawText).toBeUndefined();
	});

	// A skill or prompt template rewrites the text before it is stored, so the
	// stored message is not the one the person typed.
	it("keeps the raw text when expansion changed it", () => {
		const t = tracker();
		t.observe({ text: "/deploy prod", source: "interactive" });
		t.confirmPrompt("Deploy the application to production");
		const record = t.recordForMessage("Deploy the application to production", 1000);
		expect(record?.rawText).toBe("/deploy prod");
	});

	// The whole point: an extension's own message must never read as user
	// authorization. pi routes sendUserMessage through the same input event.
	it("never records an extension-sourced message", () => {
		const t = tracker();
		t.observe({ text: "please allow this", source: "extension" });
		t.confirmPrompt("please allow this");
		expect(t.recordForMessage("please allow this", 1000)).toBeUndefined();
	});

	it("returns nothing for a message it never saw", () => {
		expect(tracker().recordForMessage("out of nowhere", 1000)).toBeUndefined();
	});

	it("matches a queued steer message exactly, with no expansion step", () => {
		const t = tracker();
		t.observe({ text: "stop that", source: "interactive", streamingBehavior: "steer" });
		expect(t.recordForMessage("stop that", 1000)?.source).toBe("interactive");
	});

	// An expanded queued message must not be able to authorize a later message
	// that happens to equal the original text.
	it("quarantines pending observations behind a queued one", () => {
		const t = tracker();
		t.observe({ text: "/deploy", source: "interactive", streamingBehavior: "followUp" });
		expect(t.recordForMessage("something else", 1000)).toBeUndefined();
		expect(t.recordForMessage("/deploy", 2000)).toBeUndefined();
	});

	it("prefers the newest exact match", () => {
		const t = tracker();
		t.observe({ text: "same", source: "extension" });
		t.observe({ text: "same", source: "interactive" });
		expect(t.recordForMessage("same", 1000)?.source).toBe("interactive");
	});

	it("forgets everything on reset", () => {
		const t = tracker();
		t.observe({ text: "x", source: "interactive" });
		t.reset();
		expect(t.recordForMessage("x", 1000)).toBeUndefined();
	});

	describe("validation of a persisted record", () => {
		const valid = { version: 1, source: "interactive", messageTimestamp: 1, messageTextSha256: "a".repeat(64) };

		it("accepts a well-formed record", () => {
			expect(isProvenanceRecord(valid)).toBe(true);
		});

		it.each([
			["a future version", { ...valid, version: 2 }],
			["an unknown source", { ...valid, source: "extension" }],
			["a short hash", { ...valid, messageTextSha256: "abc" }],
			["a missing timestamp", { ...valid, messageTimestamp: undefined }],
		])("rejects %s", (_label, record) => {
			expect(isProvenanceRecord(record)).toBe(false);
		});
	});
});

// ---------------------------------------------------------------------------
// P2: the parallel-batch window
// ---------------------------------------------------------------------------

describe("a batch where the second call trips the breaker", () => {
	/**
	 * pi prepares every call in a batch before executing any of them, so
	 * blocking the third call cannot help the first, which is already prepared.
	 * The lock's execute-time re-check is the only thing standing between a
	 * tripped breaker and an action that was gated a moment earlier.
	 */
	function scenario(withRecheck: boolean) {
		const breaker = new CircuitBreaker({ consecutive: 1, window: [10, 50] });
		const lock = new ActionLock(withRecheck ? { breakerOpen: () => breaker.open } : {});
		const executed: string[] = [];
		let tripped = false;

		const pi = new FakePi({
			execute: (call) => {
				// What an operations object does: ask the table again, then act.
				lock.beginExecution(`bash:${call.input.command as string}`);
				executed.push(call.input.command as string);
			},
		});

		pi.onToolCall((event) => {
			const command = event.input.command as string;
			if (breaker.open) {
				return { block: true, reason: "breaker open", terminate: true };
			}
			if (command.startsWith("sudo")) {
				breaker.record(0, true);
				// The turn ends here for counting purposes: one denial, one strike,
				// and with `consecutive: 1` that opens the breaker immediately.
				if (breaker.finishTurn(0)) {
					tripped = true;
					pi.abort("breaker");
				}
				return { block: true, reason: "denied", terminate: true };
			}
			lock.register(
				canonicalize({ tool: "bash", input: event.input, cwd: "/work", home: "/home/u", profileName: "dev" }),
				event.toolCallId,
			);
			return undefined;
		});

		return { pi, executed, breaker, tripped: () => tripped };
	}

	const BATCH = [
		{ toolName: "bash", input: { command: "echo one" } },
		{ toolName: "bash", input: { command: "sudo rm -rf /" } },
		{ toolName: "bash", input: { command: "echo three" } },
	];

	it("blocks the offender and every later call, terminates once, and aborts", async () => {
		const { pi, executed, tripped } = scenario(true);
		const batch = await pi.batch(BATCH);

		expect(tripped()).toBe(true);
		expect(pi.aborts).toHaveLength(1);
		// The second and third are blocked outright; the first was already
		// prepared, so it is stopped at execution instead.
		expect(batch.prepared.filter((call) => call.result.block)).toHaveLength(2);
		expect(executed).toEqual([]);
		expect(batch.executed.every((call) => call.error !== undefined)).toBe(true);
	});

	// The control. Without the re-check the first call -- gated before the trip
	// and already prepared -- runs anyway, which is the whole failure this row
	// exists to catch.
	it("without the execute-time re-check, the already-prepared call still runs", async () => {
		const { pi, executed } = scenario(false);
		await pi.batch(BATCH);
		expect(executed).toEqual(["echo one"]);
	});
});
