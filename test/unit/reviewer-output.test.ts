import { describe, expect, it } from "vitest";
import { parseReviewerOutput, ReviewerOutputError } from "../../src/reviewer/output.ts";

describe("strict reviewer output", () => {
	it("accepts the fixed JSON contract", () => {
		expect(parseReviewerOutput('{"decision":"ask","risk":"high","reason":"Needs direct approval"}')).toEqual({
			decision: "ask",
			risk: "high",
			reason: "Needs direct approval",
		});
	});

	it.each([
		'{"risk":"low","decision":"allow","reason":"wrong order"}',
		'{"decision":"allow","risk":"low","reason":"x","extra":true}',
		'{"decision":"allow","decision":"deny","risk":"low","reason":"duplicate"}',
		'```json\n{"decision":"deny","risk":"high","reason":"x"}\n```',
		'{"decision":"yes","risk":"low","reason":"x"}',
		'{"decision":"allow","risk":"low","reason":""}',
	])("refuses malformed or ambiguous output: %s", (value) => {
		expect(() => parseReviewerOutput(value)).toThrow(ReviewerOutputError);
	});

	it("refuses terminal control characters in a reason", () => {
		expect(() => parseReviewerOutput('{"decision":"deny","risk":"high","reason":"safe\\u001b[2Japproved"}')).toThrow(
			/control characters/,
		);
	});

	it("refuses bidirectional controls that could spoof a displayed reason", () => {
		expect(() => parseReviewerOutput('{"decision":"deny","risk":"high","reason":"safe\\u202eapproved"}')).toThrow(
			/bidirectional control characters/,
		);
	});

	it("refuses an oversized response before parsing it", () => {
		expect(() => parseReviewerOutput(`{"decision":"deny","risk":"high","reason":"${"x".repeat(5_000)}"}`)).toThrow(
			/exceeds 4096 bytes/,
		);
	});
});
