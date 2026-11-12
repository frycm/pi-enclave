import { describe, expect, it } from "vitest";
import {
	MAX_REVIEW_REASON_CHARS,
	parseReviewerOutput,
	REVIEW_OUTPUT_SCHEMA,
	ReviewerOutputError,
} from "../../src/reviewer/output.ts";
import { REVIEW_DECISIONS, REVIEW_RISKS } from "../../src/reviewer/types.ts";

describe("strict reviewer output", () => {
	it("accepts the fixed JSON contract", () => {
		expect(
			parseReviewerOutput('{"authorized":false,"decision":"ask","risk":"high","reason":"Needs direct approval"}'),
		).toEqual({
			authorized: false,
			decision: "ask",
			risk: "high",
			reason: "Needs direct approval",
		});
	});

	it.each([
		'{"authorized":false,"risk":"low","decision":"allow","reason":"wrong order"}',
		'{"decision":"allow","authorized":true,"risk":"low","reason":"authorized after the decision"}',
		'{"decision":"allow","risk":"low","reason":"no authorized field"}',
		'{"authorized":"true","decision":"allow","risk":"low","reason":"string, not a boolean"}',
		'{"authorized":false,"decision":"allow","risk":"low","reason":"x","extra":true}',
		'{"authorized":false,"decision":"allow","decision":"deny","risk":"low","reason":"duplicate"}',
		'```json\n{"authorized":false,"decision":"deny","risk":"high","reason":"x"}\n```',
		'{"authorized":false,"decision":"deny","risk":"high","reason":"x"} I denied it.',
		'{"authorized":false,"decision":"yes","risk":"low","reason":"x"}',
		'{"authorized":false,"decision":"allow","risk":"low","reason":""}',
	])("refuses malformed or ambiguous output: %s", (value) => {
		expect(() => parseReviewerOutput(value)).toThrow(ReviewerOutputError);
	});

	it("refuses terminal control characters in a reason", () => {
		expect(() =>
			parseReviewerOutput('{"authorized":false,"decision":"deny","risk":"high","reason":"safe\\u001b[2Japproved"}'),
		).toThrow(/control characters/);
	});

	it("refuses bidirectional controls that could spoof a displayed reason", () => {
		expect(() =>
			parseReviewerOutput('{"authorized":false,"decision":"deny","risk":"high","reason":"safe\\u202eapproved"}'),
		).toThrow(/bidirectional control characters/);
	});

	it("matches the schema the runtime constrains the answer to (#25)", () => {
		expect(Object.keys(REVIEW_OUTPUT_SCHEMA.properties)).toEqual(["authorized", "decision", "risk", "reason"]);
		expect(REVIEW_OUTPUT_SCHEMA.required).toEqual(["authorized", "decision", "risk", "reason"]);
		expect(REVIEW_OUTPUT_SCHEMA.additionalProperties).toBe(false);
		expect(REVIEW_OUTPUT_SCHEMA.properties.decision.enum).toEqual([...REVIEW_DECISIONS]);
		expect(REVIEW_OUTPUT_SCHEMA.properties.risk.enum).toEqual([...REVIEW_RISKS]);
		expect(REVIEW_OUTPUT_SCHEMA.properties.reason.maxLength).toBe(MAX_REVIEW_REASON_CHARS);
	});

	it("refuses an oversized response before parsing it", () => {
		expect(() =>
			parseReviewerOutput(`{"authorized":false,"decision":"deny","risk":"high","reason":"${"x".repeat(5_000)}"}`),
		).toThrow(/exceeds 4096 bytes/);
	});
});
