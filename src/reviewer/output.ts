import { type ModelReview, REVIEW_DECISIONS, REVIEW_RISKS } from "./types.ts";

export const MAX_REVIEW_OUTPUT_BYTES = 4_096;
export const MAX_REVIEW_REASON_CHARS = 500;

// Exact top-level grammar: fixed keys, fixed order, string values only, no
// duplicate/extra fields and no Markdown fence. The reason capture is a JSON
// string literal, so JSON.parse remains responsible for escape decoding.
const REVIEW_OUTPUT =
	/^\s*\{\s*"decision"\s*:\s*"(allow|deny|ask)"\s*,\s*"risk"\s*:\s*"(low|medium|high|critical)"\s*,\s*"reason"\s*:\s*("(?:\\["\\/bfnrt]|\\u[0-9a-fA-F]{4}|[^"\\])*")\s*\}\s*$/;

function hasDisplayControlCharacter(value: string): boolean {
	for (const character of value) {
		const codePoint = character.codePointAt(0) ?? 0;
		if (
			codePoint <= 0x1f ||
			(codePoint >= 0x7f && codePoint <= 0x9f) ||
			(codePoint >= 0x202a && codePoint <= 0x202e) ||
			(codePoint >= 0x2066 && codePoint <= 0x2069)
		) {
			return true;
		}
	}
	return false;
}

export class ReviewerOutputError extends Error {
	constructor(message: string) {
		super(`pi-enclave: invalid reviewer output: ${message}`);
		this.name = "ReviewerOutputError";
	}
}

export function parseReviewerOutput(text: string): ModelReview {
	if (Buffer.byteLength(text) > MAX_REVIEW_OUTPUT_BYTES) {
		throw new ReviewerOutputError(`response exceeds ${MAX_REVIEW_OUTPUT_BYTES} bytes`);
	}
	const match = REVIEW_OUTPUT.exec(text);
	if (!match) {
		throw new ReviewerOutputError(
			'expected exactly {"decision":"allow|deny|ask","risk":"low|medium|high|critical","reason":"..."}',
		);
	}
	const [, decision, risk, reasonLiteral] = match;
	if (!decision || !REVIEW_DECISIONS.includes(decision as ModelReview["decision"])) {
		throw new ReviewerOutputError("unknown decision");
	}
	if (!risk || !REVIEW_RISKS.includes(risk as ModelReview["risk"])) {
		throw new ReviewerOutputError("unknown risk");
	}
	const reason = JSON.parse(reasonLiteral ?? '""') as unknown;
	if (typeof reason !== "string" || reason.trim() === "") throw new ReviewerOutputError("reason must not be empty");
	if (reason.length > MAX_REVIEW_REASON_CHARS) {
		throw new ReviewerOutputError(`reason exceeds ${MAX_REVIEW_REASON_CHARS} characters`);
	}
	// A reviewer reason crosses audit, UI and agent-output boundaries. It is
	// explanatory data, never a terminal control channel.
	if (hasDisplayControlCharacter(reason)) {
		throw new ReviewerOutputError("reason contains terminal or bidirectional control characters");
	}
	return {
		decision: decision as ModelReview["decision"],
		risk: risk as ModelReview["risk"],
		reason,
	};
}
