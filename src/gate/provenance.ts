/**
 * Which user messages are really from the user.
 *
 * Ported from pi-approval-guardian's `authorization-provenance.ts` (MIT). The
 * problem it solves is pi's, not ours: a stored user message does not record
 * whether it came from the interactive editor, from an RPC client, or from
 * `pi.sendUserMessage` in some other extension -- and skills and prompt
 * templates expand the text before it is stored, so the message in the session
 * is not the message the person typed.
 *
 * Only the `input` event has both facts, and it fires before any expansion
 * (`agent-session.ts:1116-1164`). So the tracker watches three events and
 * stitches them together:
 *
 * - `input` gives raw text and a source.
 * - `before_agent_start` gives the expanded prompt, which is how a raw
 *   observation is matched to what the model will see.
 * - `message_start` gives the stored message, which is what gets persisted.
 *
 * Phase 2 has exactly one consumer -- the breaker resets on a *direct* message,
 * not on any message, so an extension cannot clear a trip by sending one. Phase
 * 3 is where this becomes the reviewer's `authorization` evidence, which is why
 * it is built now, with the semantics settled, rather than alongside the thing
 * that depends on it.
 */
import { createHash } from "node:crypto";

export type InputSource = "interactive" | "rpc" | "extension";

export interface InputObservation {
	text: string;
	source: InputSource;
	/** Present when the message was queued mid-turn rather than starting one. */
	streamingBehavior?: "steer" | "followUp";
}

/** What is persisted as a session entry, and read back on resume. */
export interface ProvenanceRecord {
	version: 1;
	source: "interactive" | "rpc";
	messageTimestamp: number;
	messageTextSha256: string;
	/** Only when the stored text differs from what the person actually typed. */
	rawText?: string;
}

export const PROVENANCE_ENTRY_TYPE = "pi-enclave-direct-user-input";

/** Guardian's bound, kept: enough for any real interleaving, small enough to be a bound. */
const MAX_QUEUE = 32;

export function sha256(text: string): string {
	return createHash("sha256").update(text).digest("hex");
}

interface ConfirmedInput {
	input: InputObservation;
	expandedText: string;
}

export class ProvenanceTracker {
	private pending: InputObservation[] = [];
	private confirmed: ConfirmedInput[] = [];

	/** From `pi.on("input")`. The only place raw, pre-expansion text exists. */
	observe(observation: InputObservation): void {
		this.pending.push(observation);
		if (this.pending.length > MAX_QUEUE) this.pending.shift();
	}

	/**
	 * From `pi.on("before_agent_start")`, which carries the *expanded* prompt.
	 *
	 * An exact match is preferred; failing that the newest pending observation
	 * is assumed to be the one that expanded. That assumption is guardian's and
	 * it is sound in the direction that matters: it can only ever attribute a
	 * prompt to an input the user really did type moments earlier.
	 */
	confirmPrompt(expandedText: string): void {
		let index = -1;
		for (let i = this.pending.length - 1; i >= 0; i--) {
			if (this.pending[i]?.text === expandedText) {
				index = i;
				break;
			}
		}
		if (index < 0) index = this.pending.length - 1;
		const input = this.pending[index];
		if (!input) return;
		this.pending = this.pending.slice(index + 1);
		this.confirmed.push({ input, expandedText });
		if (this.confirmed.length > MAX_QUEUE) this.confirmed.shift();
	}

	/**
	 * From `pi.on("message_start")` for a user message. Returns what to persist.
	 *
	 * `undefined` means the message is not direct: either nothing matches it, or
	 * it came from an extension. Both are the same answer to the only question
	 * anyone asks of this class.
	 */
	recordForMessage(text: string, timestamp: number): ProvenanceRecord | undefined {
		const matched = this.match(text);
		if (!matched || matched.source === "extension") return undefined;

		const record: ProvenanceRecord = {
			version: 1,
			source: matched.source,
			messageTimestamp: timestamp,
			messageTextSha256: sha256(text),
		};
		// Only when they differ: storing the raw text of every message would put
		// the user's own words in a second place for no reason.
		if (matched.text !== text) record.rawText = matched.text;
		return record;
	}

	private match(text: string): InputObservation | undefined {
		const confirmedIndex = this.confirmed.findIndex((entry) => entry.expandedText === text);
		if (confirmedIndex >= 0) {
			const entry = this.confirmed[confirmedIndex] as ConfirmedInput;
			this.confirmed = this.confirmed.slice(confirmedIndex + 1);
			return entry.input;
		}

		// A queued steer or follow-up never emits `before_agent_start`, so it can
		// only be matched exactly. The latest match wins, so a newer
		// extension-sourced message cannot inherit an older direct one.
		let exact = -1;
		for (let i = this.pending.length - 1; i >= 0; i--) {
			if (this.pending[i]?.text === text) {
				exact = i;
				break;
			}
		}
		if (exact >= 0) {
			const observation = this.pending[exact];
			this.pending = this.pending.slice(exact + 1);
			return observation;
		}

		// Quarantine: drop everything up to the newest queued observation. An
		// expanded queued message must not be able to authorize a later message
		// that happens to equal the original text.
		let lastQueued = -1;
		for (let i = this.pending.length - 1; i >= 0; i--) {
			if (this.pending[i]?.streamingBehavior) {
				lastQueued = i;
				break;
			}
		}
		if (lastQueued >= 0) this.pending = this.pending.slice(lastQueued + 1);
		return undefined;
	}

	/** Nothing survives a session boundary except the persisted records. */
	reset(): void {
		this.pending = [];
		this.confirmed = [];
	}
}

/** Validate a record read back from a session entry. Anything else is untrusted. */
export function isProvenanceRecord(value: unknown): value is ProvenanceRecord {
	if (!value || typeof value !== "object") return false;
	const record = value as Partial<ProvenanceRecord>;
	return (
		record.version === 1 &&
		(record.source === "interactive" || record.source === "rpc") &&
		typeof record.messageTimestamp === "number" &&
		Number.isFinite(record.messageTimestamp) &&
		typeof record.messageTextSha256 === "string" &&
		/^[0-9a-f]{64}$/.test(record.messageTextSha256) &&
		(record.rawText === undefined || typeof record.rawText === "string")
	);
}
