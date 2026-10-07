import { isProvenanceRecord, PROVENANCE_ENTRY_TYPE, sha256 } from "../gate/provenance.ts";
import { MAX_AUTHORIZATION_ENTRIES, MAX_CONTEXT_ENTRIES } from "./evidence.ts";
import type { ReviewAuthorization, ReviewContextEntry } from "./types.ts";

export interface RestoredReviewHistory {
	authorization: ReviewAuthorization[];
	context: ReviewContextEntry[];
}

function textContent(content: unknown): string {
	if (typeof content === "string") return content;
	if (!Array.isArray(content)) return "";
	return content
		.map((part) =>
			part && typeof part === "object" && (part as { type?: unknown }).type === "text"
				? String((part as { text?: unknown }).text ?? "")
				: "",
		)
		.join("");
}

/** Restore only provenance-proven direct input and assistant tool-call metadata from the active branch. */
export function restoreReviewHistory(entries: readonly unknown[]): RestoredReviewHistory {
	const messages = new Map<string, string>();
	const authorization: ReviewAuthorization[] = [];
	const context: ReviewContextEntry[] = [];

	for (const entry of entries) {
		if (!entry || typeof entry !== "object") continue;
		const value = entry as Record<string, unknown>;
		if (value.type === "message" && value.message && typeof value.message === "object") {
			const message = value.message as Record<string, unknown>;
			if (message.role === "user") {
				const text = textContent(message.content);
				if (text) messages.set(sha256(text), text);
			} else if (message.role === "assistant" && Array.isArray(message.content)) {
				for (const part of message.content) {
					if (!part || typeof part !== "object") continue;
					const toolCall = part as Record<string, unknown>;
					if (toolCall.type !== "toolCall" || typeof toolCall.name !== "string") continue;
					const input = toolCall.arguments ?? toolCall.input;
					if (!input || typeof input !== "object" || Array.isArray(input)) continue;
					context.push({
						provenance: "assistant_tool_call",
						tool: toolCall.name,
						input: structuredClone(input as Record<string, unknown>),
					});
				}
			} else if (message.role === "toolResult" && message.nestedCalls && typeof message.nestedCalls === "object") {
				// Pi 1.1 persists child invocation metadata on the parent's result.
				// These inputs are untrusted context, never direct authorization.
				const nested = message.nestedCalls as { calls?: unknown };
				if (Array.isArray(nested.calls)) {
					for (const call of nested.calls) {
						if (!call || typeof call !== "object") continue;
						const { name, arguments: input } = call as Record<string, unknown>;
						if (typeof name !== "string" || !input || typeof input !== "object" || Array.isArray(input)) continue;
						context.push({
							provenance: "assistant_tool_call",
							tool: name,
							input: structuredClone(input as Record<string, unknown>),
						});
					}
				}
			}
			continue;
		}
		if (value.type !== "custom" || value.customType !== PROVENANCE_ENTRY_TYPE || !isProvenanceRecord(value.data)) {
			continue;
		}
		const stored = messages.get(value.data.messageTextSha256);
		const text = value.data.rawText ?? stored;
		if (!text) continue;
		authorization.push({ provenance: "direct", channel: value.data.source, text });
	}

	return {
		authorization: authorization.slice(-MAX_AUTHORIZATION_ENTRIES),
		context: context.slice(-MAX_CONTEXT_ENTRIES),
	};
}
