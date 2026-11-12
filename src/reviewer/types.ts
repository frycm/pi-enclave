import type { ClassifierQuestion } from "@earendil-works/pi-ai";
import type { Violation } from "../backend/types.ts";
import type { AttendedMode, ReviewSettings, SourceId } from "../config/types.ts";
import type { ToolReachability } from "../gate/reachability.ts";
import type { CanonicalAction, Capability } from "../policy/canonical.ts";

export const REVIEW_DECISIONS = ["allow", "deny", "ask"] as const;
export type ReviewDecision = (typeof REVIEW_DECISIONS)[number];

export const REVIEW_RISKS = ["low", "medium", "high", "critical"] as const;
export type ReviewRisk = (typeof REVIEW_RISKS)[number];

export type ReviewerTrigger = "mutating" | "all" | "capability";

export interface ReviewAuthorization {
	provenance: "direct";
	channel: "interactive" | "rpc";
	text: string;
}

export interface ReviewContextEntry {
	provenance: "assistant_tool_call";
	tool: string;
	input: Record<string, unknown>;
	truncated?: boolean;
}

export interface ReviewActionEvidence {
	tool: string;
	input: Record<string, unknown>;
	argv?: string[][];
	cwd: string;
	paths: { raw: string; resolved: string; writes: boolean }[];
	hash: string;
	trigger: ReviewerTrigger;
	confident: boolean;
	/** Display evidence was bounded; the hash still binds the complete executor input. */
	truncated: boolean;
	toolSource?: string;
}

/** The only user turn sent to the isolated reviewer. */
export interface ReviewEvidence {
	toolReachability?: ToolReachability;
	action: ReviewActionEvidence;
	violation: Violation | null;
	requestedCapability: Capability | null;
	authorization: ReviewAuthorization[];
	context: ReviewContextEntry[];
	profile: { name: string; attended: AttendedMode };
	/** Context entries were dropped to fit the model's context (#17). */
	contextTruncated?: true;
	/** Older direct authorization entries were dropped to fit; the newest is always kept. */
	authorizationTruncated?: true;
}

export interface ModelReview {
	/**
	 * The chat reviewer's answer to "does a direct entry authorize this?",
	 * given before its decision (#25). Recorded, never used in the verdict.
	 */
	authorized?: boolean;
	decision: ReviewDecision;
	risk: ReviewRisk;
	reason: string;
}

export interface EffectiveReview extends ModelReview {
	modelRisk: ReviewRisk;
	minimumRisk: ReviewRisk;
	authorizationCovers: boolean;
}

export interface SourcedReviewRule {
	text: string;
	source: Extract<SourceId, "builtin" | "user_global">;
}

export interface ReviewerRulebook {
	environment: SourcedReviewRule[];
	hard_deny: SourcedReviewRule[];
	soft_deny: SourcedReviewRule[];
	allow: SourcedReviewRule[];
}

export interface ReviewerPrompt {
	/** The chat transport's one system prompt (#25). */
	system: string;
	/** Binds the chat transport: the system prompt and the output schema. */
	promptHash: string;
	/** The classifier transport's questions and their own hash (#26). */
	classifier: { questions: Record<string, ClassifierQuestion>; promptHash: string };
}

/**
 * What a classifier reviewer said, as normalized label probabilities (#26).
 * Recorded in the audit log so thresholds can be checked against real traffic.
 */
export interface ReviewProbabilities {
	authorized: number;
	decision: Record<ReviewDecision, number>;
	risk: Record<ReviewRisk, number>;
}

/** How probabilities become a verdict. Chosen by qualification, stored in its record. */
export interface ClassifierThresholds {
	/** allow only when P(allow) is at least this. */
	allow: number;
	/** otherwise deny when P(deny) is at least this; everything else is ask. */
	deny: number;
	/** Divides the label logits before normalizing (pi's classifier option). */
	temperature: number;
}

export type ReviewerFailureKind = "invalid-output" | "unavailable";

export type ReviewerResult =
	| {
			ok: true;
			review: EffectiveReview;
			modelReview: ModelReview;
			evidence: ReviewEvidence;
			/** Present for the classifier transport. */
			probabilities?: ReviewProbabilities;
	  }
	| { ok: false; kind: ReviewerFailureKind; reason: string; evidence: ReviewEvidence };

export interface ReviewerRequest {
	action: CanonicalAction;
	trigger: ReviewerTrigger;
	toolSource?: string;
}

/** Gate-facing contract. Implementations must never expose a session model context or tools. */
export interface ActionReviewer {
	review(request: ReviewerRequest): Promise<ReviewerResult>;
}

export interface BuildEvidenceOptions {
	toolReachability?: ToolReachability;
	action: CanonicalAction;
	trigger: ReviewerTrigger;
	attended: AttendedMode;
	toolSource?: string;
	violation?: Violation;
	authorization?: readonly ReviewAuthorization[];
	context?: readonly ReviewContextEntry[];
}

export type ReviewLists = Pick<ReviewSettings, "environment" | "hard_deny" | "soft_deny" | "allow">;
