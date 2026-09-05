import type { Violation } from "../backend/types.ts";
import type { AttendedMode, ReviewSettings, SourceId } from "../config/types.ts";
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
	action: ReviewActionEvidence;
	violation: Violation | null;
	requestedCapability: Capability | null;
	authorization: ReviewAuthorization[];
	context: ReviewContextEntry[];
	profile: { name: string; attended: AttendedMode };
}

export interface ModelReview {
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
	authorizationSystem: string;
	system: string;
	decisionSystem: { "0": string; "1": string };
	promptHash: string;
}

export type ReviewerFailureKind = "invalid-output" | "unavailable";

export type ReviewerResult =
	| { ok: true; review: EffectiveReview; modelReview: ModelReview; evidence: ReviewEvidence }
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
	action: CanonicalAction;
	trigger: ReviewerTrigger;
	attended: AttendedMode;
	toolSource?: string;
	violation?: Violation;
	authorization?: readonly ReviewAuthorization[];
	context?: readonly ReviewContextEntry[];
}

export type ReviewLists = Pick<ReviewSettings, "environment" | "hard_deny" | "soft_deny" | "allow">;
