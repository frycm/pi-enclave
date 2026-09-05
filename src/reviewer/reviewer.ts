import type { EffectiveProfile } from "../config/types.ts";
import { buildReviewEvidence, renderReviewEvidence } from "./evidence.ts";
import { parseReviewerOutput, ReviewerOutputError } from "./output.ts";
import { enforceReview } from "./risk.ts";
import type {
	ActionReviewer,
	BuildEvidenceOptions,
	ModelReview,
	ReviewerPrompt,
	ReviewerRequest,
	ReviewerResult,
} from "./types.ts";

export const REVIEWER_MAX_ATTEMPTS = 3;
export const REVIEWER_MAX_TOKENS = 256;
export const REVIEWER_TEMPERATURE = 0;
export const REVIEWER_SEED = 31_337;
export const REVIEWER_NUM_CTX = 4_096;

export interface CompletionRequest {
	system: string;
	user: string;
	signal: AbortSignal;
	maxTokens: number;
	temperature: number;
	seed: number;
	numCtx: number;
}

/** A model-specific transport. It returns only assistant text and carries no tools or session context. */
export interface ReviewerCompletion {
	readonly name: string;
	/** null means provider-managed context; a number is enforced by the transport. */
	readonly numCtx?: number | null;
	complete(request: CompletionRequest): Promise<string>;
}

export interface IsolatedReviewerOptions {
	profile: EffectiveProfile;
	prompt: ReviewerPrompt;
	primary: ReviewerCompletion;
	fallback?: ReviewerCompletion;
	timeoutMs: number;
	evidence:
		| Omit<BuildEvidenceOptions, "action" | "trigger" | "toolSource">
		| ((request: ReviewerRequest) => Omit<BuildEvidenceOptions, "action" | "trigger" | "toolSource">);
	delay?: (milliseconds: number) => Promise<void>;
	maxAttempts?: number;
	seed?: number;
}

function timeoutSignal(milliseconds: number): {
	signal: AbortSignal;
	wait<T>(promise: Promise<T>): Promise<T>;
	dispose(): void;
} {
	const controller = new AbortController();
	const timeout = new Promise<never>((_resolve, reject) => {
		const timer = setTimeout(() => {
			const error = new Error("reviewer timeout");
			controller.abort(error);
			reject(error);
		}, milliseconds);
		controller.signal.addEventListener("abort", () => clearTimeout(timer), { once: true });
	});
	return {
		signal: controller.signal,
		wait: <T>(promise: Promise<T>) => Promise.race([promise, timeout]),
		dispose: () => controller.abort(),
	};
}

function invalidOutput(reason: string, evidence: ReturnType<typeof buildReviewEvidence>): ReviewerResult {
	return { ok: false, kind: "invalid-output", reason, evidence };
}

function backoff(attempt: number): number {
	return 100 * 2 ** attempt;
}

export class IsolatedReviewer implements ActionReviewer {
	private readonly delay: (milliseconds: number) => Promise<void>;

	constructor(private readonly options: IsolatedReviewerOptions) {
		this.delay = options.delay ?? ((milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds)));
	}

	async review(request: ReviewerRequest): Promise<ReviewerResult> {
		const suppliedEvidence =
			typeof this.options.evidence === "function" ? this.options.evidence(request) : this.options.evidence;
		// Keep trusted full records separate from the bounded model representation.
		const authorization = structuredClone(suppliedEvidence.authorization ?? []);
		const evidence = buildReviewEvidence({
			...suppliedEvidence,
			...request,
		});
		const rendered = renderReviewEvidence(evidence);
		let lastError = "reviewer unavailable";
		const maxAttempts = this.options.maxAttempts ?? REVIEWER_MAX_ATTEMPTS;
		const seed = this.options.seed ?? REVIEWER_SEED;

		for (let attempt = 0; attempt < maxAttempts; attempt++) {
			// A configured fallback gets the final bounded attempt; it never silently
			// becomes the session model or deterministic mode.
			const completion =
				attempt === maxAttempts - 1 && this.options.fallback ? this.options.fallback : this.options.primary;
			const timer = timeoutSignal(this.options.timeoutMs);
			try {
				const gate = await timer.wait(
					completion.complete({
						system: this.options.prompt.authorizationSystem,
						user: rendered,
						signal: timer.signal,
						maxTokens: 1,
						temperature: REVIEWER_TEMPERATURE,
						seed: seed + attempt,
						numCtx: REVIEWER_NUM_CTX,
					}),
				);
				if (gate !== "0" && gate !== "1") {
					return invalidOutput(`authorization stage returned ${JSON.stringify(gate)} instead of 0 or 1`, evidence);
				}

				const text = await timer.wait(
					completion.complete({
						system: this.options.prompt.decisionSystem[gate],
						user: rendered,
						signal: timer.signal,
						maxTokens: REVIEWER_MAX_TOKENS,
						temperature: REVIEWER_TEMPERATURE,
						seed: seed + attempt,
						numCtx: REVIEWER_NUM_CTX,
					}),
				);
				let model: ModelReview;
				try {
					model = parseReviewerOutput(text);
				} catch (error) {
					if (error instanceof ReviewerOutputError) return invalidOutput(error.message, evidence);
					throw error;
				}
				const currentEvidence =
					typeof this.options.evidence === "function" ? this.options.evidence(request) : this.options.evidence;
				if (JSON.stringify(currentEvidence.authorization ?? []) !== JSON.stringify(authorization)) {
					return invalidOutput("direct authorization changed during review; a fresh decision is required", evidence);
				}
				return {
					ok: true,
					review: enforceReview(model, request.action, this.options.profile, evidence, authorization),
					modelReview: model,
					evidence,
				};
			} catch (error) {
				lastError = `${completion.name}: ${(error as Error).message}`;
			} finally {
				timer.dispose();
			}
			if (attempt + 1 < maxAttempts) await this.delay(backoff(attempt));
		}

		return {
			ok: false,
			kind: "unavailable",
			reason: `reviewer failed after ${maxAttempts} attempts (${lastError})`,
			evidence,
		};
	}
}
