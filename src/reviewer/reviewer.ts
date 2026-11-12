import type { ClassifierAnswer, ClassifierQuestion, JsonObject } from "@earendil-works/pi-ai";
import type { EffectiveProfile } from "../config/types.ts";
import { chatFits, classifierFits, ReviewerBudgetError } from "./budget.ts";
import { buildReviewEvidence, renderReviewEvidence } from "./evidence.ts";
import { parseReviewerOutput, ReviewerOutputError } from "./output.ts";
import { parseReviewProbabilities, reviewFromProbabilities } from "./probabilities.ts";
import { enforceReview } from "./risk.ts";
import { ReviewerTelemetry, type ReviewerTelemetrySummary } from "./telemetry.ts";
import type {
	ActionReviewer,
	BuildEvidenceOptions,
	ClassifierThresholds,
	ModelReview,
	ReviewerPrompt,
	ReviewerRequest,
	ReviewerResult,
	ReviewProbabilities,
} from "./types.ts";

export const REVIEWER_MAX_ATTEMPTS = 3;
export const REVIEWER_MAX_TOKENS = 256;
export const REVIEWER_TEMPERATURE = 0;
export const REVIEWER_SEED = 31_337;
/** The default Ollama context (`reviewer.numCtx`), in tokens (#17). */
export const REVIEWER_NUM_CTX = 8_192;

export interface CompletionRequest {
	system: string;
	user: string;
	signal: AbortSignal;
	maxTokens: number;
	temperature: number;
	seed: number;
	numCtx: number;
	/** Observation only; no output bytes or authorization flow through this callback. */
	onFirstOutput?: () => void;
}

/** A model-specific transport. It returns only assistant text and carries no tools or session context. */
export interface ReviewerCompletion {
	readonly kind?: "chat";
	readonly name: string;
	/** null means provider-managed context; a number is enforced by the transport. */
	readonly numCtx?: number | null;
	complete(request: CompletionRequest): Promise<string>;
}

export interface ClassifyRequest {
	state: JsonObject;
	questions: Record<string, ClassifierQuestion>;
	signal: AbortSignal;
	temperature: number;
}

/**
 * A classifier transport (#26). It returns label probabilities for typed
 * questions about the evidence; there is no generated text to parse.
 */
export interface ReviewerClassifier {
	readonly kind: "classifier";
	readonly name: string;
	/** The server's slot context, as its identity reported and binds it; evidence is sized to it (#17). */
	readonly numCtx: number;
	/** From the qualification record; qualification itself runs with provisional values. */
	readonly thresholds: ClassifierThresholds;
	classify(request: ClassifyRequest): Promise<Record<string, ClassifierAnswer>>;
}

export type ReviewerTransport = ReviewerCompletion | ReviewerClassifier;

export function isClassifier(transport: ReviewerTransport): transport is ReviewerClassifier {
	return transport.kind === "classifier";
}

export interface IsolatedReviewerOptions {
	profile: EffectiveProfile;
	prompt: ReviewerPrompt;
	primary: ReviewerTransport;
	fallback?: ReviewerTransport;
	timeoutMs: number;
	evidence:
		| Omit<BuildEvidenceOptions, "action" | "trigger" | "toolSource">
		| ((request: ReviewerRequest) => Omit<BuildEvidenceOptions, "action" | "trigger" | "toolSource">);
	delay?: (milliseconds: number) => Promise<void>;
	maxAttempts?: number;
	seed?: number;
	onTelemetry?: (metrics: ReviewerTelemetrySummary, request: ReviewerRequest) => void;
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
		const telemetry = new ReviewerTelemetry();
		try {
			return await this.performReview(request, telemetry);
		} finally {
			this.options.onTelemetry?.(telemetry.summary(), request);
		}
	}

	private async performReview(request: ReviewerRequest, telemetry: ReviewerTelemetry): Promise<ReviewerResult> {
		const suppliedEvidence =
			typeof this.options.evidence === "function" ? this.options.evidence(request) : this.options.evidence;
		// Keep trusted full records separate from the bounded model representation.
		const authorization = structuredClone(suppliedEvidence.authorization ?? []);
		const transports = this.options.fallback ? [this.options.primary, this.options.fallback] : [this.options.primary];
		const fits = transports.map((transport) =>
			isClassifier(transport)
				? classifierFits(this.options.prompt, transport.numCtx)
				: typeof transport.numCtx === "number"
					? chatFits(this.options.prompt, transport.numCtx)
					: undefined,
		);
		let evidence: ReturnType<typeof buildReviewEvidence>;
		try {
			// One document for every attempt, so it must fit each transport that may get it.
			evidence = buildReviewEvidence({ ...suppliedEvidence, ...request }, (rendered) =>
				fits.every((check) => !check || check(rendered)),
			);
		} catch (error) {
			if (!(error instanceof ReviewerBudgetError)) throw error;
			return {
				ok: false,
				kind: "unavailable",
				reason: error.message,
				evidence: buildReviewEvidence({ ...suppliedEvidence, ...request }),
			};
		}
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
				let model: ModelReview;
				let probabilities: ReviewProbabilities | undefined;
				if (isClassifier(completion)) {
					const answers = await telemetry.measure("classify", attempt + 1, timer.signal, () =>
						timer.wait(
							completion.classify({
								// The same bounded document the chat transport sends as its user turn.
								state: JSON.parse(rendered) as JsonObject,
								questions: this.options.prompt.classifier.questions,
								signal: timer.signal,
								temperature: completion.thresholds.temperature,
							}),
						),
					);
					try {
						probabilities = parseReviewProbabilities(answers);
					} catch (error) {
						if (error instanceof ReviewerOutputError) return invalidOutput(error.message, evidence);
						throw error;
					}
					model = reviewFromProbabilities(probabilities, completion.thresholds);
				} else {
					const chat = await this.chatReview(completion, rendered, timer, telemetry, attempt, seed);
					if ("invalid" in chat) return invalidOutput(chat.invalid, evidence);
					model = chat.model;
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
					...(probabilities ? { probabilities } : {}),
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

	/** The two-stage chat protocol: a one-token authorization gate, then the JSON verdict. */
	private async chatReview(
		completion: ReviewerCompletion,
		rendered: string,
		timer: ReturnType<typeof timeoutSignal>,
		telemetry: ReviewerTelemetry,
		attempt: number,
		seed: number,
	): Promise<{ model: ModelReview } | { invalid: string }> {
		const gate = await telemetry.measure("authorization", attempt + 1, timer.signal, (onFirstOutput) =>
			timer.wait(
				completion.complete({
					system: this.options.prompt.authorizationSystem,
					user: rendered,
					signal: timer.signal,
					maxTokens: 1,
					temperature: REVIEWER_TEMPERATURE,
					seed: seed + attempt,
					numCtx: completion.numCtx ?? REVIEWER_NUM_CTX,
					onFirstOutput,
				}),
			),
		);
		if (gate !== "0" && gate !== "1") {
			return { invalid: `authorization stage returned ${JSON.stringify(gate)} instead of 0 or 1` };
		}

		const text = await telemetry.measure("decision", attempt + 1, timer.signal, (onFirstOutput) =>
			timer.wait(
				completion.complete({
					system: this.options.prompt.decisionSystem[gate],
					user: rendered,
					signal: timer.signal,
					maxTokens: REVIEWER_MAX_TOKENS,
					temperature: REVIEWER_TEMPERATURE,
					seed: seed + attempt,
					numCtx: completion.numCtx ?? REVIEWER_NUM_CTX,
					onFirstOutput,
				}),
			),
		);
		try {
			return { model: parseReviewerOutput(text) };
		} catch (error) {
			if (error instanceof ReviewerOutputError) return { invalid: error.message };
			throw error;
		}
	}
}
