/** Per-review local spans and measurements; no prompt, output or error text is recorded. */
import { InMemoryTelemetryContext } from "@earendil-works/pi-telemetry";

export interface ReviewerStageMetrics {
	/** One "decision" (chat) or "classify" per attempt (#25). */
	stage: "decision" | "classify";
	attempt: number;
	durationMs: number;
	firstOutputMs?: number;
	outcome: "ok" | "error" | "aborted";
	/** Requests the transport made to check the model's identity, when it reports them. */
	identityCalls?: number;
	/** Prompt tokens the runtime evaluated, and those it reused from its cache. */
	promptTokens?: number;
	cachedPromptTokens?: number;
	/** Time the runtime spent loading the model for this request, inside durationMs. */
	loadMs?: number;
}

/** What a transport reports about one request. Counts and durations only. */
export interface RuntimeReport {
	promptTokens?: number;
	cachedPromptTokens?: number;
	loadMs?: number;
}

export interface StageObserver {
	firstOutput(): void;
	identityCall(): void;
	runtime(report: RuntimeReport): void;
}

export interface ReviewerTelemetrySummary {
	durationMs: number;
	stages: ReviewerStageMetrics[];
}

export class ReviewerTelemetry {
	readonly context = new InMemoryTelemetryContext();
	private readonly started = performance.now();
	private readonly stages: ReviewerStageMetrics[] = [];

	async measure<T>(
		stage: ReviewerStageMetrics["stage"],
		attempt: number,
		signal: AbortSignal,
		run: (firstOutput: () => void, observer: StageObserver) => Promise<T>,
	): Promise<T> {
		const result = await this.context.startSpan(
			{ name: "pi_enclave.reviewer.stage", attributes: { stage, attempt } },
			async (span) => {
				const started = performance.now();
				let firstOutputMs: number | undefined;
				let identityCalls = 0;
				let runtime: RuntimeReport = {};
				let active = true;
				let outcome: ReviewerStageMetrics["outcome"] = "ok";
				const firstOutput = () => {
					if (!active || firstOutputMs !== undefined) return;
					firstOutputMs = performance.now() - started;
					span.addEvent("first_output", { durationMs: firstOutputMs });
				};
				const observer: StageObserver = {
					firstOutput,
					identityCall: () => {
						if (active) identityCalls++;
					},
					runtime: (report) => {
						if (!active) return;
						const numbers = Object.entries(report).filter(
							([, value]) => typeof value === "number" && Number.isFinite(value) && value >= 0,
						);
						runtime = { ...runtime, ...Object.fromEntries(numbers) };
					},
				};
				try {
					return { ok: true as const, value: await run(firstOutput, observer) };
				} catch (error) {
					outcome = signal.aborted ? "aborted" : "error";
					// Return errors as data inside the span so the recorder never
					// automatically captures a provider message containing task data.
					span.setStatus({ status: "error", error: { name: "ReviewerStageFailure", message: outcome } });
					return { ok: false as const, error };
				} finally {
					active = false;
					const durationMs = performance.now() - started;
					const metrics = {
						stage,
						attempt,
						durationMs,
						outcome,
						...(firstOutputMs !== undefined ? { firstOutputMs } : {}),
						...(identityCalls > 0 ? { identityCalls } : {}),
						...runtime,
					};
					this.stages.push(metrics);
					span.setAttributes(metrics);
					span.metrics
						?.histogram("pi_enclave.reviewer.stage.duration", { unit: "ms" })
						.record(durationMs, { stage, outcome }, span);
					if (firstOutputMs !== undefined)
						span.metrics
							?.histogram("pi_enclave.reviewer.first_output.duration", { unit: "ms" })
							.record(firstOutputMs, { stage }, span);
				}
			},
		);
		if (!result.ok) throw result.error;
		return result.value;
	}

	summary(): ReviewerTelemetrySummary {
		return { durationMs: performance.now() - this.started, stages: this.stages.map((entry) => ({ ...entry })) };
	}
}
