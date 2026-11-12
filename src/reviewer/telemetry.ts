/** Per-review local spans and measurements; no prompt, output or error text is recorded. */
import { InMemoryTelemetryContext } from "@earendil-works/pi-telemetry";

export interface ReviewerStageMetrics {
	stage: "authorization" | "decision" | "classify";
	attempt: number;
	durationMs: number;
	firstOutputMs?: number;
	outcome: "ok" | "error" | "aborted";
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
		run: (firstOutput: () => void) => Promise<T>,
	): Promise<T> {
		const result = await this.context.startSpan(
			{ name: "pi_enclave.reviewer.stage", attributes: { stage, attempt } },
			async (span) => {
				const started = performance.now();
				let firstOutputMs: number | undefined;
				let active = true;
				let outcome: ReviewerStageMetrics["outcome"] = "ok";
				const firstOutput = () => {
					if (!active || firstOutputMs !== undefined) return;
					firstOutputMs = performance.now() - started;
					span.addEvent("first_output", { durationMs: firstOutputMs });
				};
				try {
					return { ok: true as const, value: await run(firstOutput) };
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
