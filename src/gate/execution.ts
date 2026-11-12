/**
 * The execution-boundary check, on a pi that offers `pi.wrapToolExecution` (#29).
 *
 * pi 1.5.2 has no hook at the moment a tool runs. pi-enclave's own tools
 * re-check the lock from inside `execute` (`bindOwnedTool`), but a third-party
 * tool runs whatever pi hands it once `tool_call` said yes. In a parallel batch
 * every call passes `tool_call` before any executes, so a breaker that opens
 * part-way through cannot stop a third-party call that was already admitted.
 * Upstream, the gate therefore withholds such a call from a batch whenever one
 * runtime denial would open the breaker (`shouldWithholdNonOwnedSibling`).
 *
 * The `frycm/pi` prototype adds `pi.wrapToolExecution`: a wrapper that runs
 * after every `tool_call` handler, immediately before the tool, with a
 * deep-frozen copy of the arguments that is also what the tool receives. With
 * it, a third-party call runs inside `lock.runInvocation` like an owned one:
 * the complete gated action must match, the breaker is asked again, and the
 * call runs at most once. The withholding then has nothing left to do.
 *
 * Detected by a feature probe, never by version: pi-enclave keeps working on
 * unpatched pi, where nothing here is registered and the withholding stays.
 */
import { type ActionLock, LockViolation } from "./lock.ts";

/** One execution, as the prototype's wrapper receives it. */
export interface ToolExecutionCall {
	toolName: string;
	toolCallId: string;
	parentToolCallId?: string;
	input: unknown;
}

/** The part of the wrapper's extension context this check reads. */
export interface ToolExecutionContext {
	cwd: string;
	signal?: AbortSignal | undefined;
}

export type ToolExecutionWrapper = (
	call: ToolExecutionCall,
	next: () => Promise<unknown>,
	ctx: ToolExecutionContext,
) => Promise<unknown>;

/** `pi.wrapToolExecution`, typed here because pi 1.5.2's `ExtensionAPI` does not declare it. */
export interface ExecutionWrapperHost {
	wrapToolExecution: (wrapper: ToolExecutionWrapper) => () => void;
}

/** Whether this pi lets an extension decide at the moment a tool runs. */
export function hasExecutionWrapper(pi: object): pi is ExecutionWrapperHost {
	return typeof (pi as Partial<ExecutionWrapperHost>).wrapToolExecution === "function";
}

/**
 * Why a call was stopped at execution: a lock check (`LockViolation`'s kind),
 * a session that may run nothing (`unavailable`), or a cancellation that came
 * before the tool started (`aborted`). Arguments the lock cannot compare count
 * as `ambiguous`, like arguments that differ.
 */
export type ExecutionRefusalKind = LockViolation["kind"] | "unavailable" | "aborted";

/** A call the check stopped before the tool ran. */
export interface ExecutionRefusal {
	toolName: string;
	toolCallId: string;
	parentToolCallId?: string;
	kind: ExecutionRefusalKind;
	reason: string;
}

export interface ExecutionCheckDeps {
	lock: ActionLock;
	owned: readonly string[];
	/** Why nothing may run at all (probe, configuration, ownership, no policy yet), or undefined. */
	refusal: () => string | undefined;
	/** The gate is a pass-through (`PI_ENCLAVE_AUTO=off`): owned tools skip the lock then too. */
	passThrough: () => boolean;
	/**
	 * Told about every call stopped before its tool ran, so the trail says it
	 * did not run (the prototype still emits `tool_execution_end` for it, with
	 * `isError`). Not called when the tool itself ran and failed.
	 */
	onRefused?: (refusal: ExecutionRefusal) => void;
}

/**
 * The wrapper pi-enclave registers.
 *
 * A refusal is a throw: the prototype turns it into the tool's error result,
 * which is how a refused owned tool already reaches the model.
 */
export function createExecutionCheck(deps: ExecutionCheckDeps): ToolExecutionWrapper {
	return async (call, next, ctx) => {
		const refuse = (kind: ExecutionRefusalKind, reason: string): void => {
			deps.onRefused?.({
				toolName: call.toolName,
				toolCallId: call.toolCallId,
				...(call.parentToolCallId !== undefined ? { parentToolCallId: call.parentToolCallId } : {}),
				kind,
				reason,
			});
		};
		const refusal = deps.refusal();
		if (refusal !== undefined) {
			refuse("unavailable", refusal);
			throw new Error(refusal);
		}
		if (deps.passThrough()) return next();
		// Owned tools bind their invocation inside execute. Binding it here as
		// well would start the entry before the tool reaches it, and the tool's
		// own check would then refuse it as already started.
		if (deps.owned.includes(call.toolName)) return next();
		let started = false;
		try {
			return await deps.lock.runInvocation(
				call.toolCallId,
				call.toolName,
				call.input,
				ctx.cwd,
				() => {
					started = true;
					return next();
				},
				ctx.signal,
			);
		} catch (error) {
			if (!started) {
				const message = error instanceof Error ? error.message : String(error);
				// Besides a LockViolation, only a cancellation or arguments the
				// lock cannot compare (not JSON-like) stop a call here.
				const kind = error instanceof LockViolation ? error.kind : ctx.signal?.aborted ? "aborted" : "ambiguous";
				refuse(kind, message);
			}
			throw error;
		}
	};
}
