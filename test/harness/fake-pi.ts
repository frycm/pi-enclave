/**
 * A fake pi, built to the semantics verified in 0.84.2 rather than to what is
 * convenient.
 *
 * Three of those semantics are the whole reason this harness exists, and a
 * simpler double would get each of them wrong:
 *
 * 1. **Every `tool_call` handler receives the same event object**, and a later
 *    handler may mutate `event.input` in place. That is what the lock's freeze
 *    is defending against, so the harness reproduces it exactly -- no cloning
 *    between handlers.
 * 2. **A handler that throws is not caught**, and the tool does not run. So a
 *    frozen input mutated by a later handler fails the call closed. The harness
 *    lets the throw escape and records the call as errored.
 * 3. **A batch's `tool_call` events all complete before any tool executes.**
 *    This is the window the execute-time re-check exists for: blocking a call
 *    cannot un-prepare a sibling that was already prepared.
 *
 * Sources: `runner.ts:932-953` (handler loop, no clone, no catch),
 * `agent-loop.ts:489-554` (prepare-all-then-execute), `agent-session.ts:491`
 * (`input` is the object `execute` receives).
 */

export interface FakeToolCallEvent {
	type: "tool_call";
	toolName: string;
	toolCallId: string;
	input: Record<string, unknown>;
}

export interface FakeToolCallResult {
	block?: boolean;
	reason?: string;
	terminate?: boolean;
}

/** `undefined` rather than `void`: a handler that decides nothing returns nothing. */
export type ToolCallHandler = (
	event: FakeToolCallEvent,
) => Promise<FakeToolCallResult | undefined> | FakeToolCallResult | undefined;

export interface PreparedCall {
	event: FakeToolCallEvent;
	result: FakeToolCallResult;
	/** Set when a handler threw. The tool does not run. */
	error?: Error;
}

export interface ExecutedCall {
	toolCallId: string;
	toolName: string;
	/** The input as it stood when the tool ran. */
	input: Record<string, unknown>;
	output?: unknown;
	error?: Error;
}

export interface BatchResult {
	prepared: PreparedCall[];
	executed: ExecutedCall[];
	/** True when every finalized result in the batch asked to terminate. */
	terminated: boolean;
	aborted: boolean;
}

export interface FakePiOptions {
	/** What a tool does when it runs. Absent tools succeed with no output. */
	execute?: (call: FakeToolCallEvent) => Promise<unknown> | unknown;
}

export class FakePi {
	private readonly handlers: ToolCallHandler[] = [];
	private readonly options: FakePiOptions;
	/** Everything `ctx.abort()` was called for, in order. */
	readonly aborts: string[] = [];
	readonly steers: string[] = [];

	constructor(options: FakePiOptions = {}) {
		this.options = options;
	}

	onToolCall(handler: ToolCallHandler): void {
		this.handlers.push(handler);
	}

	abort(reason = "abort"): void {
		this.aborts.push(reason);
	}

	steer(message: string): void {
		this.steers.push(message);
	}

	/**
	 * Run one batch the way pi does: prepare every call, then execute the ones
	 * that survived.
	 */
	async batch(
		calls: readonly { toolName: string; input: Record<string, unknown>; toolCallId?: string }[],
	): Promise<BatchResult> {
		const prepared: PreparedCall[] = [];

		for (const [index, call] of calls.entries()) {
			const event: FakeToolCallEvent = {
				type: "tool_call",
				toolName: call.toolName,
				toolCallId: call.toolCallId ?? `call-${index}`,
				input: call.input,
			};
			let result: FakeToolCallResult = {};
			let error: Error | undefined;
			for (const handler of this.handlers) {
				try {
					const returned = await handler(event);
					if (returned) result = returned;
					// A block short-circuits the remaining handlers.
					if (returned?.block) break;
				} catch (thrown) {
					error = thrown as Error;
					break;
				}
			}
			prepared.push({ event, result, ...(error ? { error } : {}) });
		}

		const executed: ExecutedCall[] = [];
		for (const call of prepared) {
			if (call.error || call.result.block) continue;
			const record: ExecutedCall = {
				toolCallId: call.event.toolCallId,
				toolName: call.event.toolName,
				input: call.event.input,
			};
			try {
				record.output = await this.options.execute?.(call.event);
			} catch (thrown) {
				record.error = thrown as Error;
			}
			executed.push(record);
		}

		const finalized = prepared.filter((call) => call.result.block || call.error);
		const terminated = finalized.length > 0 && finalized.every((call) => call.result.terminate === true);

		return { prepared, executed, terminated, aborted: this.aborts.length > 0 };
	}

	/** One call, for the common case. */
	async call(toolName: string, input: Record<string, unknown>, toolCallId?: string): Promise<PreparedCall> {
		const result = await this.batch([{ toolName, input, ...(toolCallId ? { toolCallId } : {}) }]);
		return result.prepared[0] as PreparedCall;
	}
}

/** A UI double for the attendance layer, recording what was asked. */
export class FakeUI {
	readonly confirms: { title: string; message: string; timeout?: number }[] = [];
	readonly inputs: { title: string; placeholder?: string; timeout?: number }[] = [];
	readonly notices: { message: string; level?: string }[] = [];
	status: string | undefined;

	constructor(
		private readonly answers: {
			confirm?: (title: string, message: string) => boolean | Promise<boolean>;
			input?: (title: string, placeholder?: string) => string | undefined | Promise<string | undefined>;
		} = {},
	) {}

	async confirm(title: string, message: string, options?: { timeout?: number }): Promise<boolean> {
		this.confirms.push({ title, message, ...(options?.timeout !== undefined ? { timeout: options.timeout } : {}) });
		// pi resolves a timeout and a cancel to the same `false`; the default
		// here is that same false, so a test that forgets to answer sees the
		// production behaviour rather than a hang.
		return (await this.answers.confirm?.(title, message)) ?? false;
	}

	async input(title: string, placeholder?: string, options?: { timeout?: number }): Promise<string | undefined> {
		this.inputs.push({
			title,
			...(placeholder !== undefined ? { placeholder } : {}),
			...(options?.timeout !== undefined ? { timeout: options.timeout } : {}),
		});
		return (await this.answers.input?.(title, placeholder)) ?? undefined;
	}

	notify(message: string, level?: string): void {
		this.notices.push({ message, ...(level !== undefined ? { level } : {}) });
	}

	setStatus(_key: string, text: string | undefined): void {
		this.status = text;
	}
}
