/**
 * The action lock.
 *
 * Two mechanisms with one purpose: what executes is what was decided on.
 *
 * **The freeze** is guardian's `tool-input-lock.ts`, ported with attribution
 * (MIT). `event.input` is asserted JSON-like, deep-frozen, and redefined
 * non-writable. It works because of a fact verified in pi 0.84.2: the object
 * the `tool_call` handlers receive *is* the object `execute` receives -- pi
 * clones the arguments once at validation and never again. A later extension's
 * mutation therefore throws a `TypeError`, and `emitToolCall` is the one
 * emitter that does not catch handler exceptions, so `prepareToolCall` turns it
 * into an error result and the tool never runs. Fails closed by construction.
 *
 * **The table** is new. Guardian has no hash and no execute-once, because it
 * does not need one: it decides inside a single hook invocation and nothing it
 * writes outlives the turn. pi-enclave persists approvals across a crash, so it
 * needs to answer "is the thing about to execute the thing that was approved?",
 * and that question needs a canonical hash and a record of what has already
 * run.
 *
 * The table is also where the execute-time re-check lives. pi prepares every
 * tool call in a batch before executing any of them, so a call locked before
 * the breaker tripped is already prepared when it trips; blocking cannot
 * un-prepare it. Every operations object pi-enclave owns therefore asks the
 * table again, at the moment it is about to act.
 */
import { canonical, normalizePath } from "../backend/paths.ts";
import type { CanonicalAction } from "../policy/canonical.ts";

export type LockState = "locked" | "executing" | "consumed";

export interface LockEntry {
	action: CanonicalAction;
	toolCallId: string;
	state: LockState;
	/** How many times an operations object has begun work under this entry. */
	executions: number;
	/** Set when the action came back from a pending-approval record. */
	approved?: boolean;
}

export class LockViolation extends Error {
	readonly kind: "not-locked" | "already-consumed" | "breaker-open";

	constructor(kind: LockViolation["kind"], message: string) {
		super(message);
		this.name = "LockViolation";
		this.kind = kind;
	}
}

/**
 * Keys an operations object can look an entry up by.
 *
 * pi's operations interfaces do not all carry the tool-call id -- `BashOperations.exec`
 * gets a command and a cwd and nothing else -- so the table is addressable by
 * what each one *does* have. For `bash` that is the canonical hash of the
 * command it is about to run, which is a stronger check than an id would be: it
 * confirms the command still matches what was gated.
 */
export function executionKeys(action: CanonicalAction): string[] {
	const keys = [`hash:${action.hash}`];
	if (action.tool === "bash") {
		const command = action.input.command;
		if (typeof command === "string") keys.push(`bash:${command}`);
	}
	// Every spelling, because the operations object is handed whatever pi
	// resolved and a guard that missed on formatting alone would refuse an
	// action that was permitted -- a functional break, not a safety one.
	for (const path of action.paths) {
		keys.push(`${action.tool}:${path.raw}`, `${action.tool}:${path.typed}`, `${action.tool}:${path.resolved}`);
	}
	return [...new Set(keys)];
}

export interface LockOptions {
	/** Consulted at execute time, not only at gate time. See the note above. */
	breakerOpen?: () => boolean;
}

export class ActionLock {
	// A key maps to *every* entry registered under it, not one: two identical
	// calls in a batch (same command, same path) canonicalize to the same keys,
	// and a single-value map let the second registration overwrite the first, so
	// one call could execute under the other's entry -- including one carrying an
	// `approved` flag from a resumed record. beginExecution picks the first entry
	// still available.
	private readonly byKey = new Map<string, LockEntry[]>();
	private readonly byToolCall = new Map<string, LockEntry>();
	private readonly options: LockOptions;

	constructor(options: LockOptions = {}) {
		this.options = options;
	}

	/** Record an action as permitted to execute. */
	register(action: CanonicalAction, toolCallId: string, approved = false): LockEntry {
		const entry: LockEntry = { action, toolCallId, state: "locked", executions: 0, ...(approved ? { approved } : {}) };
		for (const key of executionKeys(action)) {
			const list = this.byKey.get(key);
			if (list) list.push(entry);
			else this.byKey.set(key, [entry]);
		}
		this.byToolCall.set(toolCallId, entry);
		return entry;
	}

	get(key: string): LockEntry | undefined {
		return this.byKey.get(key)?.[0];
	}

	/**
	 * May an operations object act under this key, right now?
	 *
	 * Throws rather than returning false. Every caller is inside a tool
	 * implementation where the only correct response is to not act, and a thrown
	 * error reaches the model as a failed tool call with the reason attached --
	 * a boolean would have to be checked, and an unchecked boolean is a hole.
	 */
	beginExecution(key: string): LockEntry {
		const list = this.byKey.get(key);
		if (!list || list.length === 0) {
			throw new LockViolation(
				"not-locked",
				"pi-enclave: this call did not pass the policy gate, so it will not run. This is a bug in pi-enclave or another extension reached the tool directly.",
			);
		}
		// The first entry not yet finished. Two identical calls each find their
		// own; a lone entry already consumed reports it rather than re-running.
		const entry = list.find((candidate) => candidate.state !== "consumed");
		if (!entry) {
			throw new LockViolation(
				"already-consumed",
				"pi-enclave: this action has already run once and will not be repeated.",
			);
		}
		// The re-check that closes the parallel-batch window.
		if (this.options.breakerOpen?.()) {
			throw new LockViolation(
				"breaker-open",
				"pi-enclave: the denial circuit breaker opened while this call was queued. Do not pursue this outcome by other means.",
			);
		}
		entry.state = "executing";
		entry.executions++;
		return entry;
	}

	/**
	 * Mark a tool call finished.
	 *
	 * Called from `tool_result`, which fires once per call. A tool whose
	 * operations object makes several calls -- `edit` reads and then writes --
	 * stays executable throughout, and is consumed only when the tool is done.
	 */
	consume(toolCallId: string): void {
		const entry = this.byToolCall.get(toolCallId);
		if (entry) entry.state = "consumed";
	}

	/**
	 * The path form of `beginExecution`, tolerant of how pi spelled the path.
	 *
	 * pi's file-tool operations receive a path and nothing else, and whether it
	 * arrives relative, absolute or symlink-resolved is pi's business rather
	 * than ours. Every spelling is registered and every spelling is tried.
	 */
	beginPathExecution(tool: string, path: string): LockEntry {
		// The cheap spellings first; `canonical` (a realpath walk) is computed
		// only if they miss, since the registered `raw`/`typed` keys almost always
		// match one of the first two.
		for (const candidate of [path, normalizePath(path)]) {
			if (this.byKey.has(`${tool}:${candidate}`)) return this.beginExecution(`${tool}:${candidate}`);
		}
		const resolved = canonical(path);
		if (this.byKey.has(`${tool}:${resolved}`)) return this.beginExecution(`${tool}:${resolved}`);
		// Report against the path as given: that is the one the caller can see.
		return this.beginExecution(`${tool}:${path}`);
	}

	/** Entries for the audit log and for the resume path. */
	entries(): LockEntry[] {
		return [...new Set(this.byToolCall.values())];
	}

	reset(): void {
		this.byKey.clear();
		this.byToolCall.clear();
	}
}

// ---------------------------------------------------------------------------
// The freeze
// ---------------------------------------------------------------------------

/**
 * Assert a value is plain JSON-like data, then deep-freeze it.
 *
 * Ported from pi-approval-guardian's `tool-input-lock.ts` (MIT). The assertion
 * matters as much as the freeze: `Object.freeze` on an object with an accessor
 * property freezes the accessor, not what it returns, so a getter would sail
 * through a freeze and still hand `execute` a different value on the second
 * read. Anything that is not a plain object, array, string, number, boolean or
 * null is refused.
 */
export function assertJsonLike(value: unknown, path = "input", active = new Set<unknown>()): void {
	if (value === null) return;
	const type = typeof value;
	if (type === "string" || type === "boolean") return;
	if (type === "number") {
		if (!Number.isFinite(value as number)) throw new TypeError(`${path} is not a finite number`);
		return;
	}
	if (type !== "object") throw new TypeError(`${path} is a ${type}, which cannot be locked`);

	if (active.has(value)) throw new TypeError(`${path} is part of a cycle`);
	active.add(value);

	const object = value as object;
	if (Array.isArray(object)) {
		if (Object.getPrototypeOf(object) !== Array.prototype)
			throw new TypeError(`${path} has a non-standard array prototype`);
		for (let i = 0; i < object.length; i++) {
			const descriptor = Object.getOwnPropertyDescriptor(object, String(i));
			// A sparse array's holes read as undefined now and could be filled later.
			if (!descriptor) throw new TypeError(`${path}[${i}] is a hole in a sparse array`);
			if (!("value" in descriptor)) throw new TypeError(`${path}[${i}] is an accessor`);
			assertJsonLike(descriptor.value, `${path}[${i}]`, active);
		}
	} else {
		const prototype = Object.getPrototypeOf(object);
		if (prototype !== Object.prototype && prototype !== null) throw new TypeError(`${path} is not a plain object`);
		if (Object.getOwnPropertySymbols(object).length > 0) throw new TypeError(`${path} has symbol keys`);
		for (const key of Object.getOwnPropertyNames(object)) {
			const descriptor = Object.getOwnPropertyDescriptor(object, key);
			if (!descriptor) continue;
			if (!("value" in descriptor)) throw new TypeError(`${path}.${key} is an accessor`);
			if (!descriptor.enumerable) throw new TypeError(`${path}.${key} is not enumerable`);
			assertJsonLike(descriptor.value, `${path}.${key}`, active);
		}
	}

	active.delete(value);
	Object.freeze(object);
}

/**
 * Freeze the input of a tool-call event and make the property non-writable.
 *
 * Both halves are needed. The deep freeze stops a later handler editing the
 * object; the non-writable property stops one *replacing* it.
 */
export function freezeToolInput(event: { input: unknown }): void {
	const input = event.input;
	assertJsonLike(input);
	const descriptor = Object.getOwnPropertyDescriptor(event, "input");
	Object.defineProperty(event, "input", {
		value: input,
		enumerable: descriptor?.enumerable ?? true,
		writable: false,
		configurable: false,
	});
}
