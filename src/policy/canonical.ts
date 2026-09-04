/**
 * The canonical action.
 *
 * One object, produced once per tool call, that every layer above L2 reads: L1
 * matches patterns against it, the lock hashes it, the audit log records it,
 * the pending-approval record persists it, and Phase 3 will send it to the
 * reviewer. Its shape is therefore fixed here and exported rather than being an
 * internal of the gate.
 *
 * Neither reference extension has one. Guardian hands the reviewer the raw
 * command string and freezes `event.input` in place; automode matches patterns
 * against a "primary argument" derived on the fly. Both work for what they do,
 * and neither can answer "is the thing about to execute the same thing that was
 * approved?", which is the question a pending approval record exists to
 * survive. That question needs a canonical form and a hash over it, so this
 * module is new rather than ported.
 *
 * **What the hash covers, and why each part is in it.** The tool, the resolved
 * paths, parsed command, working directory, requested capability, profile name,
 * and the complete tool input in its executor-observable property order. Semantic projections aid
 * policy and display; they never replace the executor-consumed input in the
 * identity. The session id is checked separately so a mismatch can retain a
 * useful diagnosis.
 */
import { createHash } from "node:crypto";
import { redact } from "../state/redact.ts";
import { normalizeInputPath, pathCandidatesInToken, resolveForPolicy } from "./paths.ts";
import { type ParsedShell, parseShell } from "./shell.ts";

/** A path the action touches, in every spelling policy needs. */
export interface ActionPath {
	/** Exactly as it appeared in the tool input, before any normalization. */
	raw: string;
	/** Absolute, after `~`/`file://`/`@` normalization. */
	typed: string;
	/** Symlinks followed as far as they exist. */
	resolved: string;
	/** Relative to the workspace, when it is inside it. */
	relative?: string;
	/** Whether the action writes here. Reads are not escalated by protectedPaths. */
	writes: boolean;
}

/**
 * A one-shot widening the agent asked for.
 *
 * In deterministic mode this is an `ask`, not a reviewer call: attended gets a
 * confirm, unattended gets a pending record. `read` and `host` are parsed and
 * refused with a clear message rather than being silently ignored, because an
 * agent that asks for one and gets no answer will keep asking.
 */
export interface Capability {
	kind: "write" | "read" | "host";
	value: string;
}

export interface CanonicalAction {
	tool: string;
	/** The tool input, exactly as it will execute. Frozen by the lock. */
	input: Record<string, unknown>;
	cwd: string;
	/** Present for `bash`. */
	shell?: ParsedShell;
	paths: ActionPath[];
	capability?: Capability;
	/** The profile this was canonicalized under. Part of the hash. */
	profileName: string;
	/** `sha256:…` over the stable serialization below. */
	hash: string;
	/**
	 * False when the shell tokenizer met something it could not follow. Callers
	 * must treat a non-confident action as mutating and as matching every `ask`
	 * rule for its tool.
	 */
	confident: boolean;
}

export interface CanonicalizeOptions {
	tool: string;
	input: Record<string, unknown>;
	cwd: string;
	home: string;
	profileName: string;
	/** Absolute paths the sandbox permits writing. Used to classify shell targets. */
	writableRoots?: readonly string[];
}

/** Tools whose path argument is written to rather than read. */
const WRITING_TOOLS = new Set(["write", "edit"]);
/** Where each built-in tool keeps its path. */
const PATH_KEYS: Record<string, string[]> = {
	read: ["path", "filePath", "file_path"],
	write: ["path", "filePath", "file_path"],
	edit: ["path", "filePath", "file_path"],
	ls: ["path", "dirPath", "directory"],
	find: ["path", "dirPath", "directory"],
	grep: ["path", "dirPath", "directory"],
};

export function canonicalize(options: CanonicalizeOptions): CanonicalAction {
	const { tool, input, cwd, home, profileName } = options;
	const paths: ActionPath[] = [];
	const addPath = (raw: string, writes: boolean) => {
		const normalized = normalizeInputPath(raw, home);
		if (normalized === "") return;
		const { typed, resolved } = resolveForPolicy(normalized, cwd);
		const existing = paths.find((entry) => entry.typed === typed);
		if (existing) {
			// A path that is both read and written is a write: that is the reading
			// that escalates, and `edit` does both to the same file.
			existing.writes ||= writes;
			return;
		}
		const relative = typed.startsWith(`${cwd}/`) ? typed.slice(cwd.length + 1) : undefined;
		paths.push({ raw, typed, resolved, writes, ...(relative !== undefined ? { relative } : {}) });
	};

	let shell: ParsedShell | undefined;

	if (tool === "bash" && typeof input.command === "string") {
		shell = parseShell(input.command);
		for (const command of shell.commands) {
			const commandName = command.name.slice(command.name.lastIndexOf("/") + 1);
			// Redirect targets are writes by construction; `<` is a read.
			for (const redirect of command.redirects) addPath(redirect.target, redirect.writes);
			// Every path-shaped argument counts as a write unless the command is
			// one we can say otherwise about. "Unknown means mutating" is the rule
			// the README states for the read-only classifier and it applies here
			// too: the cost of being wrong is an escalation, and the cost of the
			// opposite is a silent write to a protected path.
			const writes = !READ_ONLY_COMMANDS.has(commandName);
			// dd names its files with `of=`/`if=` operand assignments, which the
			// `NAME=value` filter below would otherwise skip -- so `dd
			// of=authorized_keys` recorded no write to its target. Handled
			// explicitly: `of=` is a write, `if=` a read.
			if (commandName === "dd") {
				for (const arg of command.args) {
					const of = /^of=(.+)$/.exec(arg);
					if (of?.[1]) addPath(of[1], true);
					const inf = /^if=(.+)$/.exec(arg);
					if (inf?.[1]) addPath(inf[1], false);
				}
			}
			for (const arg of command.args) {
				const candidates = pathCandidatesInToken(arg);
				if (candidates.length > 0) {
					// Includes the `/path` of a `--flag=/path`, which is why every
					// token is offered here before the bare-filename fallback below.
					for (const candidate of candidates) addPath(candidate, writes);
				} else if (
					WRITER_COMMANDS.has(commandName) &&
					arg !== "" &&
					!arg.startsWith("-") &&
					!/^[A-Za-z_][A-Za-z0-9_]*=/.test(arg)
				) {
					// A bare filename in the working directory (no slash) is still a
					// possible protected-path target: `tee authorized_keys` writes the
					// same file as `tee ./authorized_keys`. Scoped to commands whose
					// operands are files, so a commit message word or a subcommand is
					// not resolved as a path; a matched name resolves to cwd/<name>
					// and hits only the specific protected globs.
					addPath(arg, true);
				}
			}
		}
	} else {
		// Unknown tools execute in another extension's privileged code. A `path`
		// field is not evidence that the operation is a read; only owned tools with
		// a known schema receive semantic path classification.
		const keys = PATH_KEYS[tool] ?? [];
		for (const key of keys) {
			const value = input[key];
			if (typeof value === "string") addPath(value, WRITING_TOOLS.has(tool));
		}
		// `ls` and `find` default their path to the working directory when it is
		// omitted, and pi resolves that default itself. Recording it keeps the
		// lock key in step with the operation the guard will actually run -- the
		// bare `ls` / whole-workspace `find` are the most common calls, and
		// without this they registered no path key and were refused at execute
		// time as if they had bypassed the gate.
		if ((tool === "ls" || tool === "find") && paths.length === 0) addPath(".", false);
	}

	const capability = readCapability(input);
	const confident = shell ? shell.confident : true;

	const action: CanonicalAction = {
		tool,
		input,
		cwd,
		paths,
		profileName,
		confident,
		hash: "",
		...(shell ? { shell } : {}),
		...(capability ? { capability } : {}),
	};
	action.hash = hashAction(action);
	return action;
}

/**
 * Commands whose bare (slash-free) operands are *all* file targets.
 *
 * Only for these does a bare filename argument get recorded as a path, so an
 * ordinary word (a commit message, a subcommand) is not resolved as one. Every
 * operand here is a file, so recording each is right. Deliberately excluded:
 * `chmod`/`chown` (leading operand is a mode/owner), `sed` (a script), and `dd`
 * (targets are `of=`/`if=` assignments) -- their non-file leading operands would
 * be resolved as spurious write paths. A slash-bearing path is still caught for
 * every command by pathCandidatesInToken, and redirect targets always are.
 */
const WRITER_COMMANDS = new Set(["tee", "cp", "mv", "install", "ln", "touch", "truncate", "rm", "rmdir", "mkdir"]);

/**
 * Commands whose path arguments are reads.
 *
 * Short and conservative. This list only decides whether a path is recorded as
 * a *write* -- which is what `protectedPaths` escalates on -- so an omission
 * costs an unnecessary confirm and an over-inclusion skips one. Anything whose
 * subcommands or flags can turn it into a mutation (`git`, `find`, `sed`) is
 * absent rather than special-cased, because the special case is where the
 * mistake would live.
 */
const READ_ONLY_COMMANDS = new Set([
	"cat",
	"head",
	"tail",
	"less",
	"more",
	"wc",
	"file",
	"stat",
	"ls",
	"grep",
	"rg",
	"diff",
]);

/**
 * A capability request carried on the tool input.
 *
 * The agent is told to retry with `allow_write="/path"` in the violation hint,
 * so that is the spelling read here. It is part of the hash: an approval for
 * `allow_write=/Users/m/.zshrc` must not be replayable for
 * `allow_write=/Users/m/.ssh/authorized_keys`.
 */
function readCapability(input: Record<string, unknown>): Capability | undefined {
	const found: Capability[] = [];
	for (const [key, kind] of [
		["allow_write", "write"],
		["allow_read", "read"],
		["allow_host", "host"],
	] as const) {
		const value = input[key];
		if (typeof value === "string" && value.trim() !== "") found.push({ kind, value: value.trim() });
	}
	if (found.length > 1) throw new Error("an action may request exactly one capability");
	return found[0];
}

/**
 * The stable serialization the hash is taken over.
 *
 * Exported because a hash whose input cannot be inspected is a hash nobody can
 * debug, and because the pending-record resume path re-derives it and needs to
 * be able to show what differed.
 */
export function canonicalForm(action: Omit<CanonicalAction, "hash">): string {
	const commands = action.shell?.commands.map((command) => ({
		// The connector is bound too: `false && sudo id` and `false || sudo id`
		// are different actions and must not share a hash.
		connector: command.connector ?? null,
		name: command.name,
		args: command.args,
		assignments: command.assignments,
		redirects: command.redirects.map((redirect) => ({ op: redirect.op, target: redirect.target })),
		// Quote context changes shell expansion (`*` versus `"*"`) even when
		// name/args are otherwise identical. The normalized syntax keeps that
		// distinction while still ignoring harmless whitespace runs.
		syntax: command.syntax,
	}));
	return stableSerialize({
		v: 4,
		tool: action.tool,
		cwd: action.cwd,
		profile: action.profileName,
		// Sorted so that two spellings of the same set hash alike; the order the
		// tokenizer happened to find them in is not part of the action.
		paths: [...action.paths]
			.map((path) => ({ resolved: path.resolved, writes: path.writes }))
			.sort((a, b) => (a.resolved < b.resolved ? -1 : a.resolved > b.resolved ? 1 : 0)),
		commands: commands ?? null,
		// The execution-affecting fields the command/paths projection does not
		// already capture -- the write/edit body above all. Without this a `write`
		// of "SAFE" and a `write` of "EVIL" to the same path hashed identically,
		// so a pending approval could be replayed with different contents. The raw
		// command string and path are excluded (they are captured, normalised,
		// above); only body-bearing keys are bound here.
		body: bodyFields(action.input),
		// Always bind the complete executor-consumed input. The normalized fields
		// above are additional policy projections, never a lossy replacement.
		// Preserve the executor-observable property order inside a string. The
		// surrounding canonical object remains key-sorted, but two custom tools
		// that iterate differently ordered inputs must never share an approval.
		input: executionSerialize(action.input),
		capability: action.capability ?? null,
	});
}

/** Keys whose values change what a write/edit does but are not the path. */
const BODY_KEYS = [
	"content",
	"edits",
	"newContent",
	"new_string",
	"newString",
	"oldContent",
	"old_string",
	"oldString",
];

/** The body-bearing input fields, sorted, or null when there are none. */
function bodyFields(input: Record<string, unknown>): Record<string, unknown> | null {
	const out: Record<string, unknown> = {};
	for (const key of [...BODY_KEYS].sort()) {
		if (Object.hasOwn(input, key)) out[key] = stableInput(input[key]);
	}
	return Object.keys(out).length > 0 ? out : null;
}

function stableInput(input: unknown): unknown {
	const sort = (value: unknown): unknown => {
		if (Array.isArray(value)) return value.map(sort);
		if (value && typeof value === "object") {
			return Object.fromEntries(
				Object.entries(value as Record<string, unknown>)
					.sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
					.map(([key, entry]) => [key, sort(entry)]),
			);
		}
		return value;
	};
	return sort(input);
}

/**
 * Stable, injective serialization for the JSON-like values accepted by the
 * action lock. Native JSON.stringify collapses the distinct JavaScript values
 * `-0` and `0`, even though a tool can distinguish them with Object.is.
 */
export function stableSerialize(value: unknown): string {
	if (value === null) return "null";
	if (typeof value === "string") return JSON.stringify(value);
	if (typeof value === "boolean") return value ? "true" : "false";
	if (typeof value === "number") {
		if (!Number.isFinite(value)) throw new TypeError("cannot serialize a non-finite number");
		return Object.is(value, -0) ? "-0" : String(value);
	}
	if (Array.isArray(value)) return `[${value.map(stableSerialize).join(",")}]`;
	if (value && typeof value === "object") {
		return `{${Object.entries(value as Record<string, unknown>)
			.sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
			.map(([key, entry]) => `${JSON.stringify(key)}:${stableSerialize(entry)}`)
			.join(",")}}`;
	}
	throw new TypeError(`cannot serialize ${typeof value}`);
}

/**
 * Injective serialization that preserves JavaScript's observable property order.
 *
 * This is used wherever a value will be reviewed, hashed as executor input, or
 * persisted for later execution. Sorting object keys there changes semantics for
 * tools that iterate their input, so only structural/profile data uses the stable
 * key-sorted serializer above.
 */
export function executionSerialize(value: unknown): string {
	if (value === null) return "null";
	if (typeof value === "string") return JSON.stringify(value);
	if (typeof value === "boolean") return value ? "true" : "false";
	if (typeof value === "number") {
		if (!Number.isFinite(value)) throw new TypeError("cannot serialize a non-finite number");
		return Object.is(value, -0) ? "-0" : String(value);
	}
	if (Array.isArray(value)) return `[${value.map(executionSerialize).join(",")}]`;
	if (value && typeof value === "object") {
		return `{${Object.entries(value as Record<string, unknown>)
			.map(([key, entry]) => `${JSON.stringify(key)}:${executionSerialize(entry)}`)
			.join(",")}}`;
	}
	throw new TypeError(`cannot serialize ${typeof value}`);
}

/**
 * The exact stable value in an ASCII-only form suitable for an authorization UI.
 *
 * JSON escaping already distinguishes a literal `\\u202e` from U+202E. Escaping
 * every remaining non-ASCII code point keeps bidi, zero-width and terminal-
 * dependent formatting characters inert without changing the value that is
 * hashed or executed.
 */
export function approvalSerialize(value: unknown): string {
	return executionSerialize(value).replace(/[^\x20-\x7e]/gu, (character) => {
		const point = character.codePointAt(0);
		if (point === undefined) throw new TypeError("cannot render an empty code point");
		return point <= 0xffff ? `\\u${point.toString(16).padStart(4, "0")}` : `\\u{${point.toString(16)}}`;
	});
}

export function hashAction(action: Omit<CanonicalAction, "hash">): string {
	return `sha256:${createHash("sha256").update(canonicalForm(action)).digest("hex")}`;
}

/**
 * A bounded rendering for agent-facing diagnostics and audit-adjacent output.
 *
 * The canonical form, never the raw string: a command with an embedded newline
 * would otherwise be able to hide a second command below the fold of a dialog
 * whose first line looked harmless.
 */
export function describeAction(action: CanonicalAction): string {
	const head = [`${action.tool} in ${action.cwd}`];

	if (action.shell) {
		for (const command of action.shell.commands) {
			// The quote-preserving syntax keeps expansion semantics visible while
			// normalizeShellSyntax makes it safe to render on one line.
			const prefix = command.connector ? `${command.connector} ` : "";
			head.push(`    ${prefix}${command.syntax}`);
		}
		if (!action.confident) head.push(`    (parse is not confident: ${action.shell.markers.join(", ")})`);
	} else {
		for (const path of action.paths) head.push(`    ${path.writes ? "writes" : "reads"} ${path.resolved}`);
		// Body semantics remain visible without disclosing an unlimited value to
		// agent-facing diagnostics. Direct approval uses the exact renderer below.
		if (WRITING_TOOLS.has(action.tool)) {
			for (const [label, value] of bodyPreviews(action.input)) head.push(`    ${label}: ${value}`);
		}
	}
	for (const [label, value] of additionalInputPreviews(action)) head.push(`    input.${label}: ${value}`);

	if (action.capability) head.push(`    requests ${action.capability.kind} access to ${action.capability.value}`);
	return head.join("\n");
}

/**
 * Full-fidelity evidence for the direct human authorization boundary.
 *
 * This is intentionally separate from {@link describeAction}: denial messages
 * and audit-adjacent diagnostics may redact or bound untrusted values, while a
 * person deciding whether the original input may execute must see all of it.
 */
export function describeActionForApproval(action: CanonicalAction): string {
	const lines = [
		`tool: ${approvalSerialize(action.tool)}`,
		`cwd: ${approvalSerialize(action.cwd)}`,
		`profile: ${approvalSerialize(action.profileName)}`,
		`input: ${approvalSerialize(action.input)}`,
	];
	for (const path of action.paths) {
		lines.push(`${path.writes ? "writes" : "reads"}: ${approvalSerialize(path.resolved)}`);
	}
	if (action.capability) {
		lines.push(`capability: ${approvalSerialize({ kind: action.capability.kind, value: action.capability.value })}`);
	}
	lines.push(`hash: ${action.hash}`);
	return lines.join("\n");
}

/**
 * Every input field not already represented by the semantic rendering.
 *
 * Top-level names are never truncated, so a privileged third-party `mode` or
 * `force` flag cannot disappear from a confirmation. Values are redacted and
 * bounded, with the full stable value bound by a digest.
 */
function additionalInputPreviews(action: CanonicalAction): [string, string][] {
	const represented = new Set<string>();
	if (WRITING_TOOLS.has(action.tool)) for (const key of BODY_KEYS) represented.add(key);
	if (action.shell) represented.add("command");
	else for (const key of PATH_KEYS[action.tool] ?? []) represented.add(key);
	if (action.capability) represented.add(`allow_${action.capability.kind}`);
	return inputFieldPreviews(action.input, represented);
}

/** Render every leaf field; nesting must not hide a privileged mode/force flag. */
export function inputFieldPreviews(
	input: Record<string, unknown>,
	represented: ReadonlySet<string> = new Set(),
): [string, string][] {
	const out: [string, string][] = [];
	const render = (label: string, leafKey: string, value: unknown) => {
		if (Array.isArray(value)) {
			if (value.length === 0) push(label, leafKey, value);
			else {
				value.forEach((entry, index) => {
					render(`${label}[${index}]`, leafKey, entry);
				});
			}
			return;
		}
		if (value && typeof value === "object") {
			const entries = Object.entries(value as Record<string, unknown>).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
			if (entries.length === 0) push(label, leafKey, value);
			else {
				for (const [key, entry] of entries) {
					const displayed = displayInputKey(key);
					const child = displayed.startsWith('"') ? `${label}[${displayed}]` : `${label}.${displayed}`;
					render(child, key, entry);
				}
			}
			return;
		}
		push(label, leafKey, value);
	};
	const push = (label: string, leafKey: string, value: unknown) => {
		const stable = stableInput(value);
		const serialized = stableSerialize(stable);
		const visible = approvalSerialize(redact(value, {}, leafKey));
		const preview = visible.length > 240 ? `${visible.slice(0, 120)}…${visible.slice(-120)}` : visible;
		const digest = createHash("sha256").update(serialized).digest("hex");
		out.push([label, `${preview} (${serialized.length} serialized chars, sha256:${digest})`]);
	};

	for (const key of Object.keys(input).sort()) {
		if (!represented.has(key)) render(displayInputKey(key), key, input[key]);
	}
	return out;
}

/** Keep ordinary field names readable while escaping attacker-chosen controls. */
export function displayInputKey(key: string): string {
	return /^[A-Za-z_][A-Za-z0-9_-]*$/.test(key) ? key : approvalSerialize(key);
}

/** Bounded previews of write/edit body fields for non-authoritative diagnostics. */
function bodyPreviews(input: Record<string, unknown>): [string, string][] {
	const out: [string, string][] = [];
	for (const key of BODY_KEYS) {
		if (!Object.hasOwn(input, key)) continue;
		const serialized = stableSerialize(stableInput(input[key]));
		const visible = approvalSerialize(redact(input[key], {}, key));
		const preview = visible.length > 200 ? `${visible.slice(0, 100)}…${visible.slice(-100)}` : visible;
		const digest = createHash("sha256").update(serialized).digest("hex");
		out.push([key, `${preview} (${serialized.length} serialized chars, sha256:${digest})`]);
	}
	return out;
}
