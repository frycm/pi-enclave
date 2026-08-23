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
 * paths, the parsed command, the working directory, the requested capability,
 * and the profile name. Not the raw argument object -- key order and
 * whitespace would change the hash without changing the action, and an
 * approval that expires because the model re-serialized its JSON differently is
 * an approval nobody will trust. Not the session id either: that is checked
 * separately, so a mismatch can say "approved in a different session" instead
 * of "not the action you approved".
 */
import { createHash } from "node:crypto";
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
			// Redirect targets are writes by construction; `<` is a read.
			for (const redirect of command.redirects) addPath(redirect.target, redirect.writes);
			// Every path-shaped argument counts as a write unless the command is
			// one we can say otherwise about. "Unknown means mutating" is the rule
			// the README states for the read-only classifier and it applies here
			// too: the cost of being wrong is an escalation, and the cost of the
			// opposite is a silent write to a protected path.
			for (const arg of command.args) {
				for (const candidate of pathCandidatesInToken(arg)) addPath(candidate, !READ_ONLY_COMMANDS.has(command.name));
			}
		}
	} else {
		const keys = PATH_KEYS[tool] ?? ["path"];
		for (const key of keys) {
			const value = input[key];
			if (typeof value === "string") addPath(value, WRITING_TOOLS.has(tool));
		}
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
	for (const [key, kind] of [
		["allow_write", "write"],
		["allow_read", "read"],
		["allow_host", "host"],
	] as const) {
		const value = input[key];
		if (typeof value === "string" && value.trim() !== "") return { kind, value: value.trim() };
	}
	return undefined;
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
		name: command.name,
		args: command.args,
		assignments: command.assignments,
		redirects: command.redirects.map((redirect) => ({ op: redirect.op, target: redirect.target })),
	}));
	return JSON.stringify({
		v: 1,
		tool: action.tool,
		cwd: action.cwd,
		profile: action.profileName,
		// Sorted so that two spellings of the same set hash alike; the order the
		// tokenizer happened to find them in is not part of the action.
		paths: [...action.paths]
			.map((path) => ({ resolved: path.resolved, writes: path.writes }))
			.sort((a, b) => (a.resolved < b.resolved ? -1 : a.resolved > b.resolved ? 1 : 0)),
		commands: commands ?? null,
		// For tools with no shell and no path, the input itself is the action, so
		// it is included with its keys sorted.
		input: commands || action.paths.length > 0 ? null : stableInput(action.input),
		capability: action.capability ?? null,
	});
}

function stableInput(input: Record<string, unknown>): unknown {
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

export function hashAction(action: Omit<CanonicalAction, "hash">): string {
	return `sha256:${createHash("sha256").update(canonicalForm(action)).digest("hex")}`;
}

/**
 * A one-line rendering for a confirm dialog and for the audit log.
 *
 * The canonical form, never the raw string: a command with an embedded newline
 * would otherwise be able to hide a second command below the fold of a dialog
 * whose first line looked harmless.
 */
export function describeAction(action: CanonicalAction): string {
	if (action.shell) {
		const lines = action.shell.commands.map((command) => `    ${[command.name, ...command.args].join(" ")}`);
		const head = [`${action.tool} in ${action.cwd}`, ...lines];
		if (!action.confident) head.push(`    (parse is not confident: ${action.shell.markers.join(", ")})`);
		if (action.capability) head.push(`    requests ${action.capability.kind} access to ${action.capability.value}`);
		return head.join("\n");
	}
	const targets = action.paths.map((path) => `    ${path.writes ? "writes" : "reads"} ${path.resolved}`);
	return [`${action.tool} in ${action.cwd}`, ...targets].join("\n");
}
