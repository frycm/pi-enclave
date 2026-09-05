import type { ReviewTrigger } from "../config/types.ts";
import type { ToolDisposition } from "../gate/tools.ts";
import type { CanonicalAction } from "../policy/canonical.ts";
import type { SimpleCommand } from "../policy/shell.ts";
import type { ReviewerTrigger } from "./types.ts";

export interface Classification {
	readOnly: boolean;
	reason: string;
}

const SIMPLE_READERS = new Set([
	"basename",
	"cat",
	"dirname",
	"file",
	"grep",
	"head",
	"jq",
	"ls",
	"pwd",
	"readlink",
	"realpath",
	"rg",
	"stat",
	"tail",
	"wc",
]);

const FIND_EFFECT_FLAGS = ["-delete", "-exec", "-execdir", "-ok", "-okdir", "-fls", "-fprint", "-fprint0", "-fprintf"];
const GH_EFFECT_FLAGS = ["-X", "--method", "--input", "-w", "--web"];
const FILE_EFFECT_FLAGS = ["-C", "--compile"];
const RG_EFFECT_FLAGS = ["--pre", "--hostname-bin"];
const GIT_EFFECT_FLAGS = [
	"--exec-path",
	"--config-env",
	"--upload-pack",
	"--receive-pack",
	"--ext-diff",
	"--textconv",
	"--output",
];

function baseName(value: string): string {
	return value.slice(value.lastIndexOf("/") + 1).toLowerCase();
}

function hasFlag(args: readonly string[], flags: readonly string[]): boolean {
	return args.some((arg) =>
		flags.some(
			(flag) =>
				arg === flag ||
				arg.startsWith(`${flag}=`) ||
				(flag.length === 2 && /^-[^-]/.test(arg) && arg.slice(1).includes(flag[1] as string)),
		),
	);
}

function fileReadOnly(args: readonly string[]): boolean {
	// Positive syntax only. Unknown options/abbreviations and short clusters
	// containing -C must not turn a magic database compilation into a read.
	for (let i = 0; i < args.length; i++) {
		const arg = args[i] as string;
		if (arg === "--") return true;
		if (!arg.startsWith("-") || arg === "-") continue;
		if (
			[
				"--brief",
				"--mime",
				"--mime-type",
				"--mime-encoding",
				"--dereference",
				"--no-dereference",
				"--version",
				"--help",
			].includes(arg)
		)
			continue;
		if (arg === "-m" || arg === "--magic-file") {
			if (!args[++i]) return false;
			continue;
		}
		if (/^-[bikLNnprszh0]+$/.test(arg)) continue;
		return false;
	}
	return true;
}

function gitReadOnly(command: SimpleCommand): boolean {
	if (hasFlag(command.args, GIT_EFFECT_FLAGS)) return false;
	const [subcommand, ...rest] = command.args;
	if (!subcommand || subcommand.startsWith("-")) return false;
	// These may execute configured fsmonitor/diff/textconv programs. The
	// sandbox bounds them, but their subcommand name cannot bypass review.
	if (["status", "log", "diff", "show"].includes(subcommand)) return false;
	if (subcommand === "branch") return rest[0] === "--list" && rest.slice(1).every((arg) => !arg.startsWith("-"));
	if (subcommand === "remote") return rest.length === 1 && rest[0] === "-v";
	return false;
}

function ghReadOnly(command: SimpleCommand): boolean {
	if (hasFlag(command.args, GH_EFFECT_FLAGS)) return false;
	const [group, operation] = command.args;
	if (!group || !operation || !["pr", "issue", "repo"].includes(group)) return false;
	return ["view", "list", "status"].includes(operation);
}

function simpleCommandReadOnly(command: SimpleCommand): boolean {
	if (!command.name || command.assignments.length > 0 || command.redirects.length > 0) return false;
	// Only an unqualified command can resolve through the filtered, immutable
	// host PATH. `./cat` or `/workspace/bin/git` is repository-controlled code,
	// regardless of its basename.
	if (command.name.includes("/")) return false;
	const name = baseName(command.name);
	if (name === "file") return fileReadOnly(command.args);
	if (name === "rg") return !hasFlag(command.args, RG_EFFECT_FLAGS);
	if (SIMPLE_READERS.has(name)) return true;
	if (name === "git") return gitReadOnly(command);
	if (name === "gh") return ghReadOnly(command);
	if (name === "find") return !hasFlag(command.args, FIND_EFFECT_FLAGS);
	return false;
}

export function classifyReadOnly(action: CanonicalAction, disposition: ToolDisposition): Classification {
	if (!disposition.allowed) return { readOnly: false, reason: "the tool is not allowed" };
	if (action.capability) return { readOnly: false, reason: "a capability request crosses the sandbox boundary" };
	if (action.tool !== "bash") {
		return disposition.readOnly
			? { readOnly: true, reason: `tools.allow marks ${action.tool} read-only` }
			: { readOnly: false, reason: `tools.allow does not mark ${action.tool} read-only` };
	}
	if (!action.shell || !action.confident) {
		return { readOnly: false, reason: "the shell parse is not confident" };
	}
	if (action.shell.commands.length === 0) return { readOnly: false, reason: "the command is empty" };
	for (const command of action.shell.commands) {
		if (!simpleCommandReadOnly(command)) {
			return { readOnly: false, reason: `shell command is not in the read-only table: ${command.syntax}` };
		}
	}
	return { readOnly: true, reason: "every simple command matches the read-only table" };
}

export function reviewerTrigger(
	configured: ReviewTrigger,
	action: CanonicalAction,
	disposition: ToolDisposition,
): ReviewerTrigger | undefined {
	if (action.capability) return "capability";
	if (configured === "boundary") return undefined;
	if (configured === "all") return "all";
	return classifyReadOnly(action, disposition).readOnly ? undefined : "mutating";
}

export const READ_ONLY_CLASSIFIER = {
	simple: [...SIMPLE_READERS],
	git: ["branch --list", "remote -v"],
	gitConfiguredPrograms: ["status", "log", "diff", "show"],
	gitForbidden: GIT_EFFECT_FLAGS,
	gh: ["pr view|list|status", "issue view|list|status", "repo view|list|status"],
	ghForbidden: GH_EFFECT_FLAGS,
	findForbidden: FIND_EFFECT_FLAGS,
	fileForbidden: FILE_EFFECT_FLAGS,
	ripgrepForbidden: RG_EFFECT_FLAGS,
	pathQualifiedExecutables: "mutating",
} as const;
