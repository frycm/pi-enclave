/**
 * A shell tokenizer good enough to match rules against, and honest about when
 * it is not.
 *
 * This is a heuristic, and it has to be: a real shell grammar is a parser
 * project of its own, and the README already records tree-sitter-bash as the v2
 * answer. What matters is that the heuristic never *quietly* misreads a
 * command. Every construct it cannot follow -- command substitution, process
 * substitution, `eval`, a heredoc, an unbalanced quote -- is recorded as a
 * marker and clears the `confident` flag, and the gate treats a non-confident
 * parse as matching every `ask` rule for the tool. Being loudly unsure is the
 * only safe failure mode for a component that decides what a pattern applies
 * to.
 *
 * It splits further than automode's does in one respect that matters: `deny`
 * patterns are matched against **each simple command**, so `bash(rm -rf *)`
 * catches `echo ok && rm -rf /` rather than only a command that starts with
 * `rm`. Matching the raw string was the alternative, and it is the reason a
 * pipeline is the standard way past a command allowlist.
 */

import { posix } from "node:path";

/** Something the tokenizer saw but cannot follow. Each one clears `confident`. */
export type ShellMarker =
	| "command-substitution"
	| "process-substitution"
	| "backtick"
	| "heredoc"
	| "unbalanced-quote"
	| "eval"
	| "shell-c"
	| "xargs"
	| "wrapper"
	| "param-expansion"
	| "cwd-change"
	| "interpreter"
	| "source-script"
	| "script-runner"
	| "workspace-executable"
	| "command-dispatch"
	| "archive-extract"
	| "environment-assignment"
	| "pathname-expansion"
	| "subshell"
	| "compound"
	| "clobber"
	| "unaccounted-line"
	| "unusual-whitespace"
	| "shell-state"
	| "unknown-command";

export interface Redirect {
	/** The operator as written: `>`, `>>`, `2>`, `&>`, `<`, `<>`. */
	op: string;
	target: string;
	/** False for `<`, which reads rather than writes. */
	writes: boolean;
}

export interface SimpleCommand {
	/** The segment as written, trimmed. Kept for diagnostics and audit records. */
	text: string;
	/** One-line, whitespace-normalized syntax with quotes and escapes preserved. */
	syntax: string;
	/** The command name, after any `VAR=value` prefixes. Empty for a bare assignment. */
	name: string;
	/** Arguments, quotes removed. */
	args: string[];
	/** `VAR=value` prefixes, in order. */
	assignments: string[];
	redirects: Redirect[];
	/**
	 * The operator that joined this command to the one before it (`&&`, `||`,
	 * `|`, `;`, `&`, or a newline), or undefined for the first. Part of the
	 * canonical hash: `false && x` and `false || x` are different actions.
	 */
	connector?: string;
}

export interface ParsedShell {
	/** Every simple command, in order. A pipeline contributes each of its members. */
	commands: SimpleCommand[];
	/**
	 * False when the tokenizer met something it cannot follow.
	 *
	 * A rule engine reading a non-confident parse is reading a guess. The gate's
	 * response is to escalate rather than to trust it.
	 */
	confident: boolean;
	markers: ShellMarker[];
}

const SEPARATORS = new Set([";", "\n", "|", "&"]);

/** Commands whose arguments are another command the tokenizer will not see. */
const OPAQUE_COMMANDS: Record<string, ShellMarker> = {
	eval: "eval",
	trap: "command-dispatch",
	xargs: "xargs",
	sh: "shell-c",
	bash: "shell-c",
	zsh: "shell-c",
	dash: "shell-c",
	ksh: "shell-c",
	ash: "shell-c",
	csh: "shell-c",
	tcsh: "shell-c",
	fish: "shell-c",
};

/**
 * Commands that run *another* command given as their arguments.
 *
 * `env rm -rf /` and `bash(rm -rf *)` share no prefix, so a rule anchored on the
 * inner command never fires and the parse otherwise looks ordinary. Rather than
 * unwrap these -- which would mean parsing each wrapper's own options and
 * getting a single one wrong is a bypass -- a wrapper with a real argument is
 * marked non-confident, so the gate escalates it to a person. This over-asks for
 * `timeout 30 npm test`, which is the safe direction the module already takes
 * for everything it cannot read with confidence.
 *
 * The `-c` shells are handled by OPAQUE_COMMANDS; `sudo`/`su`/`doas` are denied
 * outright by `rules.deny`, so they are not repeated here.
 */
const WRAPPER_COMMANDS = new Set([
	"env",
	"nohup",
	"nice",
	"ionice",
	"chrt",
	"timeout",
	"stdbuf",
	"setsid",
	"command",
	"builtin",
	"enable",
	"exec",
	"time",
	"watch",
	"nice",
]);

/**
 * Programs that run another command taken from their arguments or options.
 *
 * Unlike the wrappers above, they are marked even with no argument, since several
 * read commands from stdin. Examples: `flock l git
 * push`, `strace -f rm -rf src`, `vim -es -c '!rm -rf src'`, `man -P 'cmd' ls`,
 * `ssh host cmd`, `rsync -e 'sh -c …'`. Unwrapping them would mean modelling
 * each program's option grammar, and a single mistake there is a bypass.
 */
const LAUNCHER_COMMANDS = new Set([
	"coproc",
	"flock",
	"strace",
	"ltrace",
	"script",
	"parallel",
	"unshare",
	"nsenter",
	"chroot",
	"ssh",
	"scp",
	"sftp",
	"rsync",
	"vim",
	"vi",
	"nvim",
	"view",
	"ex",
	"ed",
	"emacs",
	"nano",
	"less",
	"more",
	"most",
	"man",
	"gdb",
	"lldb",
	"fc",
	// Denied outright by `rules.deny`; listed so the parse is not confident either.
	"sudo",
	"su",
	"doas",
]);

/**
 * Builtins that change what a later command in the same script means.
 *
 * `hash -p /usr/bin/rm ls` and `shopt -s expand_aliases; alias ls='rm -rf'`
 * make a later `ls` run `rm`, and `export`/`declare` change the environment
 * every later command inherits. The tokenizer reads each command name
 * literally, so a script that uses one of these is not confident. `set` is
 * handled separately: its common error-handling options are harmless.
 */
const SHELL_STATE_BUILTINS = new Set([
	"hash",
	"alias",
	"unalias",
	"shopt",
	"export",
	"declare",
	"typeset",
	"readonly",
	"local",
	"unset",
]);

/** `set` options that only change error handling or tracing, never what a name runs. */
const HARMLESS_SET_ARG = /^(?:[-+][euxvo]+|pipefail|errexit|nounset|xtrace|verbose|--)$/;

/**
 * Commands whose argv the tokenizer understands: they do not run another
 * command taken from their arguments, and what they touch is named in argv.
 *
 * Confidence is an allowlist. A command name that is not here and not
 * classified by one of the tables above (interpreters, script runners,
 * wrappers, launchers, opaque commands, keywords) is `unknown-command`, because
 * an unlisted program may launch another one from its options and the
 * tokenizer cannot tell. Entries with options that do run a command (`sort
 * --compress-program`, `tar --to-command`, `rg --pre`, several `git`
 * subcommands) are checked separately below.
 */
const KNOWN_COMMANDS = new Set([
	// Shell builtins and utilities with no hidden effect.
	":",
	"[",
	"[[",
	"echo",
	"printf",
	"true",
	"false",
	"test",
	"pwd",
	"sleep",
	"wait",
	"jobs",
	"read",
	"shift",
	"exit",
	"return",
	"break",
	"continue",
	"umask",
	"ulimit",
	"type",
	"which",
	"set",
	"cd",
	"pushd",
	"popd",
	".",
	"source",
	// Reading and inspecting.
	"ls",
	"dir",
	"cat",
	"tac",
	"head",
	"tail",
	"wc",
	"nl",
	"cut",
	"paste",
	"tr",
	"uniq",
	"sort",
	"comm",
	"join",
	"fold",
	"fmt",
	"column",
	"expand",
	"unexpand",
	"rev",
	"shuf",
	"seq",
	"od",
	"xxd",
	"hexdump",
	"base64",
	"md5sum",
	"sha1sum",
	"sha256sum",
	"sha512sum",
	"shasum",
	"cksum",
	"grep",
	"egrep",
	"fgrep",
	"rg",
	"jq",
	"find",
	"tree",
	"du",
	"df",
	"stat",
	"file",
	"basename",
	"dirname",
	"realpath",
	"readlink",
	"diff",
	"cmp",
	"date",
	"id",
	"whoami",
	"groups",
	"uname",
	"hostname",
	"uptime",
	"nproc",
	"printenv",
	"ps",
	"pgrep",
	// Writing, with every target in argv.
	"mkdir",
	"rmdir",
	"touch",
	"cp",
	"mv",
	"rm",
	"ln",
	"chmod",
	"chown",
	"chgrp",
	"truncate",
	"dd",
	"tee",
	"mktemp",
	"mkfifo",
	"split",
	"csplit",
	"gzip",
	"gunzip",
	"zcat",
	"bzip2",
	"bunzip2",
	"xz",
	"unxz",
	"zstd",
	"kill",
	"pkill",
	"killall",
	// Classified elsewhere in this module, with their own markers.
	"sed",
	"tar",
	"unzip",
	"cpio",
	"busybox",
	"git",
	"gh",
]);

/**
 * `git` subcommands whose argv the tokenizer understands. Any other word may be
 * an alias (`git config alias.st '!cmd'`) or a `git-<name>` program on PATH.
 */
const GIT_SUBCOMMANDS = new Set([
	"add",
	"apply",
	"archive",
	"bisect",
	"blame",
	"branch",
	"cat-file",
	"checkout",
	"cherry-pick",
	"clean",
	"clone",
	"commit",
	"config",
	"count-objects",
	"describe",
	"diff",
	"fetch",
	"for-each-ref",
	"format-patch",
	"fsck",
	"gc",
	"grep",
	"help",
	"init",
	"log",
	"ls-files",
	"ls-remote",
	"ls-tree",
	"merge",
	"merge-base",
	"mv",
	"notes",
	"pull",
	"push",
	"rebase",
	"reflog",
	"remote",
	"reset",
	"restore",
	"rev-list",
	"rev-parse",
	"revert",
	"rm",
	"shortlog",
	"show",
	"stash",
	"status",
	"submodule",
	"switch",
	"symbolic-ref",
	"tag",
	"version",
	"worktree",
]);

/**
 * True when an argument spells one of the named long options.
 *
 * GNU getopt and git's parse-options accept any unambiguous abbreviation of a
 * long option (`sort --co=x` is `--compress-program=x`, `tar --rs=x` is
 * `--rsh-command=x`), so an option name that is a prefix of a listed one counts
 * as that option. An ambiguous abbreviation is an error in the program and
 * over-asks here, which is the safe direction.
 */
function hasLongOption(args: readonly string[], options: readonly string[]): boolean {
	return args.some((arg) => {
		if (!arg.startsWith("--") || arg.length < 3) return false;
		const name = arg.split("=", 1)[0] as string;
		return options.some((option) => option.startsWith(name) || name.startsWith(option));
	});
}

/** Options, on any `git` subcommand, that name a program for git to run. */
const GIT_PROGRAM_OPTIONS = [
	"--upload-pack",
	"--receive-pack",
	"--exec",
	"--ext-diff",
	"--extcmd",
	"--open-files-in-pager",
];

/**
 * `git config` forms that only read, accepted only as the first argument (after
 * an optional scope flag). Every other form may set an alias, pager, editor or
 * hook path: `git config core.hooksPath list` sets the value `list`, and an
 * option that takes a value (`--file --get k v`) can swallow a read flag.
 */
const GIT_CONFIG_READS = new Set(["--get", "--get-all", "--get-regexp", "--list", "-l", "get", "list"]);
const GIT_CONFIG_SCOPES = new Set(["--global", "--system", "--local", "--worktree"]);

function gitConfigReads(args: readonly string[]): boolean {
	const first = GIT_CONFIG_SCOPES.has(args[0] ?? "") ? args[1] : args[0];
	return first !== undefined && GIT_CONFIG_READS.has(first);
}

/** True when a `git` invocation can run a program its argv does not show. */
function gitDispatches(args: readonly string[]): boolean {
	const [subcommand, ...rest] = args;
	if (subcommand === undefined) return false;
	// `git -c core.pager=… log` and `git --exec-path=…` configure programs.
	if (subcommand.startsWith("-")) return true;
	if (!GIT_SUBCOMMANDS.has(subcommand)) return true;
	if (hasLongOption(rest, GIT_PROGRAM_OPTIONS)) return true;
	switch (subcommand) {
		case "config":
			return !gitConfigReads(rest);
		case "grep":
			// `-O<pager>` opens matches in a program of the caller's choosing.
			return rest.some((arg) => /^-[^-]*O/.test(arg));
		case "rebase":
			return rest.some((arg) => /^-[^-]*x/.test(arg));
		case "submodule":
			return rest.includes("foreach");
		case "bisect":
			return rest[0] === "run";
		case "clone":
		case "ls-remote":
			// `-u <program>` is `--upload-pack`.
			return rest.some((arg) => /^-[^-]*u/.test(arg));
		default:
			return false;
	}
}

/** `gh` command groups that do not run extensions, aliases or other programs. */
const GH_GROUPS = new Set([
	"api",
	"auth",
	"cache",
	"gist",
	"issue",
	"label",
	"pr",
	"release",
	"repo",
	"run",
	"search",
	"status",
	"workflow",
]);

/** `tar` long options that name a program for tar to run. */
const TAR_PROGRAM_OPTIONS = [
	"--checkpoint-action",
	"--to-command",
	"--use-compress-program",
	"--rsh-command",
	"--rmt-command",
	"--info-script",
	"--new-volume-script",
];

/** True when `tar` would run a program named in its options. */
function tarDispatches(args: readonly string[]): boolean {
	if (hasLongOption(args, TAR_PROGRAM_OPTIONS)) return true;
	// `-I prog` / `-F script` in a short cluster, or in old-style first argument (`tar xIf …`).
	return args.some((arg, i) => (/^-[^-]/.test(arg) || (i === 0 && !arg.startsWith("-"))) && /[IF]/.test(arg));
}

/** `$IFS` / `${IFS}` -- the internal field separator, used to rebuild a command from an argument. */
const IFS_EXPANSION = /\$\{?IFS\}?/;

/** Keywords that introduce a compound command the tokenizer does not model. */
const SHELL_KEYWORDS = new Set([
	"!",
	"if",
	"then",
	"elif",
	"else",
	"fi",
	"for",
	"while",
	"until",
	"do",
	"done",
	"case",
	"esac",
	"select",
	"function",
	"{",
	"}",
]);

/** Interpreters can perform writes that are absent from their argv. */
const INTERPRETER_NAMES = new Set([
	"deno",
	"bun",
	"tsx",
	"ts-node",
	"qjs",
	"julia",
	"rscript",
	"r",
	"java",
	"groovy",
	"scala",
	"clojure",
]);

function isInterpreterCommand(name: string): boolean {
	return (
		/^(?:node|nodejs)(?:\d+(?:\.\d+)*)?$/.test(name) ||
		/^(?:python|pypy)(?:\d+(?:\.\d+)*)?$/.test(name) ||
		/^(?:perl|ruby|php|lua)(?:\d+(?:\.\d+)*)?$/.test(name) ||
		/^(?:g|m|n)?awk(?:\d+(?:\.\d+)*)?$/.test(name) ||
		INTERPRETER_NAMES.has(name.toLowerCase())
	);
}

/** Dispatchers whose project-controlled configuration selects executable code. */
const SCRIPT_RUNNERS = new Set([
	"npm",
	"npx",
	"pnpm",
	"yarn",
	"corepack",
	"make",
	"gmake",
	"ninja",
	"just",
	"task",
	"cargo",
	"go",
	"gradle",
	"gradlew",
	"mvn",
	"mvnw",
	"ant",
	"bazel",
	"buck",
	"poetry",
	"pipenv",
	"tox",
	"cmake",
	"ctest",
]);

const TRUSTED_EXECUTABLE_PREFIXES = [
	"/bin/",
	"/sbin/",
	"/usr/bin/",
	"/usr/sbin/",
	"/usr/local/bin/",
	"/usr/local/sbin/",
];

/** A path-selected executable may be project-controlled and hide all effects. */
function isWorkspaceExecutable(command: string): boolean {
	if (!command.includes("/")) return false;
	if (!command.startsWith("/")) return true;
	const normalized = posix.normalize(command);
	return !TRUSTED_EXECUTABLE_PREFIXES.some((prefix) => normalized.startsWith(prefix));
}

const PATHNAME_EXPANSION = /[*?[{]/;

/** A path prefix such as `/usr/bin/env` still names `env`. */
function baseName(command: string): string {
	const slash = command.lastIndexOf("/");
	return slash >= 0 ? command.slice(slash + 1) : command;
}

/**
 * Remove shell comments, keeping the newline that ends each one.
 *
 * Bash starts a comment at an unquoted `#` that begins a word and runs it to the
 * end of the line. The scanners below track quote state over the whole string,
 * so a quote inside a comment (`# don't`) used to open a span that swallowed the
 * following lines up to the next quote in a later comment, and a multi-line
 * script parsed as one confident command. Stripping comments first, with the
 * same lexical rules bash uses, means the scanners never see them.
 *
 * `#` is literal when it does not begin a word (`a#b`, `$#`, `${#x}`) and inside
 * any quotes. Inside backticks bash finds the closing backtick before it parses
 * the body, so a `#` there does not hide the closing backtick; the body is left
 * as written (it is non-confident anyway). Heredoc bodies are not modelled here
 * either; a heredoc is non-confident on its own.
 */
function stripComments(command: string): string {
	let out = "";
	let quote: '"' | "'" | "`" | undefined;
	// True where a new word may begin: at the start, and after unquoted
	// whitespace or a metacharacter. A line continuation does not change it.
	let wordStart = true;

	for (let i = 0; i < command.length; i++) {
		const char = command[i] as string;

		if (quote === "'") {
			if (char === "'") quote = undefined;
			out += char;
			continue;
		}
		if (char === "\\") {
			const next = command[i + 1];
			out += char + (next ?? "");
			i++;
			if (next !== "\n") wordStart = false;
			continue;
		}
		if (quote) {
			if (char === quote) quote = undefined;
			out += char;
			continue;
		}
		if (char === "'" || char === '"' || char === "`") {
			quote = char;
			wordStart = false;
			out += char;
			continue;
		}
		if (char === "#" && wordStart) {
			// Drop up to, not including, the newline: the newline still separates
			// the command before the comment from the one after it.
			const end = command.indexOf("\n", i);
			if (end < 0) break;
			i = end - 1;
			continue;
		}
		// Exactly bash's blanks and metacharacters. JavaScript's `\s` also
		// matches CR, FF, VT and Unicode spaces, after which bash does *not*
		// start a word, so a `#` there is literal and the rest of the line runs.
		wordStart = /[ \t\n;&|()<>]/.test(char);
		out += char;
	}
	return out;
}

/**
 * Count the lines a script is made of, independently of the scanners.
 *
 * A line counts when it is not blank and does not start with `#`; a line ending
 * in a backslash joins the next one. Every counted line holds at least one
 * simple command unless a quoted string, heredoc or compound command spans
 * lines, so a parse with fewer commands than counted lines has merged lines
 * that bash runs separately -- or the script has a multi-line construct the
 * tokenizer does not model. Either way it is not confident. This is a tripwire
 * for tokenizer bugs, not a parser: it can only add uncertainty.
 */
function countScriptLines(command: string): number {
	let count = 0;
	for (const line of command.replace(/\\\n/g, "").split("\n")) {
		const trimmed = line.trim();
		if (trimmed !== "" && !trimmed.startsWith("#")) count++;
	}
	return count;
}

/**
 * Whitespace and control characters bash does not treat as blanks.
 *
 * Bash separates words only at space, tab and newline. The scanners here use
 * JavaScript's `\s` in places, which also matches CR, FF, VT and the Unicode
 * spaces, and a word boundary the two disagree on can hide or invent a
 * command. Rather than prove every such case harmless, a command containing
 * one of these characters is not confident. A CRLF line ending is the one
 * ordinary source, and it over-asks.
 */
const UNUSUAL_WHITESPACE =
	// biome-ignore lint/suspicious/noControlCharactersInRegex: matching control characters is the point
	/[\0-\x08\v\f\r\x0e-\x1f\x7f\u0085\u00a0\u1680\u180e\u2000-\u200b\u2028\u2029\u202f\u205f\u3000\ufeff]/;

export function parseShell(command: string): ParsedShell {
	const markers = new Set<ShellMarker>();
	if (UNUSUAL_WHITESPACE.test(command)) markers.add("unusual-whitespace");
	const segments = splitSegments(stripComments(command), markers);
	const commands = segments
		.map((segment) => {
			const cmd = parseSegment(segment.text, markers);
			if (segment.op !== undefined) cmd.connector = segment.op;
			return cmd;
		})
		.filter((cmd) => cmd.text !== "");

	for (const cmd of commands) {
		// `/bin/bash -c` and `/usr/bin/env` name the same thing as `bash`/`env`.
		const name = baseName(cmd.name);

		// Canonical paths are resolved against the action cwd. Once a shell changes
		// directory, later relative operands no longer have that meaning.
		if (name === "cd" || name === "pushd" || name === "popd") markers.add("cwd-change");

		// Script/interpreter and archive contents can name writes that never appear
		// in argv. L2 remains the enforcement boundary; L1 must not claim a
		// confident parse of effects it cannot see.
		if (isInterpreterCommand(name)) markers.add("interpreter");
		if ((name === "." || name === "source") && cmd.args.length > 0) markers.add("source-script");
		if (SCRIPT_RUNNERS.has(name)) markers.add("script-runner");
		if (cmd.assignments.length > 0) markers.add("environment-assignment");
		if (isWorkspaceExecutable(cmd.name)) markers.add("workspace-executable");
		if (name === "git" && gitDispatches(cmd.args)) markers.add("command-dispatch");
		// `gh <extension>` and `gh <alias>` run arbitrary code; `--web` launches a browser.
		if (
			name === "gh" &&
			((cmd.args[0] !== undefined && !GH_GROUPS.has(cmd.args[0])) ||
				cmd.args.includes("-w") ||
				hasLongOption(cmd.args, ["--web"]))
		) {
			markers.add("command-dispatch");
		}
		// Builtins that assign a variable named in their arguments can set PATH.
		if (
			name === "read" ||
			(name === "printf" && cmd.args.includes("-v")) ||
			(name === "wait" && cmd.args.includes("-p"))
		) {
			markers.add("shell-state");
		}
		if (name === "sort" && hasLongOption(cmd.args, ["--compress-program"])) markers.add("command-dispatch");
		if (name === "split" && hasLongOption(cmd.args, ["--filter"])) markers.add("command-dispatch");
		if (name === "tar" && tarDispatches(cmd.args)) markers.add("command-dispatch");
		if (name === "rg" && hasLongOption(cmd.args, ["--pre", "--hostname-bin"])) markers.add("command-dispatch");
		// Unconditionally: `ex`, `vim`, `gdb`, `script` and others also run
		// commands read from stdin (`echo ':!cmd' | ex`, `ex < file`).
		if (LAUNCHER_COMMANDS.has(name)) markers.add("wrapper");
		// `exec < file` with no command rebinds stdin for the rest of the script.
		if (name === "exec" && cmd.args.length === 0) markers.add("shell-state");
		if (SHELL_STATE_BUILTINS.has(name)) markers.add("shell-state");
		if (name === "set" && !cmd.args.every((arg) => HARMLESS_SET_ARG.test(arg))) markers.add("shell-state");
		if (
			cmd.name !== "" &&
			!KNOWN_COMMANDS.has(name) &&
			!LAUNCHER_COMMANDS.has(name) &&
			!SHELL_STATE_BUILTINS.has(name) &&
			!WRAPPER_COMMANDS.has(name) &&
			!SHELL_KEYWORDS.has(name) &&
			!SCRIPT_RUNNERS.has(name) &&
			!isInterpreterCommand(name) &&
			OPAQUE_COMMANDS[name] === undefined
		) {
			markers.add("unknown-command");
		}
		if (name === "sed" && cmd.args.length > 0) markers.add("command-dispatch");
		if (name === "find" && cmd.args.some((arg) => ["-exec", "-execdir", "-ok", "-okdir", "-delete"].includes(arg))) {
			markers.add("command-dispatch");
		}
		if (name === "busybox" && cmd.args.length > 0) markers.add("command-dispatch");
		if (
			(name === "tar" && !cmd.args.some((arg) => /^-[^-]*t/.test(arg) || arg === "--list")) ||
			(name === "unzip" && !cmd.args.some((arg) => arg === "-l" || arg === "-p")) ||
			name === "cpio"
		) {
			markers.add("archive-extract");
		}

		const marker = OPAQUE_COMMANDS[name];
		if (marker) {
			// A shell script is as opaque as `-c`: its writes are not represented in
			// this argv. A shell with no arguments is too, because it runs whatever
			// reaches its stdin, and that need not be a visible pipe: `cat a |& sh`,
			// a pipe followed by a newline, or `exec < file` earlier in the script.
			markers.add(marker);
			continue;
		}

		// A wrapper with a real (non-option) argument is running a command the
		// rules were never matched against. Escalate rather than guess where the
		// wrapper's own options end and the inner command begins.
		if (WRAPPER_COMMANDS.has(name) && cmd.args.length > 0) {
			markers.add("wrapper");
		}

		// A parameter expansion in the command name reconstructs the command from
		// a value the tokenizer cannot see: `$c -rf /`, `git${IFS}push`, `${cmd}`.
		// The name matched literally, so no rule fired and the parse stayed
		// confident. `$IFS` is a word-splitting trick with no benign use in a
		// command an agent would write, so it is flagged wherever it appears. An
		// argument expansion can change a policy-sensitive subcommand just as easily
		// as a path (`verb=reset; git "$verb" --hard`), so every argument expansion
		// is uncertain. Quoted literals containing `$` may over-ask; silently
		// treating an expansion as literal would let it bypass configured rules.
		if (
			cmd.name.includes("$") ||
			cmd.args.some((arg) => IFS_EXPANSION.test(arg) || arg.includes("$")) ||
			cmd.redirects.some((redirect) => redirect.target.includes("$"))
		) {
			markers.add("param-expansion");
		}

		// Pathname expansion can reconstruct a policy-sensitive subcommand as
		// well as a file target (`git r?set --hard`). The tokenizer does not keep
		// enough per-argument quote state to prove a metacharacter was literal, so
		// every argument/redirect occurrence is conservatively non-confident.
		if (
			PATHNAME_EXPANSION.test(cmd.name) ||
			cmd.redirects.some((redirect) => PATHNAME_EXPANSION.test(redirect.target)) ||
			cmd.args.some((arg) => PATHNAME_EXPANSION.test(arg))
		) {
			markers.add("pathname-expansion");
		}

		// A shell keyword introduces a compound command (if/for/while/case/{) the
		// tokenizer does not model; escalate rather than treat the keyword as the
		// command.
		if (SHELL_KEYWORDS.has(name)) markers.add("compound");
	}

	if (command.includes("\n") && commands.length < countScriptLines(command)) markers.add("unaccounted-line");

	return { commands, confident: markers.size === 0, markers: [...markers] };
}

/**
 * Split into segments on `;`, newline, `|`, `||`, `&&` and `&`.
 *
 * Single `&` is a separator here even though automode does not treat it as
 * one: `make & rm -rf /` is two commands, and a splitter that returns one
 * would hand the matcher a string no pattern for the second command can reach.
 * `&>` is excluded, because there it is a redirect operator.
 */
function splitSegments(command: string, markers: Set<ShellMarker>): { text: string; op?: string }[] {
	const segments: { text: string; op?: string }[] = [];
	let current = "";
	// The operator that split *before* the current segment; attached to it when
	// it is pushed, so the hash can tell `a && b` from `a || b`.
	let pendingOp: string | undefined;
	let quote: '"' | "'" | "`" | undefined;
	let depth = 0;

	for (let i = 0; i < command.length; i++) {
		const char = command[i] as string;
		const next = command[i + 1];

		if (quote === "'") {
			// Nothing is special inside single quotes, not even a backslash.
			if (char === "'") quote = undefined;
			current += char;
			continue;
		}

		if (char === "\\") {
			// A backslash before a newline is a line continuation the shell
			// deletes entirely (joining the two physical lines); keeping it turned
			// `rm \\\n-rf /x` into a confident parse whose command line began
			// `rm \n-rf` and matched no `rm -rf *` rule. Drop both characters so
			// the segment reads as the single command the shell will run.
			if (next === "\n") {
				i++;
				continue;
			}
			// Single quotes are handled above, so anything reaching here is
			// unquoted or double-quoted, where a backslash escapes.
			current += char + (next ?? "");
			i++;
			continue;
		}

		if (quote) {
			// Bash performs command substitution inside double quotes, so the
			// inner command runs although the word is quoted: `cat "`git push`"`.
			// The backslash branch above has already consumed escaped forms.
			if (quote === '"' && char === "`") markers.add("backtick");
			if (quote === '"' && char === "$" && next === "(") markers.add("command-substitution");
			if (char === quote) quote = undefined;
			current += char;
			continue;
		}

		if (char === "'" || char === '"' || char === "`") {
			if (char === "`") markers.add("backtick");
			quote = char;
			current += char;
			continue;
		}

		// `$(`, `<(` and `>(` all nest, and all hide a command from the splitter.
		if (char === "$" && next === "(") {
			markers.add("command-substitution");
			depth++;
			current += "$(";
			i++;
			continue;
		}
		if ((char === "<" || char === ">") && next === "(") {
			markers.add("process-substitution");
			depth++;
			current += `${char}(`;
			i++;
			continue;
		}
		if (char === "(") {
			// A bare `(` is a subshell/grouping whose contents the tokenizer does
			// not parse as their own commands. `$(`/`<(`/`>(` are handled above.
			markers.add("subshell");
			depth++;
			current += char;
			continue;
		}
		if (char === ")") {
			if (depth > 0) depth--;
			current += char;
			continue;
		}

		if (char === "<" && next === "<") {
			markers.add("heredoc");
			current += char;
			continue;
		}

		// `>|` is a force-clobber redirect; the `|` is not a pipe here. Record it
		// and consume both so it does not split into a bogus segment.
		if (char === ">" && next === "|") {
			markers.add("clobber");
			current += ">|";
			i++;
			continue;
		}

		if (depth === 0 && SEPARATORS.has(char)) {
			// `&>` and `>&` are redirects, not separators.
			if (char === "&" && (next === ">" || command[i - 1] === ">")) {
				current += char;
				continue;
			}
			segments.push(pendingOp !== undefined ? { text: current, op: pendingOp } : { text: current });
			current = "";
			// The operator that will precede the next segment. `&&`/`||` consume a
			// second character; a newline is normalised to `;` (same sequencing).
			if (char === "&" && next === "&") {
				pendingOp = "&&";
				i++;
			} else if (char === "|" && next === "|") {
				pendingOp = "||";
				i++;
			} else {
				pendingOp = char === "\n" ? ";" : char;
			}
			continue;
		}

		current += char;
	}

	if (quote) markers.add("unbalanced-quote");
	segments.push(pendingOp !== undefined ? { text: current, op: pendingOp } : { text: current });
	return segments.map((segment) => ({
		text: segment.text.trim(),
		...(segment.op !== undefined ? { op: segment.op } : {}),
	}));
}

const REDIRECT = /^(\d*<>|\d*>>?|\d*<|&>>?|>&)$/;
const ASSIGNMENT = /^[A-Za-z_][A-Za-z0-9_]*=/;

/** Split one segment into words, pulling out redirects and assignment prefixes. */
function parseSegment(segment: string, markers: Set<ShellMarker>): SimpleCommand {
	const words = splitWords(segment, markers);
	const args: string[] = [];
	const redirects: Redirect[] = [];
	const assignments: string[] = [];
	let name: string | undefined;

	for (let i = 0; i < words.length; i++) {
		const word = words[i] as string;

		// A redirect written detached (`> out`) or attached (`>out`).
		const detached = REDIRECT.exec(word);
		if (detached) {
			const target = words[i + 1];
			if (target !== undefined) {
				redirects.push({ op: word, target, writes: !word.endsWith("<") });
				i++;
			}
			continue;
		}
		const attached = /^(\d*<>|\d*>>?|\d*<|&>>?|>&)(.+)$/.exec(word);
		if (attached?.[1] && attached[2]) {
			redirects.push({ op: attached[1], target: attached[2], writes: !attached[1].endsWith("<") });
			continue;
		}

		if (name === undefined && ASSIGNMENT.test(word)) {
			assignments.push(word);
			continue;
		}
		if (name === undefined) {
			name = word;
			continue;
		}
		args.push(word);
	}

	return { text: segment, syntax: normalizeShellSyntax(segment), name: name ?? "", args, assignments, redirects };
}

/**
 * Preserve syntax that changes execution (quotes and escapes) while ignoring
 * runs of whitespace outside quotes. Control characters are escaped so this is
 * safe to show on one line in a confirmation dialog.
 */
function normalizeShellSyntax(segment: string): string {
	let out = "";
	let pendingSpace = false;
	let quote: '"' | "'" | "`" | undefined;
	const appendControlSafe = (char: string) => {
		out += char === "\n" ? "\\n" : char === "\r" ? "\\r" : char === "\t" ? "\\t" : char;
	};

	for (let i = 0; i < segment.length; i++) {
		const char = segment[i] as string;
		const next = segment[i + 1];
		if (char === "\\" && next !== undefined) {
			if (pendingSpace && out !== "") out += " ";
			pendingSpace = false;
			out += char;
			appendControlSafe(next);
			i++;
			continue;
		}
		if (quote) {
			appendControlSafe(char);
			if (char === quote) quote = undefined;
			continue;
		}
		if (char === "'" || char === '"' || char === "`") {
			if (pendingSpace && out !== "") out += " ";
			pendingSpace = false;
			quote = char;
			out += char;
			continue;
		}
		if (/\s/.test(char)) {
			pendingSpace = out !== "";
			continue;
		}
		if (pendingSpace && out !== "") out += " ";
		pendingSpace = false;
		out += char;
	}
	return out;
}

/** Whitespace split with quote removal. Quoting does not join separate words here. */
function splitWords(segment: string, markers: Set<ShellMarker>): string[] {
	const words: string[] = [];
	let current = "";
	let started = false;
	let quote: '"' | "'" | "`" | undefined;

	const flush = () => {
		if (started) words.push(current);
		current = "";
		started = false;
	};

	for (let i = 0; i < segment.length; i++) {
		const char = segment[i] as string;

		if (quote === "'") {
			if (char === "'") quote = undefined;
			else current += char;
			started = true;
			continue;
		}
		if (char === "\\") {
			const next = segment[i + 1];
			// A line continuation: the shell joins the lines and drops the
			// backslash-newline, so it must not become a literal newline glued
			// into the word (which left the parse confident but wrong).
			if (next === "\n") {
				i++;
				continue;
			}
			if (next !== undefined) {
				current += next;
				i++;
				started = true;
			}
			continue;
		}
		if (quote) {
			if (char === quote) quote = undefined;
			else current += char;
			started = true;
			continue;
		}
		if (char === "'" || char === '"' || char === "`") {
			quote = char;
			started = true;
			continue;
		}
		if (/\s/.test(char)) {
			flush();
			continue;
		}
		// A redirect operator glued to the preceding word: `payload>>.git/x` is
		// arg `payload`, operator `>>`, target `.git/x` in a real shell, but the
		// naive splitter kept it as one token so the target was never seen as a
		// write. Split it out here, pulling any fd prefix (`2`, `&`) off the word.
		// `<(`/`>(` are process substitution, already marked at the segment level;
		// leave those alone so this does not invent a bogus redirect.
		if ((char === ">" || char === "<") && segment[i + 1] !== "(") {
			// An fd prefix only when the *whole* preceding token is `&` or all
			// digits, as bash requires. `report2>out` keeps `report2` as an
			// argument and redirects fd 1 -- stripping the trailing `2` there
			// corrupted the argument and misread the fd.
			const fd = /^(?:&|\d+)$/.test(current) ? current : "";
			if (fd) current = "";
			if (current !== "") words.push(current);
			current = "";
			started = false;
			let op = fd + char;
			if (char === "<" && segment[i + 1] === ">") {
				op += ">";
				i++;
			} else if (char === ">" && segment[i + 1] === ">") {
				op += ">";
				i++;
			} else if (char === ">" && segment[i + 1] === "&") {
				op += "&";
				i++;
			}
			words.push(op);
			continue;
		}
		current += char;
		started = true;
	}

	if (quote) markers.add("unbalanced-quote");
	flush();
	return words;
}

/**
 * The canonical text of a simple command: name and arguments, space-joined.
 *
 * Patterns match against this rather than the raw segment so that quoting and
 * runs of whitespace do not change whether a rule fires. `rm  -rf  /` and
 * `rm -rf "/"` are the same action and must match the same pattern.
 */
export function commandLine(command: SimpleCommand): string {
	return [command.name, ...command.args].filter((part) => part !== "").join(" ");
}
