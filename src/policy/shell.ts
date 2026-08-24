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
	| "subshell"
	| "compound"
	| "clobber";

export interface Redirect {
	/** The operator as written: `>`, `>>`, `2>`, `&>`, `<`. */
	op: string;
	target: string;
	/** False for `<`, which reads rather than writes. */
	writes: boolean;
}

export interface SimpleCommand {
	/** The segment as written, trimmed. Kept for diagnostics and audit records. */
	text: string;
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
	xargs: "xargs",
	sh: "shell-c",
	bash: "shell-c",
	zsh: "shell-c",
	dash: "shell-c",
	ksh: "shell-c",
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
	"exec",
	"time",
	"watch",
	"nice",
]);

/** `$IFS` / `${IFS}` -- the internal field separator, used to rebuild a command from an argument. */
const IFS_EXPANSION = /\$\{?IFS\}?/;

/** Keywords that introduce a compound command the tokenizer does not model. */
const SHELL_KEYWORDS = new Set([
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

/** A path prefix such as `/usr/bin/env` still names `env`. */
function baseName(command: string): string {
	const slash = command.lastIndexOf("/");
	return slash >= 0 ? command.slice(slash + 1) : command;
}

export function parseShell(command: string): ParsedShell {
	const markers = new Set<ShellMarker>();
	const segments = splitSegments(command, markers);
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

		const marker = OPAQUE_COMMANDS[name];
		if (marker) {
			// `sh script.sh` is ordinary; `sh -c '…'` (or `-lc`, `-xc`, …) hides a
			// whole command line. Any clustered short flag containing `c` counts.
			if (marker === "shell-c" && !cmd.args.some((arg) => /^-[a-z]*c[a-z]*$/i.test(arg))) continue;
			markers.add(marker);
			continue;
		}

		// A wrapper with a real (non-option) argument is running a command the
		// rules were never matched against. Escalate rather than guess where the
		// wrapper's own options end and the inner command begins.
		if (WRAPPER_COMMANDS.has(name) && cmd.args.some((arg) => !arg.startsWith("-"))) {
			markers.add("wrapper");
		}

		// A parameter expansion in the command name reconstructs the command from
		// a value the tokenizer cannot see: `$c -rf /`, `git${IFS}push`, `${cmd}`.
		// The name matched literally, so no rule fired and the parse stayed
		// confident. `$IFS` is a word-splitting trick with no benign use in a
		// command an agent would write, so it is flagged wherever it appears. An
		// argument that is a *variable-expanded path* (`$DIR/../.ssh`) can resolve
		// to a protected path the matcher cannot see, so it is flagged too -- but a
		// bare `$VAR` argument (`echo $HOME`) is common and left alone.
		if (
			cmd.name.includes("$") ||
			cmd.args.some((arg) => IFS_EXPANSION.test(arg) || (arg.includes("$") && arg.includes("/")))
		) {
			markers.add("param-expansion");
		}

		// A shell keyword introduces a compound command (if/for/while/case/{) the
		// tokenizer does not model; escalate rather than treat the keyword as the
		// command.
		if (SHELL_KEYWORDS.has(name)) markers.add("compound");
	}

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

const REDIRECT = /^(\d*>>?|\d*<|&>>?|>&)$/;
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
		const attached = /^(\d*>>?|\d*<|&>>?|>&)(.+)$/.exec(word);
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

	return { text: segment, name: name ?? "", args, assignments, redirects };
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
			if (char === ">" && segment[i + 1] === ">") {
				op += ">";
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
