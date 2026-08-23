import { describe, expect, it } from "vitest";
import { commandLine, parseShell } from "../../src/policy/shell.ts";

function names(command: string): string[] {
	return parseShell(command).commands.map((cmd) => cmd.name);
}

function lines(command: string): string[] {
	return parseShell(command).commands.map(commandLine);
}

describe("parseShell", () => {
	it("parses a single command", () => {
		const parsed = parseShell("git status --short");
		expect(parsed.commands).toHaveLength(1);
		expect(parsed.commands[0]?.name).toBe("git");
		expect(parsed.commands[0]?.args).toEqual(["status", "--short"]);
		expect(parsed.confident).toBe(true);
	});

	// Every simple command is matched separately, so a rule about `rm` is not
	// defeated by putting something harmless in front of it. This is the whole
	// reason the tokenizer splits at all.
	it.each([
		["a && b", ["a", "b"]],
		["a || b", ["a", "b"]],
		["a | b", ["a", "b"]],
		["a ; b", ["a", "b"]],
		["a & b", ["a", "b"]],
		["a\nb", ["a", "b"]],
		["echo ok && rm -rf /", ["echo", "rm"]],
	])("splits %s", (command, expected) => {
		expect(names(command)).toEqual(expected);
	});

	it("does not split inside quotes", () => {
		expect(names('echo "a && b"')).toEqual(["echo"]);
		expect(names("echo 'a | b'")).toEqual(["echo"]);
	});

	it("normalizes quoting and whitespace in the matched line", () => {
		expect(lines('rm  -rf   "/tmp/x"')).toEqual(["rm -rf /tmp/x"]);
	});

	describe("redirects", () => {
		it.each([
			["cat x > out", ">", "out"],
			["cat x >> out", ">>", "out"],
			["cat x >out", ">", "out"],
			["cmd 2> err", "2>", "err"],
			["cmd &> both", "&>", "both"],
		])("pulls %s out of the arguments", (command, op, target) => {
			const parsed = parseShell(command);
			expect(parsed.commands[0]?.redirects).toEqual([{ op, target, writes: true }]);
			expect(parsed.commands[0]?.args).not.toContain(target);
		});

		it("treats an input redirect as a read", () => {
			expect(parseShell("cmd < in").commands[0]?.redirects[0]?.writes).toBe(false);
		});

		// `&>` is a redirect, not a background-and-then. Splitting there would
		// invent a second command out of the filename.
		it("does not split on the & of &>", () => {
			expect(names("cmd &> out")).toEqual(["cmd"]);
		});
	});

	it("separates environment assignment prefixes from the command name", () => {
		const parsed = parseShell("FOO=1 BAR=2 make build");
		expect(parsed.commands[0]?.assignments).toEqual(["FOO=1", "BAR=2"]);
		expect(parsed.commands[0]?.name).toBe("make");
	});

	// Being loudly unsure is the only safe failure mode: the gate escalates a
	// non-confident parse instead of trusting it.
	describe("confidence", () => {
		it.each([
			["echo $(whoami)", "command-substitution"],
			["echo `whoami`", "backtick"],
			["diff <(a) <(b)", "process-substitution"],
			["cat <<EOF", "heredoc"],
			['eval "$CMD"', "eval"],
			["ls | xargs rm", "xargs"],
			["sh -c 'rm -rf /'", "shell-c"],
			["bash -c 'x'", "shell-c"],
			["echo 'unterminated", "unbalanced-quote"],
		])("%s is not confident (%s)", (command, marker) => {
			const parsed = parseShell(command);
			expect(parsed.confident).toBe(false);
			expect(parsed.markers).toContain(marker);
		});

		it("an ordinary command is confident", () => {
			expect(parseShell("npm run build && npm test").confident).toBe(true);
		});

		// `sh script.sh` runs a file; only `-c` hides a command line the
		// tokenizer will never see.
		it("sh without -c stays confident", () => {
			expect(parseShell("sh ./deploy.sh").confident).toBe(true);
		});
	});

	it("ignores empty segments from trailing separators", () => {
		expect(names("ls ; ")).toEqual(["ls"]);
	});
});
