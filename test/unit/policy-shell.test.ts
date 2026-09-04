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
			["cmd <> read-write", "<>", "read-write"],
			["cmd 1<>read-write", "1<>", "read-write"],
		])("pulls %s out of the arguments", (command, op, target) => {
			const parsed = parseShell(command);
			expect(parsed.commands[0]?.redirects).toEqual([{ op, target, writes: true }]);
			expect(parsed.commands[0]?.args).not.toContain(target);
		});

		it("treats an input redirect as a read", () => {
			expect(parseShell("cmd < in").commands[0]?.redirects[0]?.writes).toBe(false);
		});

		it("treats a read-write redirect as a write", () => {
			expect(parseShell("cmd 1<>target").commands[0]?.redirects).toEqual([
				{ op: "1<>", target: "target", writes: true },
			]);
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
			["PATH=/tmp/agent-bin git status", "environment-assignment"],
			["LD_PRELOAD=/work/agent.so true", "environment-assignment"],
			["echo 'unterminated", "unbalanced-quote"],
		])("%s is not confident (%s)", (command, marker) => {
			const parsed = parseShell(command);
			expect(parsed.confident).toBe(false);
			expect(parsed.markers).toContain(marker);
		});

		it("an ordinary command is confident", () => {
			expect(parseShell("git status --short && ls").confident).toBe(true);
		});

		it("a shell script is opaque too", () => {
			expect(parseShell("sh ./deploy.sh").confident).toBe(false);
		});
	});

	it("ignores empty segments from trailing separators", () => {
		expect(names("ls ; ")).toEqual(["ls"]);
	});

	// A redirect glued to the preceding word was kept as one token, so the target
	// was never seen as a write and protectedPaths never fired.
	describe("glued redirects", () => {
		it("splits an operator joined to a word", () => {
			const parsed = parseShell("cat payload>>.git/hooks/pre-commit");
			expect(parsed.commands[0]?.name).toBe("cat");
			expect(parsed.commands[0]?.redirects).toEqual([{ op: ">>", target: ".git/hooks/pre-commit", writes: true }]);
		});

		it("keeps an fd prefix on the operator", () => {
			expect(parseShell("cmd 2>err").commands[0]?.redirects).toEqual([{ op: "2>", target: "err", writes: true }]);
			expect(parseShell("cmd 2>>err").commands[0]?.redirects[0]?.op).toBe("2>>");
		});

		it("does not split process substitution as a glued redirect", () => {
			// The `<(` guard keeps the new word-splitting from firing; process
			// substitution is non-confident anyway, which is what actually matters.
			expect(parseShell("diff <(a) <(b)").confident).toBe(false);
		});
	});

	// A command wrapper hides the real command from a rule anchored on it, so it
	// is marked non-confident and the gate escalates rather than guess.
	describe("wrappers", () => {
		it.each([
			["env rm -rf /", "env"],
			["nohup sudo sh", "nohup"],
			["timeout 30 rm -rf .", "timeout"],
			["/usr/bin/env curl x", "path-qualified env"],
			["bash -lc 'git push'", "clustered -lc"],
			["builtin eval 'git reset --hard'", "builtin"],
			["env -S 'git reset --hard'", "env -S"],
		])("%s is not confident (%s)", (command) => {
			expect(parseShell(command).confident).toBe(false);
		});

		it("bare env with no command stays confident", () => {
			expect(parseShell("env").confident).toBe(true);
		});
	});

	// A backslash-newline is a line continuation the shell deletes; keeping it as
	// a literal newline left a confident parse whose command line matched no rule.
	describe("line continuation", () => {
		it("joins the lines so the command matches", () => {
			const parsed = parseShell("rm \\\n-rf /work/.git");
			expect(parsed.confident).toBe(true);
			expect(parsed.commands.map(commandLine)).toEqual(["rm -rf /work/.git"]);
		});
	});

	// A parameter expansion in command position reconstructs the command from a
	// value the tokenizer cannot see; it must escalate rather than parse it away.
	describe("parameter expansion", () => {
		// biome-ignore lint/suspicious/noTemplateCurlyInString: these are shell parameter expansions under test, not JS template placeholders
		it.each(["$c -rf /x", "git${IFS}push${IFS}--force", "${cmd} arg", "a${IFS}b"])("%s is not confident", (command) => {
			expect(parseShell(command).confident).toBe(false);
		});

		// Argument expansion can select a sensitive dispatcher verb or path.
		it.each([
			"echo $HOME",
			"npm run $script",
			"cat $file",
			'x=reset; git "$x" --hard',
		])("%s is not confident", (command) => {
			expect(parseShell(command).confident).toBe(false);
		});

		it.each([
			'TARGET=.github/workflows/ci.yml; echo pwn > "$TARGET"',
			'tee "$TARGET"',
			"dd if=/dev/zero of=$TARGET",
		])("%s escalates because a write target is expanded", (command) => {
			const parsed = parseShell(command);
			expect(parsed.confident).toBe(false);
			expect(parsed.markers).toContain("param-expansion");
		});
	});

	describe("hidden filesystem effects", () => {
		it.each([
			["cd .pi && touch extensions/x", "cwd-change"],
			['python3 -c \'open(".pi/extensions/x", "w")\'', "interpreter"],
			["node build.js", "interpreter"],
			["nodejs -e 'process.exit()'", "interpreter"],
			["/usr/bin/nodejs -e 'process.exit()'", "interpreter"],
			["python3.12 deploy.py", "interpreter"],
			["ruby3.3 deploy.rb", "interpreter"],
			["lua5.4 deploy.lua", "interpreter"],
			[". ./deploy.sh", "source-script"],
			["source ./deploy.sh", "source-script"],
			["npm run deploy", "script-runner"],
			["./deploy.sh", "workspace-executable"],
			["find . -exec git reset --hard ';'", "command-dispatch"],
			["sed -n 'e git reset --hard' /dev/null", "command-dispatch"],
			["busybox sh -c 'git reset --hard'", "command-dispatch"],
			["fish -c 'git reset --hard'", "shell-c"],
			["trap 'git reset --hard' EXIT", "command-dispatch"],
			["cmake -P agent.cmake", "script-runner"],
			["printf x | awk 'system(\"git reset --hard\")'", "interpreter"],
			["R -e 'system(\"git reset --hard\")'", "interpreter"],
			["/usr/bin/../../work/evil", "workspace-executable"],
			["printf 'git reset --hard\\n' | sh", "shell-c"],
			["sh < ./agent-script", "shell-c"],
			["tar -xf payload.tar", "archive-extract"],
			["printf x > .pi/extensions/*", "pathname-expansion"],
			["touch reset; git r?set --hard", "pathname-expansion"],
			["touch git; gi? reset --hard", "pathname-expansion"],
		])("%s is not confident (%s)", (command, marker) => {
			const parsed = parseShell(command);
			expect(parsed.confident).toBe(false);
			expect(parsed.markers).toContain(marker);
		});
	});

	// Compound and path-qualified forms the policy does not model must escalate
	// rather than parse away.
	describe("unsupported forms escalate", () => {
		it.each([
			"! sudo id",
			"(cd /x && rm -rf /)",
			"if true; then rm -rf /; fi",
			"for f in *; do rm $f; done",
			"echo x >| /work/.git/config",
			"cat $DIR/../.ssh/id",
		])("%s is not confident", (command) => {
			expect(parseShell(command).confident).toBe(false);
		});

		it("records the connector between commands", () => {
			expect(parseShell("a && b").commands[1]?.connector).toBe("&&");
			expect(parseShell("a || b").commands[1]?.connector).toBe("||");
			expect(parseShell("a | b").commands[1]?.connector).toBe("|");
			expect(parseShell("a").commands[0]?.connector).toBeUndefined();
		});
	});

	it("preserves quote syntax while normalizing harmless whitespace", () => {
		expect(parseShell('rm  "*"').commands[0]?.syntax).toBe('rm "*"');
		expect(parseShell("rm  *").commands[0]?.syntax).toBe("rm *");
	});

	// Regressions from the glued-redirect splitter.
	describe("redirect fidelity", () => {
		it("keeps trailing digits that belong to an argument, not an fd", () => {
			const parsed = parseShell("cat report2>out");
			expect(parsed.commands[0]?.args).toEqual(["report2"]);
			expect(parsed.commands[0]?.redirects).toEqual([{ op: ">", target: "out", writes: true }]);
		});

		it("treats a bare digit token as an fd", () => {
			expect(parseShell("cmd 2>out").commands[0]?.redirects[0]?.op).toBe("2>");
		});

		it("records &>> and >& targets as writes", () => {
			expect(parseShell("cmd &>>secret.txt").commands[0]?.redirects).toEqual([
				{ op: "&>>", target: "secret.txt", writes: true },
			]);
			expect(parseShell("cmd &>> secret.txt").commands[0]?.redirects[0]?.target).toBe("secret.txt");
			expect(parseShell("cmd >&secret.txt").commands[0]?.redirects[0]).toEqual({
				op: ">&",
				target: "secret.txt",
				writes: true,
			});
		});
	});
});
