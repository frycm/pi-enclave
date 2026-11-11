/**
 * Differential test of the shell tokenizer against real bash.
 *
 * The tokenizer is a hand-written heuristic, and two independent gaps in it
 * (comments, #14, and backticks inside double quotes, #32) each let a script
 * hide a command behind a confident parse. This test is the safety net for that
 * class: it builds scripts from fragments that combine quoting, comments,
 * substitutions and continuations around a marker command, runs each one under
 * bash, and checks the one property the policy depends on:
 *
 *   if the parse is confident, every simple command bash ran is one the parser
 *   listed.
 *
 * The marker is `probe`, a script on PATH that appends its first argument to a
 * log. A listed probe is a parsed simple command named `probe` with that
 * argument. Nothing else in the fragments has an effect: only `probe`, `echo`
 * and `true` are run, in a throwaway directory.
 *
 * Over-listing (the parser lists a probe bash did not run, for example one in a
 * comment it failed to strip) is not a safety failure and is not asserted here;
 * the unit tests pin the exact parse for those cases.
 */
import { spawnSync } from "node:child_process";
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { parseShell } from "../../src/policy/shell.ts";

const BASH = ["/bin/bash", "/usr/bin/bash"].find((path) => spawnSync(path, ["-c", "true"]).status === 0);

/** `@` is replaced by a fresh probe id, so each probe in a script is distinct. */
const FRAGMENTS = [
	"probe @",
	"probe @ # it's a comment",
	'probe @ # say "hi"',
	"probe @ # a `tick",
	"# don't run probe @",
	'# "unbalanced',
	"probe @ '#literal'",
	'probe @ "#literal"',
	"probe @ a#b",
	"probe @#glued",
	"probe @ \\# escaped hash",
	'probe @ "a \\" # still quoted"',
	'probe @ "it\'s"',
	"probe @ '\"'",
	'probe @ "`probe @`"',
	'probe @ "$(probe @)"',
	"probe @ '`probe @`'",
	"echo `probe @`",
	"echo $(probe @ # inner ')')",
	"probe @ $'it\\'s'",
	"probe @ \\\n  # continued into a comment",
	"probe @ \\\n'#'",
	"probe @ ; # trailing",
	"probe @;#glued comment ' quote",
	"probe @&&#comment",
	"probe @ |#comment\ncat",
	"probe @ {#,x}",
	"probe @ # a comment ending in a backslash \\",
	"(#comment\nprobe @)",
	// Characters JavaScript's \s treats as blanks and bash does not: a `#`
	// after one of them is literal, so the rest of the line runs.
	"echo a\r#b; probe @",
	"echo a\f#b; probe @",
	"echo a\v#b; probe @",
	"echo a\u00a0#b; probe @",
	"echo a\u2028#b; probe @",
	"echo a\u3000#b; probe @",
	"echo a\ufeff#b; probe @",
	"probe @ | probe @",
	"probe @ && probe @",
	"{ probe @; }",
	"true # ' ; probe @",
	'echo "line one\nprobe @"',
];

const JOINERS = ["\n", "; ", " && ", "\n# it's\n"];

/** A small deterministic generator, so a failure reproduces exactly. */
function rng(seed: number) {
	let state = seed >>> 0;
	return () => {
		state = (state * 1664525 + 1013904223) >>> 0;
		return state / 2 ** 32;
	};
}

function buildScripts(): string[] {
	const scripts: string[] = [];
	for (const a of FRAGMENTS) {
		scripts.push(a);
		for (const b of FRAGMENTS) scripts.push(`${a}\n${b}`);
	}
	const random = rng(0x5eed);
	const pick = <T>(items: readonly T[]) => items[Math.floor(random() * items.length)] as T;
	for (let n = 0; n < 400; n++) {
		const parts = [pick(FRAGMENTS), pick(FRAGMENTS), pick(FRAGMENTS)];
		scripts.push(parts.map((part, i) => (i === 0 ? part : `${pick(JOINERS)}${part}`)).join(""));
	}
	return scripts.map((script) => {
		let id = 0;
		return script.replace(/@/g, () => `p${++id}`);
	});
}

describe.skipIf(!BASH)("the tokenizer against real bash", () => {
	let root: string;
	let bin: string;
	let work: string;

	beforeAll(() => {
		root = mkdtempSync(join(tmpdir(), "enclave-shell-diff-"));
		bin = join(root, "bin");
		work = join(root, "work");
		mkdirSync(bin);
		mkdirSync(work);
		const probe = join(bin, "probe");
		writeFileSync(probe, '#!/bin/sh\nprintf "%s\\n" "$1" >> "$PROBE_LOG"\n');
		chmodSync(probe, 0o755);
	});

	afterAll(() => {
		rmSync(root, { recursive: true, force: true });
	});

	function run(script: string): string[] {
		const log = join(root, "probe.log");
		writeFileSync(log, "");
		spawnSync(BASH as string, ["--noprofile", "--norc", "-c", script], {
			cwd: work,
			env: { PATH: `${bin}:/usr/bin:/bin`, PROBE_LOG: log },
			stdio: "ignore",
			timeout: 5000,
		});
		return readFileSync(log, "utf8").split("\n").filter(Boolean);
	}

	it("never lists fewer commands than bash runs in a confident parse", () => {
		const failures: string[] = [];
		let confident = 0;
		let executedSomething = 0;
		for (const script of buildScripts()) {
			const executed = run(script);
			if (executed.length > 0) executedSomething++;
			const parsed = parseShell(script);
			if (!parsed.confident) continue;
			confident++;
			const listed = new Set(
				parsed.commands
					.filter((command) => command.name === "probe")
					.map((command) => command.args[0])
					.filter((arg): arg is string => arg !== undefined),
			);
			const hidden = executed.filter((id) => !listed.has(id));
			if (hidden.length > 0) failures.push(`${JSON.stringify(script)} ran ${hidden.join(",")} unlisted`);
		}
		expect(failures, failures.slice(0, 20).join("\n")).toEqual([]);
		// Guard against a vacuous pass: the corpus must exercise confident parses
		// that really run probes, not only scripts the parser gives up on.
		expect(confident).toBeGreaterThan(200);
		expect(executedSomething).toBeGreaterThan(500);
		// About 1,300 bash processes; slower runners need more than the default.
	}, 120_000);

	// A control for the harness itself: a parse that drops a command bash runs
	// must be detected, otherwise the property above could hold vacuously.
	it("detects a command the parser failed to list", () => {
		expect(run("probe p1 # it's\nprobe p2 # it's")).toEqual(["p1", "p2"]);
		expect(run('true "`probe p1`"')).toEqual(["p1"]);
	});
});
