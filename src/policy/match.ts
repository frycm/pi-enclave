/**
 * Pattern rules: the L1 matcher and its precedence.
 *
 * The pattern language is automode's, and staying compatible with it is
 * deliberate -- people already have these rules written down. One wildcard
 * (`*`), matching anything including `/`, case-insensitive, with a linear-time
 * matcher rather than a regular expression so that a pattern cannot be made to
 * backtrack. Regular expressions were the obvious alternative and they hand a
 * denial-of-service to whoever writes the config, which in a project file is
 * not necessarily the person running it.
 *
 * The one semantic departure: for `bash`, patterns are matched against **each
 * simple command** of the parsed line rather than against the raw string. A
 * rule that only sees the whole command line is defeated by `echo ok && …`,
 * which is the standard way past a command allowlist and not a subtle one.
 */
import type { CanonicalAction } from "./canonical.ts";
import { commandLine } from "./shell.ts";

/** Beyond these, matching is refused rather than attempted. */
const MAX_PATTERN = 4096;
const MAX_INPUT = 1024 * 1024;

export interface ToolPattern {
	/** The tool this applies to, lowercased. */
	tool: string;
	/** Absent for a bare `toolname` pattern, which matches every call. */
	argument?: string;
	/** The pattern as written, for diagnostics and audit records. */
	raw: string;
	/** Set when the pattern could not be parsed. Such a pattern never matches. */
	invalid?: string;
}

const PATTERN = /^@?([A-Za-z0-9_.-]+)(?:\((.*)\))?$/s;

export function parsePattern(raw: string): ToolPattern {
	const match = PATTERN.exec(raw.trim());
	if (!match?.[1]) return { tool: "", raw, invalid: "expected tool(argument pattern) or a bare tool name" };
	const [, tool, argument] = match;
	if (argument !== undefined && argument.length > MAX_PATTERN) {
		return { tool: tool.toLowerCase(), raw, invalid: `argument pattern longer than ${MAX_PATTERN} characters` };
	}
	return argument === undefined ? { tool: tool.toLowerCase(), raw } : { tool: tool.toLowerCase(), argument, raw };
}

/**
 * What to do when the input is too large to match.
 *
 * Asymmetric on purpose, and the asymmetry is the whole point: a `deny` or
 * `ask` rule *matches* an oversized input, an allow-shaped one does not. Both
 * directions fail toward the human.
 */
export type OverflowPolicy = "match" | "no-match";

/**
 * Single-wildcard glob matching, linear in the input.
 *
 * `*` matches any run of characters, including separators and newlines.
 * Comparison is case-insensitive, which matters mostly for Windows-style paths
 * and for `Bash(...)` spelled with a capital.
 */
export function matchesWildcard(pattern: string, input: string, overflow: OverflowPolicy = "match"): boolean {
	if (input.length > MAX_INPUT || pattern.length > MAX_PATTERN) return overflow === "match";

	const haystack = input.toLowerCase();
	const parts = pattern.toLowerCase().split("*");
	if (parts.length === 1) return haystack === parts[0];

	const first = parts[0] as string;
	const last = parts[parts.length - 1] as string;

	if (!haystack.startsWith(first)) return false;
	if (!haystack.endsWith(last)) return false;
	// The prefix and suffix may overlap on a short input; that is only legal
	// when the pattern is a bare `*` between them.
	if (first.length + last.length > haystack.length) return false;

	let cursor = first.length;
	for (let i = 1; i < parts.length - 1; i++) {
		const literal = parts[i] as string;
		if (literal === "") continue;
		const found = haystack.indexOf(literal, cursor);
		if (found < 0) return false;
		cursor = found + literal.length;
	}
	return cursor <= haystack.length - last.length;
}

// ---------------------------------------------------------------------------
// Matching an action
// ---------------------------------------------------------------------------

export interface RuleMatch {
	list: "deny" | "ask" | "skipReview" | "protectedPaths.deny" | "protectedPaths.ask";
	pattern: string;
	/** What the pattern matched: a simple command, a path, a search pattern. */
	target: string;
}

/**
 * Every string a pattern for this tool should be tried against.
 *
 * For `bash` that is one entry per simple command; for a file tool, the path in
 * both the spelling the model used and the resolved one; for anything else, the
 * serialized input, which is a blunt instrument but is at least total.
 */
export function matchTargets(action: CanonicalAction): string[] {
	if (action.tool === "bash") {
		const lines: string[] = [];
		for (const command of action.shell?.commands ?? []) {
			const line = commandLine(command);
			if (line !== "") lines.push(line);
			// Also a basename-normalized line, so a path-qualified command matches
			// a rule anchored on the bare name: `/usr/bin/git push` must match
			// `bash(git push *)`, and `/usr/bin/sudo` must match `bash(sudo *)`.
			if (command.name.includes("/")) {
				const bare = commandLine({ ...command, name: command.name.slice(command.name.lastIndexOf("/") + 1) });
				if (bare !== "" && bare !== line) lines.push(bare);
			}
		}
		// The whole line is included as well, so a pattern someone wrote against
		// a pipeline as a unit still fires.
		const whole = typeof action.input.command === "string" ? [action.input.command] : [];
		return [...new Set([...lines, ...whole])];
	}
	if (action.tool === "grep") {
		const pattern = action.input.pattern;
		return typeof pattern === "string" ? [pattern] : [];
	}
	if (action.paths.length > 0) {
		return [...new Set(action.paths.flatMap((path) => [path.typed, path.resolved, path.relative ?? path.typed]))];
	}
	return [safeStringify(action.input)];
}

function safeStringify(input: unknown): string {
	try {
		return JSON.stringify(input) ?? "";
	} catch {
		return "";
	}
}

function matchList(
	list: RuleMatch["list"],
	patterns: readonly string[],
	action: CanonicalAction,
	overflow: OverflowPolicy,
	// Passed in rather than recomputed: the three rule lists share one action,
	// and rebuilding the target set (re-joining every simple command) for each
	// was wasted work on the hot path.
	targets: readonly string[],
): RuleMatch[] {
	const matches: RuleMatch[] = [];
	for (const raw of patterns) {
		const pattern = parsePattern(raw);
		if (pattern.invalid) continue;
		if (pattern.tool !== action.tool.toLowerCase()) continue;
		if (pattern.argument === undefined) {
			matches.push({ list, pattern: raw, target: action.tool });
			continue;
		}
		for (const target of targets) {
			if (matchesWildcard(pattern.argument, target, overflow)) {
				matches.push({ list, pattern: raw, target });
				break;
			}
		}
	}
	return matches;
}

// ---------------------------------------------------------------------------
// Evaluation
// ---------------------------------------------------------------------------

export type Verdict = "deny" | "ask" | "skipReview" | "none";

export interface RulesInput {
	deny: readonly string[];
	ask: readonly string[];
	skipReview: readonly string[];
	protectedPaths: { deny: readonly string[]; ask: readonly string[] };
}

export interface Evaluation {
	verdict: Verdict;
	/** Every rule that matched, including ones the precedence overrode. */
	matches: RuleMatch[];
	/** The matches that decided the verdict. */
	decisive: RuleMatch[];
}

/**
 * Evaluate L1.
 *
 * Precedence is fixed and not configurable: **`deny` > `ask` > `skipReview`**.
 * An action matching both `deny` and `skipReview` is denied; one matching `ask`
 * and `skipReview` is asked. Only an action that matches nothing in `deny` or
 * `ask` can be fast-pathed. Every match is returned, not just the decisive one,
 * so the audit record can name both sides of an overlap -- a `skipReview` entry
 * that is being silently overridden is something the user needs to see.
 */
export function evaluateRules(
	action: CanonicalAction,
	rules: RulesInput,
	options: { protectedMatcher?: (patterns: readonly string[]) => RuleMatch[] } = {},
): Evaluation {
	const targets = matchTargets(action);
	const matches: RuleMatch[] = [
		...matchList("deny", rules.deny, action, "match", targets),
		...matchList("ask", rules.ask, action, "match", targets),
		// An oversized input must never be fast-pathed, so the allow-shaped list
		// is the one that fails to *no* match.
		...matchList("skipReview", rules.skipReview, action, "no-match", targets),
	];

	if (options.protectedMatcher) {
		matches.push(
			...options
				.protectedMatcher(rules.protectedPaths.deny)
				.map((m) => ({ ...m, list: "protectedPaths.deny" as const })),
		);
		matches.push(
			...options.protectedMatcher(rules.protectedPaths.ask).map((m) => ({ ...m, list: "protectedPaths.ask" as const })),
		);
	}

	const decisiveOf = (list: RuleMatch["list"][]) => matches.filter((match) => list.includes(match.list));

	const denials = decisiveOf(["deny", "protectedPaths.deny"]);
	if (denials.length > 0) return { verdict: "deny", matches, decisive: denials };

	const asks = decisiveOf(["ask", "protectedPaths.ask"]);
	if (asks.length > 0) return { verdict: "ask", matches, decisive: asks };

	const skips = decisiveOf(["skipReview"]);
	if (skips.length > 0) return { verdict: "skipReview", matches, decisive: skips };

	return { verdict: "none", matches, decisive: [] };
}

/** Patterns that cannot be parsed, so a config check can report them. */
export function invalidPatterns(patterns: readonly string[]): { raw: string; reason: string }[] {
	const out: { raw: string; reason: string }[] = [];
	for (const raw of patterns) {
		const parsed = parsePattern(raw);
		if (parsed.invalid) out.push({ raw, reason: parsed.invalid });
	}
	return out;
}
