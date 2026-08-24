import { describe, expect, it } from "vitest";
import { canonicalize } from "../../src/policy/canonical.ts";
import {
	evaluateRules,
	invalidPatterns,
	matchesWildcard,
	parsePattern,
	type RulesInput,
} from "../../src/policy/match.ts";

const BASE = { cwd: "/work", home: "/home/u", profileName: "dev" };
const bash = (command: string) => canonicalize({ ...BASE, tool: "bash", input: { command } });

function rules(partial: Partial<RulesInput> = {}): RulesInput {
	return {
		deny: [],
		ask: [],
		skipReview: [],
		protectedPaths: { deny: [], ask: [] },
		...partial,
	};
}

describe("matchesWildcard", () => {
	it.each([
		["git push *", "git push origin main", true],
		["git push *", "git pushx origin", false],
		["*", "anything at all", true],
		["rm -rf *", "rm -rf /", true],
		["exact", "exact", true],
		["exact", "exactly", false],
		["a*b*c", "axxbyyc", true],
		["a*b*c", "axxc", false],
		// `*` crosses separators and newlines, unlike a filesystem glob.
		["curl *", "curl https://example.com/a/b", true],
		["* -k *", "curl -k https://x", true],
	])("%s against %s", (pattern, input, expected) => {
		expect(matchesWildcard(pattern, input)).toBe(expected);
	});

	it("is case-insensitive", () => {
		expect(matchesWildcard("Bash(x)".toLowerCase(), "bash(x)")).toBe(true);
		expect(matchesWildcard("git PUSH *", "git push origin")).toBe(true);
	});

	// The asymmetry is the point: both directions fail toward the human.
	describe("oversized input", () => {
		const huge = "x".repeat(1024 * 1024 + 1);

		it("matches a deny-shaped rule", () => {
			expect(matchesWildcard("anything", huge, "match")).toBe(true);
		});

		it("does not match an allow-shaped rule", () => {
			expect(matchesWildcard("anything", huge, "no-match")).toBe(false);
		});
	});
});

describe("parsePattern", () => {
	it.each([
		["bash(git push *)", "bash", "git push *"],
		["Bash(x)", "bash", "x"],
		["@some-tool(y)", "some-tool", "y"],
	])("parses %s", (raw, tool, argument) => {
		const parsed = parsePattern(raw);
		expect(parsed.tool).toBe(tool);
		expect(parsed.argument).toBe(argument);
	});

	it("a bare tool name matches every call of that tool", () => {
		const parsed = parsePattern("deploy");
		expect(parsed.tool).toBe("deploy");
		expect(parsed.argument).toBeUndefined();
	});

	it("keeps an unparseable pattern but never matches it", () => {
		const parsed = parsePattern("this is not a pattern");
		expect(parsed.invalid).toBeDefined();
		expect(invalidPatterns(["this is not a pattern"])).toHaveLength(1);
	});
});

describe("evaluateRules", () => {
	it("returns none when nothing matches", () => {
		expect(evaluateRules(bash("ls"), rules()).verdict).toBe("none");
	});

	it("denies on a deny match", () => {
		const result = evaluateRules(bash("sudo rm x"), rules({ deny: ["bash(sudo *)"] }));
		expect(result.verdict).toBe("deny");
		expect(result.decisive[0]?.pattern).toBe("bash(sudo *)");
	});

	// The reason the tokenizer splits at all: a rule about `rm` must not be
	// defeated by putting something harmless in front of it.
	it("matches a rule against each simple command, not just the first", () => {
		expect(evaluateRules(bash("echo ok && sudo rm x"), rules({ deny: ["bash(sudo *)"] })).verdict).toBe("deny");
		expect(evaluateRules(bash("cat x | sudo tee /etc/hosts"), rules({ deny: ["bash(sudo *)"] })).verdict).toBe("deny");
	});

	// A path-qualified command must match a rule anchored on the bare name.
	it("matches a bare-name rule against a path-qualified command", () => {
		expect(evaluateRules(bash("/usr/bin/sudo rm x"), rules({ deny: ["bash(sudo *)"] })).verdict).toBe("deny");
		expect(evaluateRules(bash("/usr/bin/git push origin"), rules({ ask: ["bash(git push *)"] })).verdict).toBe("ask");
	});

	it("still matches a pattern written against a whole pipeline", () => {
		expect(evaluateRules(bash("cat x | grep y"), rules({ ask: ["bash(cat x | grep y)"] })).verdict).toBe("ask");
	});

	it("ignores a pattern for a different tool", () => {
		expect(evaluateRules(bash("rm x"), rules({ deny: ["write(rm x)"] })).verdict).toBe("none");
	});

	// Precedence is fixed and not configurable. These two are conformance rows
	// P7 and P8 in the platform matrix.
	describe("precedence", () => {
		it("deny beats skipReview, and the audit sees both", () => {
			const result = evaluateRules(bash("npm test"), rules({ deny: ["bash(npm *)"], skipReview: ["bash(npm test*)"] }));
			expect(result.verdict).toBe("deny");
			expect(result.matches.map((match) => match.list).sort()).toEqual(["deny", "skipReview"]);
		});

		it("ask beats skipReview", () => {
			const result = evaluateRules(bash("npm test"), rules({ ask: ["bash(npm *)"], skipReview: ["bash(npm test*)"] }));
			expect(result.verdict).toBe("ask");
			expect(result.matches.map((match) => match.list).sort()).toEqual(["ask", "skipReview"]);
		});

		it("deny beats ask", () => {
			expect(evaluateRules(bash("npm test"), rules({ deny: ["bash(npm *)"], ask: ["bash(npm *)"] })).verdict).toBe(
				"deny",
			);
		});

		it("skipReview applies only when nothing else matched", () => {
			expect(evaluateRules(bash("npm test"), rules({ skipReview: ["bash(npm test*)"] })).verdict).toBe("skipReview");
		});
	});

	// The asymmetry has to survive the wiring, not just the primitive: an
	// oversized command must be denied by a deny rule and must never be
	// fast-pathed by a skipReview one. Caught by a mutation check that flipped
	// the overflow policy and passed every other test.
	describe("an input too large to match", () => {
		const huge = () => bash(`echo ${"x".repeat(1024 * 1024 + 1)}`);

		it("matches a deny rule", () => {
			expect(evaluateRules(huge(), rules({ deny: ["bash(echo *)"] })).verdict).toBe("deny");
		});

		it("matches an ask rule", () => {
			expect(evaluateRules(huge(), rules({ ask: ["bash(echo *)"] })).verdict).toBe("ask");
		});

		it("is never fast-pathed by skipReview", () => {
			expect(evaluateRules(huge(), rules({ skipReview: ["bash(echo *)"] })).verdict).toBe("none");
		});
	});

	describe("file tools", () => {
		const write = (path: string) => canonicalize({ ...BASE, tool: "write", input: { path } });

		it("matches the relative path", () => {
			expect(evaluateRules(write("infra/main.tf"), rules({ ask: ["write(infra/*)"] })).verdict).toBe("ask");
		});

		it("matches the absolute path", () => {
			expect(evaluateRules(write("infra/main.tf"), rules({ ask: ["write(/work/infra/*)"] })).verdict).toBe("ask");
		});
	});

	it("matches grep against its search pattern", () => {
		const action = canonicalize({ ...BASE, tool: "grep", input: { pattern: "AKIA[0-9A-Z]+" } });
		expect(evaluateRules(action, rules({ ask: ["grep(AKIA*)"] })).verdict).toBe("ask");
	});

	it("matches an unknown tool by name alone", () => {
		const action = canonicalize({ ...BASE, tool: "deploy", input: { env: "prod" } });
		expect(evaluateRules(action, rules({ deny: ["deploy"] })).verdict).toBe("deny");
	});

	it("routes protected-path matches through the supplied matcher", () => {
		const action = canonicalize({ ...BASE, tool: "write", input: { path: "infra/main.tf" } });
		const result = evaluateRules(action, rules({ protectedPaths: { deny: [], ask: ["infra/**"] } }), {
			protectedMatcher: (patterns) =>
				patterns.includes("infra/**") ? [{ list: "ask", pattern: "infra/**", target: "/work/infra/main.tf" }] : [],
		});
		expect(result.verdict).toBe("ask");
		expect(result.decisive[0]?.list).toBe("protectedPaths.ask");
	});
});
