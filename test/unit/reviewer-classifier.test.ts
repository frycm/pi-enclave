import { describe, expect, it } from "vitest";
import { defaultProfile, OWNED_TOOLS } from "../../src/config/defaults.ts";
import { checkTool } from "../../src/gate/tools.ts";
import { canonicalize } from "../../src/policy/canonical.ts";
import { classifyReadOnly, reviewerTrigger } from "../../src/reviewer/classifier.ts";

const PROFILE = defaultProfile({ cwd: "/work", home: "/home/u", tmp: "/tmp", agentDir: "/home/u/.pi/agent" });

function classify(command: string) {
	const action = canonicalize({ tool: "bash", input: { command }, cwd: "/work", home: "/home/u", profileName: "dev" });
	const disposition = checkTool({ tool: "bash", tools: PROFILE.tools, owned: OWNED_TOOLS });
	return { action, disposition, classification: classifyReadOnly(action, disposition) };
}

describe("reviewer trigger classifier", () => {
	it.each([
		"git status --short",
		"git log --oneline | head -5",
		"git branch --list",
		"git remote -v",
		"gh pr view 6",
		"find src -name README.md",
		"cat README.md",
	])("classifies an allowlisted shell read as read-only: %s", (command) => {
		expect(classify(command).classification.readOnly).toBe(true);
	});

	it.each([
		"git reset --hard",
		"git branch new-branch",
		"git branch --list --delete old-branch",
		"git remote add origin x",
		"gh api -X DELETE repos/o/r",
		"gh pr view 6 --web",
		"gh pr view 6 -w",
		"find . -delete",
		"find . -fprint0 output.txt",
		"file --compile -m workspace.magic",
		"rg --pre ./converter needle .",
		"rg --hostname-bin ./hostname needle .",
		"cat README.md > copy.md",
		"cat $(echo README.md)",
		"echo hello",
		"tee output.txt",
		"git statsu",
		"./cat README.md",
		"/work/bin/git status",
	])("classifies mutations, structural ambiguity, and unknowns as mutating: %s", (command) => {
		expect(classify(command).classification.readOnly).toBe(false);
	});

	it("requires every member of a pipeline to be read-only", () => {
		expect(classify("cat README.md | tee copy.md").classification.readOnly).toBe(false);
	});

	it("uses declared readOnly only for non-shell tools", () => {
		const action = canonicalize({
			tool: "read",
			input: { path: "README.md" },
			cwd: "/work",
			home: "/home/u",
			profileName: "dev",
		});
		const disposition = checkTool({ tool: "read", tools: PROFILE.tools, owned: OWNED_TOOLS });
		expect(classifyReadOnly(action, disposition).readOnly).toBe(true);
	});

	it("maps configured triggers without letting boundary review ordinary calls", () => {
		const { action, disposition } = classify("echo hello");
		expect(reviewerTrigger("boundary", action, disposition)).toBeUndefined();
		expect(reviewerTrigger("mutating", action, disposition)).toBe("mutating");
		expect(reviewerTrigger("all", action, disposition)).toBe("all");
	});

	it("always reviews a capability crossing", () => {
		const action = canonicalize({
			tool: "bash",
			input: { command: "cat /srv/x", allow_read: "/srv/x" },
			cwd: "/work",
			home: "/home/u",
			profileName: "dev",
		});
		const disposition = checkTool({ tool: "bash", tools: PROFILE.tools, owned: OWNED_TOOLS });
		expect(reviewerTrigger("boundary", action, disposition)).toBe("capability");
	});
});
