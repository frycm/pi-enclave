import { describe, expect, it } from "vitest";
import { parseDocument, parseEnvironment } from "../../src/config/schema.ts";
import type { SourceId } from "../../src/config/types.ts";

const OPTIONS = { cwd: "/work", home: "/home/u", tmp: "/tmp", agentDir: "/home/u/.pi/agent" };

function parse(raw: unknown, source: SourceId = "user_global") {
	return parseDocument(
		raw,
		source,
		source === "user_global" ? "/home/u/.pi/agent/enclave.json" : "/work/.pi/enclave.json",
		OPTIONS,
	);
}

function errorKeys(result: ReturnType<typeof parse>): string[] {
	return result.ok ? [] : result.errors.map((error) => error.key);
}

describe("parseDocument", () => {
	it("accepts an empty document", () => {
		const result = parse({});
		expect(result.ok).toBe(true);
	});

	it("rejects an unknown key and names it", () => {
		const result = parse({ sandbx: {} });
		expect(errorKeys(result)).toEqual(["sandbx"]);
	});

	// A misspelled key that is ignored produces a sandbox the user believes is
	// narrower than it is, which is the failure this whole module exists to
	// prevent -- so it gets its own test at every nesting depth.
	it("rejects an unknown key nested inside a section", () => {
		const result = parse({ sandbox: { readDenyy: [] } });
		expect(errorKeys(result)).toEqual(["sandbox.readDenyy"]);
	});

	it("reports every error rather than stopping at the first", () => {
		const result = parse({ sandbox: { allowPty: "yes" }, rules: { deny: 3 } });
		expect(errorKeys(result).sort()).toEqual(["rules.deny", "sandbox.allowPty"]);
	});

	it("splices $defaults in place and keeps the user's entries after it", () => {
		const result = parse({ rules: { ask: ["$defaults", "bash(terraform apply*)"] } });
		if (!result.ok) throw new Error(result.errors.map((e) => e.key).join());
		const ask = result.document.patch?.rules?.ask ?? [];
		expect(ask).toContain("bash(git push *)");
		expect(ask.at(-1)).toBe("bash(terraform apply*)");
	});

	it("omitting $defaults takes ownership of the list", () => {
		const result = parse({ rules: { ask: ["bash(terraform apply*)"] } });
		if (!result.ok) throw new Error("expected success");
		expect(result.document.patch?.rules?.ask).toEqual(["bash(terraform apply*)"]);
	});

	// automode keeps the defaults when a list is malformed, which is the
	// conservative choice for a classifier hint. Here a dropped entry is a rule
	// the user believes is in force, so the file is rejected instead.
	it("rejects a list with a malformed entry rather than dropping it", () => {
		const result = parse({ rules: { deny: ["bash(sudo *)", 42] } });
		expect(errorKeys(result)).toEqual(["rules.deny[1]"]);
	});

	it("collapses duplicates while preserving order", () => {
		const result = parse({ rules: { deny: ["bash(a)", "bash(b)", "bash(a)"] } });
		if (!result.ok) throw new Error("expected success");
		expect(result.document.patch?.rules?.deny).toEqual(["bash(a)", "bash(b)"]);
	});

	describe("phase gating", () => {
		it("accepts an explicit named reviewer model", () => {
			const result = parse({ reviewer: { model: "ollama/qwen3:32b" } });
			expect(result.ok).toBe(true);
		});

		it.each([
			"qwen3:32b",
			"/model",
			"provider/",
			"provider/model id",
		])("refuses malformed reviewer model %s", (model) => {
			expect(errorKeys(parse({ reviewer: { model } }))).toEqual(["reviewer.model"]);
		});

		it("accepts an explicit named fallback", () => {
			expect(parse({ reviewer: { model: "ollama/primary", fallback: "ollama/fallback" } }).ok).toBe(true);
		});

		it('accepts reviewer.model "none"', () => {
			expect(parse({ reviewer: { model: "none" } }).ok).toBe(true);
		});

		it('refuses hostExec "human" until the L4 host path exists', () => {
			expect(errorKeys(parse({ sandbox: { hostExec: "human" } }))).toEqual(["sandbox.hostExec"]);
		});

		it("refuses a non-empty network allowlist", () => {
			expect(errorKeys(parse({ sandbox: { network: { allowHosts: ["example.com"] } } }))).toEqual([
				"sandbox.network.allowHosts",
			]);
		});
	});

	describe("values", () => {
		it("accepts a user-global grantable read-deny list", () => {
			const result = parse({ sandbox: { grantableReadDeny: ["/work/private"] } });
			if (!result.ok) throw new Error("expected success");
			expect(result.document.patch?.sandbox?.grantableReadDeny).toEqual(["/work/private"]);
		});

		it("rejects a zero confirm timeout", () => {
			expect(errorKeys(parse({ attended: { confirmTimeoutMs: 0 } }))).toEqual(["attended.confirmTimeoutMs"]);
		});

		it("rejects a breaker window whose limit exceeds its size", () => {
			expect(errorKeys(parse({ breaker: { window: [60, 50] } }))).toEqual(["breaker.window"]);
		});

		it("rejects a tool that is both readOnly and reviewed", () => {
			expect(errorKeys(parse({ tools: { allow: { thing: { readOnly: true, reviewed: true } } } }))).toEqual([
				"tools.allow.thing",
			]);
		});

		it("accepts a source pin on a tool grant", () => {
			const result = parse({ tools: { allow: { thing: { source: "/ext/thing/index.ts" } } } });
			if (!result.ok) throw new Error("expected success");
			expect(result.document.patch?.tools?.allow?.thing?.source).toBe("/ext/thing/index.ts");
		});
	});

	describe("project files", () => {
		const project = (raw: unknown) => parse(raw, "project_shared");

		it.each([
			["sandbox.grantableReadDeny", { sandbox: { grantableReadDeny: [] } }],
			["rules.skipReview", { rules: { skipReview: [] } }],
			["review.environment", { review: { environment: ["x"] } }],
			["review.hard_deny", { review: { hard_deny: ["x"] } }],
			["review.soft_deny", { review: { soft_deny: ["x"] } }],
			["review.allow", { review: { allow: ["x"] } }],
			["reviewer", { reviewer: { model: "none" } }],
			["breaker", { breaker: { consecutive: 1 } }],
			["audit", { audit: { retentionDays: 1 } }],
			["sandbox.env", { sandbox: { env: { passthrough: [] } } }],
			["profiles", { profiles: {} }],
		])("rejects %s on presence alone", (key, raw) => {
			expect(errorKeys(project(raw))).toContain(key);
		});

		// A soft_deny that reads as tightening is still a repository-supplied
		// string inside a reviewer prompt, which is the injection path the threat
		// model excludes. The value is never examined.
		it("rejects an empty prose list, because presence is the test", () => {
			expect(errorKeys(project({ review: { soft_deny: [] } }))).toContain("review.soft_deny");
		});

		it("allows the keys a project may set", () => {
			const result = project({
				profile: "dev",
				rules: { deny: ["bash(terraform destroy*)"], protectedPaths: { ask: ["infra/**"] } },
				review: { trigger: "all" },
				sandbox: { writableRoots: ["build"] },
			});
			expect(errorKeys(result)).toEqual([]);
		});

		it("lets a user-global file set everything a project may not", () => {
			const result = parse({
				rules: { skipReview: ["bash(npm test*)"] },
				review: { soft_deny: ["no migrations outside the CLI"] },
				sandbox: { grantableReadDeny: ["/work/private"], env: { passthrough: ["FOO"] } },
			});
			expect(errorKeys(result)).toEqual([]);
		});
	});
});

describe("parseEnvironment", () => {
	it("accepts an empty environment", () => {
		const result = parseEnvironment({});
		if (!result.ok) throw new Error("expected success");
		expect(result.document.patch).toBeUndefined();
	});

	it("turns attendance off", () => {
		const result = parseEnvironment({ PI_ENCLAVE_ATTENDED: "off" });
		if (!result.ok) throw new Error("expected success");
		expect(result.document.patch?.attended?.mode).toBe("off");
	});

	it("refuses to turn attendance on", () => {
		const result = parseEnvironment({ PI_ENCLAVE_ATTENDED: "tui" });
		expect(result.ok).toBe(false);
	});

	it("refuses PI_ENCLAVE_AUTO=on", () => {
		expect(parseEnvironment({ PI_ENCLAVE_AUTO: "on" }).ok).toBe(false);
	});

	it("clears auto for PI_ENCLAVE_AUTO=off", () => {
		const result = parseEnvironment({ PI_ENCLAVE_AUTO: "off" });
		if (!result.ok) throw new Error("expected success");
		expect(result.document.auto).toBe(false);
	});

	// Whoever controls the process environment of an ops runner should not get
	// to probe for variables that do something.
	it("rejects an unknown PI_ENCLAVE_ variable", () => {
		const result = parseEnvironment({ PI_ENCLAVE_MODEL: "gpt" });
		expect(result.ok).toBe(false);
		if (result.ok) return;
		expect(result.errors[0]?.key).toBe("PI_ENCLAVE_MODEL");
	});

	it("does not treat the conformance harness weaker-mode switch as production config", () => {
		const result = parseEnvironment({ PI_ENCLAVE_WEAKER_NESTED: "1" });
		expect(result.ok).toBe(false);
	});

	it("ignores unrelated variables", () => {
		expect(parseEnvironment({ PATH: "/usr/bin", HOME: "/home/u" }).ok).toBe(true);
	});
});
