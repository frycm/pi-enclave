import { describe, expect, it } from "vitest";
import { defaultProfile, OWNED_TOOLS } from "../../src/config/defaults.ts";
import type { EffectiveProfile } from "../../src/config/types.ts";
import { ActionLock, decide, type Escalator, type GateDecision } from "../../src/gate/gate.ts";
import { assertJsonLike, freezeToolInput, LockViolation } from "../../src/gate/lock.ts";
import { checkOwnership } from "../../src/gate/ownership.ts";
import { checkTool } from "../../src/gate/tools.ts";
import { canonicalize } from "../../src/policy/canonical.ts";
import { buildReviewEvidence } from "../../src/reviewer/evidence.ts";
import type { ActionReviewer, ReviewerResult } from "../../src/reviewer/types.ts";
import { FakePi } from "../harness/fake-pi.ts";

const OPTIONS = { cwd: "/work", home: "/home/u", tmp: "/tmp", agentDir: "/home/u/.pi/agent" };

function profile(edit: (p: EffectiveProfile) => void = () => {}): EffectiveProfile {
	const p = defaultProfile(OPTIONS);
	edit(p);
	return p;
}

const YES: Escalator = { confirm: async () => true };

function fakeReviewer(
	result:
		| Omit<Extract<ReviewerResult, { ok: true }>, "evidence">["review"]
		| { failure: "invalid-output" | "unavailable" },
): ActionReviewer & { calls: number } {
	return {
		calls: 0,
		async review(request) {
			this.calls++;
			const evidence = buildReviewEvidence({ action: request.action, trigger: request.trigger, attended: "off" });
			return "failure" in result
				? { ok: false, kind: result.failure, reason: "scripted failure", evidence }
				: { ok: true, review: result, modelReview: result, evidence };
		},
	};
}

function deps(overrides: Partial<Parameters<typeof decide>[1]> = {}) {
	return {
		profile: profile(),
		cwd: "/work",
		home: "/home/u",
		lock: new ActionLock(),
		owned: OWNED_TOOLS,
		...overrides,
	};
}

async function gate(toolName: string, input: Record<string, unknown>, overrides = {}): Promise<GateDecision> {
	return decide({ toolName, toolCallId: "c1", input }, deps(overrides));
}

describe("the gate", () => {
	it("permits an ordinary command", async () => {
		const decision = await gate("bash", { command: "git status --short" });
		expect(decision.block).toBe(false);
		expect(decision.outcome).toBe("allow");
	});

	it("denies a built-in deny rule and names the pattern", async () => {
		const decision = await gate("bash", { command: "sudo rm -rf /" });
		expect(decision.block).toBe(true);
		expect(decision.outcome).toBe("deny");
		expect(decision.reason).toContain("bash(sudo *)");
		expect(decision.adverse).toBe(true);
	});

	it.each([
		"git init --separate-git-dir .actualgit .",
		"git clone --config core.hooksPath=hooks ../source nested",
		"git -C nested worktree add ../branch-worktree",
		"git submodule add ../source dependency",
		"git submodule update --init dependency",
		"git submodule --quiet update --init dependency",
		"git submodule absorbgitdirs dependency",
	])("denies agent-driven Git metadata creation: %s", async (command) => {
		const decision = await gate("bash", { command });
		expect(decision.outcome).toBe("deny");
		expect(decision.reason).toContain("bash(git ");
	});

	it("steers away from the outcome rather than the command", async () => {
		const decision = await gate("bash", { command: "sudo rm -rf /" });
		expect(decision.reason).toContain("Do not pursue this outcome by other means");
	});

	describe("escalation", () => {
		it("asks on an ask rule, and denies when nobody answers", async () => {
			const decision = await gate("bash", { command: "git push origin main" });
			expect(decision.outcome).toBe("ask-denied");
			expect(decision.block).toBe(true);
			expect(decision.terminate).toBe(true);
		});

		it("permits when a human says yes", async () => {
			const decision = await gate("bash", { command: "git push origin main" }, { escalator: YES });
			expect(decision.outcome).toBe("ask-approved");
			expect(decision.block).toBe(false);
		});

		// The whole of deterministic mode: with no reviewer, a boundary crossing
		// has nowhere to go but a person.
		it("asks for a capability request", async () => {
			const decision = await gate(
				"bash",
				{ command: "printf x > /etc/hosts", allow_write: "/etc/hosts" },
				{ escalator: YES },
			);
			expect(decision.outcome).toBe("ask-approved");
		});

		it("refuses a speculative write capability unrelated to the action", async () => {
			const decision = await gate(
				"bash",
				{ command: "touch /work/output", allow_write: "/srv/unrelated" },
				{ escalator: YES },
			);
			expect(decision.outcome).toBe("deny");
			expect(decision.reason).toContain("does not cover a concrete write");
		});

		it("refuses a write capability intersecting read-denied credentials before asking", async () => {
			let asked = false;
			const decision = await gate(
				"bash",
				{ command: "cat /home/u/.ssh/id_ed25519", allow_write: "/home/u/.ssh/out" },
				{
					escalator: {
						confirm: async () => {
							asked = true;
							return true;
						},
					},
				},
			);
			expect(decision.outcome).toBe("deny");
			expect(decision.reason).toContain("immutable read-deny");
			expect(asked).toBe(false);
		});

		it("refuses a backend-immutable write target before asking", async () => {
			let asked = false;
			const decision = await gate(
				"bash",
				{ command: "true", allow_write: "/work/.pi/extensions" },
				{
					writeCapabilityIssue: () => "pi-enclave: target intersects immutable write-deny /work/.pi",
					escalator: {
						confirm: async () => {
							asked = true;
							return true;
						},
					},
				},
			);
			expect(decision.outcome).toBe("deny");
			expect(decision.reason).toContain("not grantable");
			expect(asked).toBe(false);
		});

		it("refuses a forged write capability on a file tool", async () => {
			let asked = false;
			const decision = await gate(
				"write",
				{ path: "/work/output", content: "x", allow_write: "/work/output" },
				{
					escalator: {
						confirm: async () => {
							asked = true;
							return true;
						},
					},
				},
			);
			expect(decision.outcome).toBe("deny");
			expect(decision.reason).toContain("supported only by the sandboxed bash tool");
			expect(asked).toBe(false);
		});

		it("permits an exact user-grantable read denial after escalation", async () => {
			const decision = await gate(
				"read",
				{ path: "/work/private/report.txt", allow_read: "/work/private" },
				{
					profile: profile((p) => {
						p.sandbox.readDeny.push("/work/private");
						p.sandbox.grantableReadDeny.push("/work/private");
					}),
					escalator: YES,
				},
			);
			expect(decision.outcome).toBe("ask-approved");
			expect(decision.block).toBe(false);
		});

		it("refuses a read grant that is not user-grantable before asking", async () => {
			let asked = false;
			const decision = await gate(
				"read",
				{ path: "/work/private/report.txt", allow_read: "/work/private" },
				{
					profile: profile((p) => p.sandbox.readDeny.push("/work/private")),
					escalator: {
						confirm: async () => {
							asked = true;
							return true;
						},
					},
				},
			);
			expect(decision.outcome).toBe("deny");
			expect(asked).toBe(false);
		});

		it("refuses a read grant unrelated to the action before asking", async () => {
			const decision = await gate(
				"read",
				{ path: "/work/public/report.txt", allow_read: "/work/private" },
				{
					profile: profile((p) => {
						p.sandbox.readDeny.push("/work/private");
						p.sandbox.grantableReadDeny.push("/work/private");
					}),
					escalator: YES,
				},
			);
			expect(decision.outcome).toBe("deny");
			expect(decision.reason).toContain("does not cover a concrete read");
		});

		it("continues to refuse host capabilities before asking", async () => {
			const decision = await gate("bash", { command: "echo x", allow_host: "example.com:443" }, { escalator: YES });
			expect(decision.outcome).toBe("deny");
		});

		it("does not escalate a capability disabled by current policy", async () => {
			let asked = false;
			const decision = await gate(
				"bash",
				{ command: "echo x", allow_write: "/etc/hosts" },
				{
					profile: profile((p) => {
						p.sandbox.capabilities = "none";
					}),
					escalator: {
						confirm: async () => {
							asked = true;
							return true;
						},
					},
				},
			);
			expect(decision.outcome).toBe("deny");
			expect(asked).toBe(false);
		});

		it("asks rather than allowing a parameter-expanded sensitive subcommand", async () => {
			const decision = await gate("bash", { command: "x=reset; git $x --hard" });
			expect(decision.outcome).toBe("ask-denied");
			expect(decision.reason).toContain("param-expansion");
		});

		it("asks rather than allowing a pathname-expanded sensitive subcommand", async () => {
			const decision = await gate("bash", { command: "touch reset; git r?set --hard" });
			expect(decision.outcome).toBe("ask-denied");
			expect(decision.reason).toContain("pathname-expansion");
		});

		it("does not confidently allow a multi-cd protected-path write", async () => {
			const decision = await gate("bash", {
				command: "mkdir .pi; cd .pi; mkdir extensions; cd extensions; printf x > evil.ts",
			});
			expect(decision.outcome).toBe("ask-denied");
			expect(decision.reason).toContain("cwd-change");
		});

		// The rules were matched against a guess, so a deny rule may not have
		// fired. Asking is the only honest answer to "I do not know what this is".
		it("asks when the tokenizer could not parse the command", async () => {
			const decision = await gate("bash", { command: 'eval "$CMD"' });
			expect(decision.outcome).toBe("ask-denied");
			expect(decision.reason).toContain("could not be parsed with confidence");
		});

		it.each([
			"! git push origin main",
			'TARGET=.github/workflows/ci.yml; echo pwn > "$TARGET"',
			'tee "$TARGET"',
			". /tmp/agent-script",
			"nodejs /tmp/agent-script.js",
			"npm run agent-controlled-script",
			"find . -exec git reset --hard ';'",
			"sed -n 'e git reset --hard' /dev/null",
			"busybox sh -c 'git reset --hard'",
			"fish -c 'git reset --hard'",
		])("fails closed for unsupported shell semantics in %s", async (command) => {
			const decision = await gate("bash", { command });
			expect(decision.outcome).toBe("ask-denied");
			expect(decision.reason).toContain("could not be parsed with confidence");
		});

		it("does not ask for a command it parsed confidently", async () => {
			expect((await gate("bash", { command: "ls -la" })).outcome).toBe("allow");
		});
	});

	describe("isolated reviewer", () => {
		const allow = () =>
			fakeReviewer({
				decision: "allow",
				risk: "medium",
				reason: "routine mutation",
				modelRisk: "low",
				minimumRisk: "medium",
				authorizationCovers: false,
			});

		const reviewProfile = () =>
			profile((p) => {
				p.reviewer.model = "ollama/reviewer";
				p.review.trigger = "mutating";
			});

		it("reviews a mutation and locks an allow", async () => {
			let frozen = false;
			const reviewer: ActionReviewer = {
				async review(request) {
					frozen = Object.isFrozen(request.action.input);
					const evidence = buildReviewEvidence({
						action: request.action,
						trigger: request.trigger,
						attended: "off",
					});
					const review = {
						decision: "allow" as const,
						risk: "medium" as const,
						reason: "routine mutation",
						modelRisk: "low" as const,
						minimumRisk: "medium" as const,
						authorizationCovers: false,
					};
					return { ok: true, review, modelReview: review, evidence };
				},
			};
			const decision = await gate("bash", { command: "touch output.txt" }, { profile: reviewProfile(), reviewer });
			expect(decision.outcome).toBe("review-allow");
			expect(decision.block).toBe(false);
			expect(frozen).toBe(true);
		});

		it("keeps a classified read on the fast path", async () => {
			const reviewer = allow();
			const decision = await gate("bash", { command: "git status --short" }, { profile: reviewProfile(), reviewer });
			expect(decision.outcome).toBe("allow");
			expect(reviewer.calls).toBe(0);
		});

		it("sends all actions to a trigger configured as all", async () => {
			const reviewer = allow();
			const configured = reviewProfile();
			configured.review.trigger = "all";
			expect((await gate("bash", { command: "git status --short" }, { profile: configured, reviewer })).outcome).toBe(
				"review-allow",
			);
		});

		it("does not let the reviewer clear an L1 ask", async () => {
			const reviewer = allow();
			const decision = await gate(
				"bash",
				{ command: "git push origin main" },
				{
					profile: reviewProfile(),
					reviewer,
					escalator: YES,
				},
			);
			expect(decision.outcome).toBe("ask-approved");
			expect(reviewer.calls).toBe(0);
		});

		it("turns reviewer ask into L4 confirmation", async () => {
			const reviewer = fakeReviewer({
				decision: "ask",
				risk: "medium",
				reason: "ambiguous intent",
				modelRisk: "medium",
				minimumRisk: "medium",
				authorizationCovers: false,
			});
			expect(
				(await gate("bash", { command: "touch output.txt" }, { profile: reviewProfile(), reviewer, escalator: YES }))
					.outcome,
			).toBe("ask-approved");
		});

		it("does not let a reviewer alone admit an explicitly reviewed third-party tool", async () => {
			const configured = reviewProfile();
			configured.tools.allow.deploy = { reviewed: true };
			const reviewer = allow();
			const decision = await gate("deploy", { env: "preview" }, { profile: configured, reviewer });
			expect(decision.outcome).toBe("ask-denied");
			expect(decision.reason).toContain("runs outside the sandbox and requires human approval");
			expect(reviewer.calls).toBe(1);
		});

		it("fails closed without retrying or escalating invalid output", async () => {
			let asked = false;
			const decision = await gate(
				"bash",
				{ command: "touch output.txt" },
				{
					profile: reviewProfile(),
					reviewer: fakeReviewer({ failure: "invalid-output" }),
					escalator: {
						confirm: async () => {
							asked = true;
							return true;
						},
					},
				},
			);
			expect(decision.outcome).toBe("review-deny");
			expect(decision.terminate).toBe(true);
			expect(asked).toBe(false);
		});

		it("turns exhausted availability errors into an ask", async () => {
			const decision = await gate(
				"bash",
				{ command: "touch output.txt" },
				{
					profile: reviewProfile(),
					reviewer: fakeReviewer({ failure: "unavailable" }),
					escalator: YES,
				},
			);
			expect(decision.outcome).toBe("ask-approved");
		});
	});

	describe("protected paths", () => {
		it("escalates a write to a protected path", async () => {
			const decision = await gate("write", { path: ".github/workflows/ci.yml" });
			expect(decision.outcome).toBe("ask-denied");
		});

		// Escalating reads would make the list unusable in any repository where
		// the agent has to look at what it may not change.
		it("does not escalate a read of one", async () => {
			expect((await gate("read", { path: ".github/workflows/ci.yml" })).outcome).toBe("allow");
		});

		it("denies a write to a deny-listed path", async () => {
			const decision = await gate("write", { path: ".git/hooks/pre-commit" });
			expect(decision.outcome).toBe("deny");
		});

		it("catches a shell redirect to a protected path", async () => {
			const decision = await gate("bash", { command: "echo x > .github/workflows/ci.yml" });
			expect(decision.outcome).toBe("ask-denied");
		});

		it("denies a read-write redirect to a protected bare filename", async () => {
			const decision = await gate("bash", { command: "printf PWN 1<>authorized_keys" });
			expect(decision.outcome).toBe("deny");
		});

		it("denies a path-qualified writer targeting a protected bare filename", async () => {
			const decision = await gate("bash", { command: "/usr/bin/tee authorized_keys" });
			expect(decision.outcome).toBe("deny");
		});

		it("denies deletion of a protected directory root", async () => {
			const decision = await gate("bash", { command: "rm -rf .git/hooks" });
			expect(decision.outcome).toBe("deny");
		});
	});

	describe("the tool allowlist", () => {
		it("denies a tool nobody allowed", async () => {
			const decision = await gate("deploy", { env: "prod" });
			expect(decision.outcome).toBe("deny");
			expect(decision.reason).toContain("not in tools.allow");
		});

		it("allows one that is listed", async () => {
			const decision = await gate(
				"deploy",
				{ env: "prod" },
				{
					profile: profile((p) => {
						p.tools.allow.deploy = {};
					}),
				},
			);
			expect(decision.block).toBe(false);
		});

		it("withholds an otherwise allowed tool at the final unsandboxed boundary", async () => {
			const decision = await gate(
				"deploy",
				{ env: "prod" },
				{
					profile: profile((p) => {
						p.tools.allow.deploy = {};
					}),
					withholdBeforeExecution: () => "earlier owned sibling could trip the breaker",
				},
			);
			expect(decision.outcome).toBe("batch-withheld");
			expect(decision.block).toBe(true);
		});

		it("applies a deny before the final unsandboxed-boundary check", async () => {
			const decision = await gate(
				"deploy",
				{},
				{
					profile: profile((p) => {
						p.tools.allow.deploy = {};
						p.rules.deny.push("deploy");
					}),
					withholdBeforeExecution: () => "batch risk",
				},
			);
			expect(decision.outcome).toBe("deny");
		});

		it("sends a reviewed tool to a human", async () => {
			const decision = await gate(
				"deploy",
				{ env: "prod" },
				{
					profile: profile((p) => {
						p.tools.allow.deploy = { reviewed: true };
					}),
				},
			);
			expect(decision.outcome).toBe("ask-denied");
		});

		// A tool name is not an identity: load order decides whose registration
		// pi keeps, so an unpinned grant is a grant to whoever loads first.
		it("refuses a pinned grant claimed by a different extension", async () => {
			const decision = await gate(
				"deploy",
				{},
				{
					profile: profile((p) => {
						p.tools.allow.deploy = { source: "/ext/ours.ts" };
					}),
					toolSource: () => "/ext/theirs.ts",
				},
			);
			expect(decision.outcome).toBe("deny");
			expect(decision.reason).toContain("/ext/ours.ts");
		});
	});

	describe("PI_ENCLAVE_AUTO=off", () => {
		const off = () =>
			profile((p) => {
				p.auto = false;
			});

		it("passes an action L1 would have denied", async () => {
			const decision = await gate("bash", { command: "sudo rm -rf /" }, { profile: off() });
			expect(decision.block).toBe(false);
		});

		// The sandbox is the one layer nothing may remove, and an environment
		// variable is the least trusted place such a request could come from.
		it("still locks the action, so the sandbox path is unchanged", async () => {
			const lock = new ActionLock();
			await gate("bash", { command: "ls" }, { profile: off(), lock });
			expect(lock.entries()).toHaveLength(1);
		});
	});

	describe("failure", () => {
		it("freezes input before an already-open breaker short-circuits", async () => {
			const input = { command: "ls" };
			const decision = await gate("bash", input, { breakerOpen: () => true });
			expect(decision.outcome).toBe("breaker-open");
			expect(Object.isFrozen(input)).toBe(true);
		});

		it("turns an internal error into a denial", async () => {
			const decision = await decide(
				{ toolName: "bash", toolCallId: "c1", input: { command: "ls" } },
				{
					...deps(),
					// A profile with no rules object at all: the kind of shape only a
					// bug produces, and the gate must still refuse rather than permit.
					profile: { ...profile(), rules: undefined as never },
				},
			);
			expect(decision.block).toBe(true);
			expect(decision.outcome).toBe("error");
			expect(decision.adverse).toBe(true);
		});

		// A failed freeze must turn the allow into a denial rather than hand out
		// a guarantee that is not there. Guardian makes the same choice.
		it("denies when the input cannot be locked", async () => {
			const input: Record<string, unknown> = {};
			Object.defineProperty(input, "command", { get: () => "ls", enumerable: true, configurable: true });
			const decision = await decide({ toolName: "bash", toolCallId: "c1", input }, deps());
			expect(decision.block).toBe(true);
			expect(decision.outcome).toBe("error");
		});
	});
});

describe("the lock", () => {
	describe("assertJsonLike", () => {
		it("accepts plain data", () => {
			expect(() => assertJsonLike({ a: 1, b: [true, null, "x"] })).not.toThrow();
		});

		// Object.freeze on an accessor freezes the accessor, not what it returns,
		// so a getter would sail through a freeze and still hand `execute` a
		// different value on the second read.
		it.each([
			["an accessor", () => Object.defineProperty({}, "x", { get: () => 1, enumerable: true })],
			["a function", () => ({ x: () => 1 })],
			["a class instance", () => ({ x: new Date() })],
			[
				"a cycle",
				() => {
					const a: Record<string, unknown> = {};
					a.self = a;
					return a;
				},
			],
			["a symbol key", () => ({ [Symbol("s")]: 1 })],
			["a non-enumerable property", () => Object.defineProperty({}, "x", { value: 1, enumerable: false })],
			[
				"a sparse array",
				() => {
					// Built by assignment rather than with a literal hole: the hole is
					// the point of the test, and a formatter would helpfully fill it in.
					const sparse: unknown[] = [];
					sparse[0] = 1;
					sparse[2] = 3;
					return { x: sparse };
				},
			],
			["a non-finite number", () => ({ x: Number.NaN })],
		])("rejects %s", (_label, build) => {
			expect(() => assertJsonLike(build())).toThrow(TypeError);
		});
	});

	it("makes the input non-writable as well as frozen", () => {
		const event = { input: { command: "ls" } as Record<string, unknown> };
		freezeToolInput(event);
		expect(() => {
			(event as { input: unknown }).input = { command: "rm -rf /" };
		}).toThrow(TypeError);
		expect(() => {
			event.input.command = "rm -rf /";
		}).toThrow(TypeError);
	});

	describe("execution keys", () => {
		const action = canonicalize({
			tool: "bash",
			input: { command: "ls" },
			cwd: "/work",
			home: "/home/u",
			profileName: "dev",
		});

		it("refuses a key it never saw", () => {
			const lock = new ActionLock();
			expect(() => lock.beginExecution("bash:ls")).toThrow(LockViolation);
		});

		it("permits a registered action", () => {
			const lock = new ActionLock();
			lock.register(action, "c1");
			expect(() => lock.beginExecution("bash:ls")).not.toThrow();
		});

		// `edit` reads and then writes the same file, so several operations run
		// under one tool call and must all be allowed.
		it("permits repeated operations within one tool call", () => {
			const lock = new ActionLock();
			const edit = canonicalize({
				tool: "edit",
				input: { path: "/work/file", oldText: "a", newText: "b" },
				cwd: "/work",
				home: "/home/u",
				profileName: "dev",
			});
			lock.register(edit, "c1");
			lock.beginExecution("edit:/work/file");
			expect(() => lock.beginExecution("edit:/work/file")).not.toThrow();
		});

		it("refuses after the tool call is consumed", () => {
			const lock = new ActionLock();
			lock.register(action, "c1");
			lock.beginExecution("bash:ls");
			lock.consume("c1");
			expect(() => lock.beginExecution("bash:ls")).toThrow(/has run once/);
		});

		// Two identical commands in one batch canonicalize to the same key; a
		// single-value table let the second registration orphan the first, so one
		// call could run under the other's entry. Each must find its own.
		it("keeps a separate entry for each of two identical calls", () => {
			const lock = new ActionLock();
			lock.register(action, "c1");
			lock.register(action, "c2");
			const first = lock.beginExecution("bash:ls");
			const second = lock.beginExecution("bash:ls");
			expect(first.toolCallId).toBe("c1");
			expect(second.toolCallId).toBe("c2");
			lock.consume("c1");
			lock.consume("c2");
			// Both spent now; a third finds nothing available.
			expect(() => lock.beginExecution("bash:ls")).toThrow(/has run once/);
		});

		it("refuses indistinguishable concurrent bash calls with different capabilities", () => {
			const lock = new ActionLock();
			const widened = canonicalize({
				tool: "bash",
				input: { command: "ls", allow_write: "/srv/result" },
				cwd: "/work",
				home: "/home/u",
				profileName: "dev",
			});
			lock.register(widened, "capability-call");
			lock.register(action, "ordinary-call");

			expect(() => lock.beginExecution("bash:ls")).toThrow(/different authority/);
			lock.consume("ordinary-call");
			expect(lock.beginExecution("bash:ls").toolCallId).toBe("capability-call");
		});

		// The window pi's prepare-all-then-execute batching opens: this call was
		// gated before the breaker tripped and is already prepared.
		it("refuses when the breaker opened after the call was locked", () => {
			let open = false;
			const lock = new ActionLock({ breakerOpen: () => open });
			lock.register(action, "c1");
			open = true;
			expect(() => lock.beginExecution("bash:ls")).toThrow(/circuit breaker/);
		});
	});
});

describe("ownership", () => {
	const tools = (overrides: Record<string, string> = {}) =>
		OWNED_TOOLS.map((name) => ({ name, sourceInfo: { path: overrides[name] ?? "/ext/pi-enclave/index.ts" } }));

	const check = (overrides: Record<string, string> = {}, extra: Partial<Parameters<typeof checkOwnership>[0]> = {}) =>
		checkOwnership({
			tools: tools(overrides),
			ownPath: "/ext/pi-enclave/index.ts",
			cwd: "/work",
			projectTrusted: false,
			listProjectExtensions: () => [],
			...extra,
		});

	it("passes when pi-enclave owns everything", () => {
		expect(check()).toEqual([]);
	});

	// pi keeps the *first* extension's registration, so the dangerous extension
	// is the one loaded before us -- its bash wins and ours is discarded.
	it("refuses when another extension owns a sandboxed tool", () => {
		const problems = check({ bash: "/ext/other/index.ts" });
		expect(problems).toHaveLength(1);
		expect(problems[0]?.kind).toBe("foreign-tool");
		expect(problems[0]?.message).toContain("/ext/other/index.ts");
	});

	it("refuses when a sandboxed tool is missing entirely", () => {
		const problems = checkOwnership({
			tools: tools().filter((tool) => tool.name !== "grep"),
			ownPath: "/ext/pi-enclave/index.ts",
			cwd: "/work",
			projectTrusted: false,
			listProjectExtensions: () => [],
		});
		expect(problems[0]?.kind).toBe("missing-tool");
	});

	describe("project extensions", () => {
		// pi will not load one from an untrusted project, so this only fires
		// where trust was granted -- which is exactly where the agent's own
		// writes become executable code in the pi process.
		it("refuses a trusted project carrying extensions", () => {
			const problems = check({}, { projectTrusted: true, listProjectExtensions: () => ["helper.ts"] });
			expect(problems[0]?.kind).toBe("project-extension");
			expect(problems[0]?.message).toContain("helper.ts");
		});

		it("says nothing when the project is not trusted", () => {
			expect(check({}, { projectTrusted: false, listProjectExtensions: () => ["helper.ts"] })).toEqual([]);
		});

		it("refuses a project-scoped tool", () => {
			const problems = checkOwnership({
				tools: [...tools(), { name: "helper", sourceInfo: { path: "/work/.pi/extensions/h.ts", scope: "project" } }],
				ownPath: "/ext/pi-enclave/index.ts",
				cwd: "/work",
				projectTrusted: true,
				listProjectExtensions: () => [],
			});
			expect(problems[0]?.kind).toBe("project-extension");
		});
	});
});

describe("checkTool", () => {
	it("treats a reviewed grant on an owned tool as ordinary", () => {
		const disposition = checkTool({
			tool: "bash",
			tools: { allow: { bash: { reviewed: true } } },
			owned: OWNED_TOOLS,
		});
		expect(disposition.allowed && disposition.reviewed).toBe(false);
	});

	it("keeps reviewed on a tool pi-enclave cannot sandbox", () => {
		const disposition = checkTool({
			tool: "deploy",
			tools: { allow: { deploy: { reviewed: true } } },
			owned: OWNED_TOOLS,
		});
		expect(disposition.allowed && disposition.reviewed).toBe(true);
	});

	it("fails a configured source pin closed when the runtime source is absent", () => {
		const disposition = checkTool({
			tool: "deploy",
			tools: { allow: { deploy: { source: "/ext/deploy.ts" } } },
			owned: OWNED_TOOLS,
		});
		expect(disposition.allowed).toBe(false);
		if (disposition.allowed) return;
		expect(disposition.reason).toContain("unknown source");
	});

	it("accepts a matching source pin for an owned tool", () => {
		const disposition = checkTool({
			tool: "bash",
			tools: { allow: { bash: { source: "/ext/pi-enclave.ts" } } },
			owned: OWNED_TOOLS,
			source: "/ext/pi-enclave.ts",
		});
		expect(disposition.allowed).toBe(true);
	});

	// A tool named after an Object.prototype member must not inherit a grant.
	it.each(["toString", "constructor", "hasOwnProperty"])("denies a tool named %s with no own grant", (name) => {
		expect(checkTool({ tool: name, tools: { allow: {} }, owned: OWNED_TOOLS }).allowed).toBe(false);
	});
});

// ---------------------------------------------------------------------------
// Against the fake pi, which reproduces the semantics that make the lock work
// ---------------------------------------------------------------------------

describe("through pi's handler chain", () => {
	function install(pi: FakePi, lock = new ActionLock()) {
		pi.onToolCall(async (event) => {
			const decision = await decide(event, deps({ lock }));
			return decision.block
				? { block: true, reason: decision.reason ?? "", ...(decision.terminate ? { terminate: true } : {}) }
				: {};
		});
		return lock;
	}

	it("permits a benign call through to execution", async () => {
		const pi = new FakePi({ execute: () => "ran" });
		install(pi);
		const batch = await pi.batch([{ toolName: "bash", input: { command: "ls" } }]);
		expect(batch.executed).toHaveLength(1);
	});

	it("blocks a denied call before it executes", async () => {
		const pi = new FakePi({ execute: () => "ran" });
		install(pi);
		const batch = await pi.batch([{ toolName: "bash", input: { command: "sudo ls" } }]);
		expect(batch.executed).toHaveLength(0);
	});

	// The freeze's whole purpose: a later extension rewriting the approved
	// arguments. pi does not catch the resulting TypeError, so the tool never
	// runs -- the failure is closed by construction.
	it("a later handler mutating the input fails the call closed", async () => {
		const pi = new FakePi({ execute: () => "ran" });
		install(pi);
		pi.onToolCall((event) => {
			event.input.command = "sudo rm -rf /";
			return undefined;
		});
		const batch = await pi.batch([{ toolName: "bash", input: { command: "ls" } }]);
		expect(batch.prepared[0]?.error).toBeInstanceOf(TypeError);
		expect(batch.executed).toHaveLength(0);
	});

	it("a later handler replacing the input object also fails closed", async () => {
		const pi = new FakePi({ execute: () => "ran" });
		install(pi);
		pi.onToolCall((event) => {
			(event as { input: unknown }).input = { command: "sudo rm -rf /" };
			return undefined;
		});
		const batch = await pi.batch([{ toolName: "bash", input: { command: "ls" } }]);
		expect(batch.prepared[0]?.error).toBeInstanceOf(TypeError);
		expect(batch.executed).toHaveLength(0);
	});

	it("blocking one call in a batch does not affect its siblings", async () => {
		const pi = new FakePi({ execute: () => "ran" });
		install(pi);
		const batch = await pi.batch([
			{ toolName: "bash", input: { command: "ls" } },
			{ toolName: "bash", input: { command: "sudo ls" } },
			{ toolName: "bash", input: { command: "pwd" } },
		]);
		expect(batch.executed.map((call) => call.input.command)).toEqual(["ls", "pwd"]);
	});
});
