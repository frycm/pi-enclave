/**
 * #18: what an unattended session can run, in each mode.
 *
 * The first table is the issue's evidence, kept as a fixture with the outcome
 * chosen for each row and mode. "reviewer" uses a model that always answers
 * allow/low, so it shows the best case any model could reach; the floors are
 * what still stop it. The second table is what the reviewer may not clear.
 */
import { describe, expect, it } from "vitest";
import { defaultProfile, OWNED_TOOLS } from "../../src/config/defaults.ts";
import type { EffectiveProfile } from "../../src/config/types.ts";
import { ActionLock, decide, type GateOutcome } from "../../src/gate/gate.ts";
import { decisionLayer, describeTally, emptyTally, recordLayer } from "../../src/gate/layers.ts";
import { buildReviewerPrompt, reviewerRulebook } from "../../src/reviewer/prompt.ts";
import { IsolatedReviewer } from "../../src/reviewer/reviewer.ts";
import { ASK_DENIED_TARGET, DEV_TASK_CROSSING, DEV_TASK_IN_SANDBOX } from "../harness/dev-task.ts";

const OPTIONS = { cwd: "/work", home: "/home/u", tmp: "/tmp", agentDir: "/home/u/.pi/agent" };

type Mode = "deterministic" | "sandbox" | "reviewer";

function profileFor(mode: Mode, edit: (p: EffectiveProfile) => void = () => {}): EffectiveProfile {
	const p = defaultProfile(OPTIONS);
	if (mode === "sandbox") p.rules.onUncertain = "sandbox";
	if (mode === "reviewer") {
		p.reviewer.model = "ollama/reviewer";
		p.review.trigger = "mutating";
	}
	edit(p);
	return p;
}

async function outcome(
	mode: Mode,
	tool: string,
	input: Record<string, unknown>,
	edit?: (p: EffectiveProfile) => void,
): Promise<GateOutcome> {
	const profile = profileFor(mode, edit);
	const reviewer =
		mode === "reviewer"
			? new IsolatedReviewer({
					profile,
					prompt: buildReviewerPrompt(reviewerRulebook(profile.review, new Map(), profile.rules)),
					primary: {
						name: "always-allow",
						complete: async () => '{"authorized":false,"decision":"allow","risk":"low","reason":"fine"}',
					},
					timeoutMs: 1_000,
					evidence: { attended: "off" },
					delay: async () => {},
				})
			: undefined;
	// attended off: no escalator, so every ask is the unattended "no".
	const decision = await decide(
		{ toolName: tool, toolCallId: "c1", input },
		{
			profile,
			cwd: "/work",
			home: "/home/u",
			lock: new ActionLock(),
			owned: OWNED_TOOLS,
			...(reviewer ? { reviewer } : {}),
		},
	);
	return decision.outcome;
}

const bash = (command: string) => ["bash", { command }] as const;

// [tool, input, deterministic, sandbox, reviewer]
const ISSUE_TABLE: readonly (readonly [string, Record<string, unknown>, GateOutcome, GateOutcome, GateOutcome])[] = [
	[...bash("git status --short"), "allow", "allow", "review-allow"],
	[...bash("npm test"), "ask-denied", "sandboxed-uncertain", "review-allow"],
	[...bash("npm run build"), "ask-denied", "sandboxed-uncertain", "review-allow"],
	[...bash("cd src && ls"), "ask-denied", "sandboxed-uncertain", "review-allow"],
	[...bash("ls *.ts"), "ask-denied", "sandboxed-uncertain", "review-allow"],
	[...bash("echo $HOME"), "ask-denied", "sandboxed-uncertain", "review-allow"],
	[...bash("make test"), "ask-denied", "sandboxed-uncertain", "review-allow"],
	[...bash("cargo build"), "ask-denied", "sandboxed-uncertain", "review-allow"],
	[...bash("sed -n 1,20p README.md"), "ask-denied", "sandboxed-uncertain", "review-allow"],
	[...bash("for f in a b; do echo $f; done"), "ask-denied", "sandboxed-uncertain", "review-allow"],
	[...bash("timeout 60 npm test"), "ask-denied", "sandboxed-uncertain", "review-allow"],
	[...bash("FOO=1 ./run.sh"), "ask-denied", "sandboxed-uncertain", "review-allow"],
	[...bash("python3 scripts/check.py"), "ask-denied", "sandboxed-uncertain", "review-allow"],
	[...bash("rm -f build/x"), "allow", "allow", "review-allow"],
	[...bash("git checkout -b feature"), "allow", "allow", "review-allow"],
	[...bash("git restore README.md"), "allow", "allow", "review-allow"],
	["write", { path: "src/big.ts", content: "x".repeat(9_000) }, "allow", "allow", "review-allow"],
	["write", { path: "src/a.ts", content: "export const a = 1;\n" }, "allow", "allow", "review-allow"],
	// From the issue's comment: a multi-line commit message is unaccounted text.
	[
		...bash('git commit -m "Fix the parser\n\nLonger explanation."'),
		"ask-denied",
		"sandboxed-uncertain",
		"review-allow",
	],
];

// [tool, input, deterministic, sandbox, reviewer]: none of these may run unattended.
const NOT_CLEARED: readonly (readonly [string, Record<string, unknown>, GateOutcome, GateOutcome, GateOutcome])[] = [
	// L1 ask rules: a person decides, whatever the parse or the reviewer.
	[...bash("git push origin main"), "ask-denied", "ask-denied", "ask-denied"],
	[...bash("git reset --hard HEAD~1"), "ask-denied", "ask-denied", "ask-denied"],
	// L1 deny rules still apply to the guess of an unreadable command.
	[...bash("sudo $CMD"), "deny", "deny", "deny"],
	// Destructive outside the writable roots: the high floor (#18 item 2).
	[...bash("rm -rf ../other"), "allow", "allow", "ask-denied"],
	[...bash("kill 1234"), "allow", "allow", "ask-denied"],
	// A capability widens L2 for one call: never sandboxed-uncertain, never cleared by the model.
	[...bash("npm test > out/log"), "ask-denied", "sandboxed-uncertain", "review-allow"],
	["bash", { command: "npm test > /srv/out/log", allow_write: "/srv/out" }, "ask-denied", "ask-denied", "ask-denied"],
	// A long bash command is truncated evidence: high, unlike a long write body.
	[...bash(`touch ${"x".repeat(9_000)}`), "allow", "allow", "ask-denied"],
	// Protected paths are L1 denials before any review.
	["write", { path: ".pi/extensions/x.ts", content: "x".repeat(9_000) }, "deny", "deny", "deny"],
	[...bash("rm -rf .git"), "deny", "deny", "deny"],
];

const grantable = (p: EffectiveProfile) => {
	p.sandbox.grantableWriteRoots = ["/srv"];
};

describe("the #18 table, unattended", () => {
	for (const [label, table] of [
		["issue evidence", ISSUE_TABLE],
		["not cleared", NOT_CLEARED],
	] as const) {
		describe(label, () => {
			it.each(table)("%s %j", async (tool, input, deterministic, sandbox, reviewer) => {
				expect(await outcome("deterministic", tool, input, grantable)).toBe(deterministic);
				expect(await outcome("sandbox", tool, input, grantable)).toBe(sandbox);
				expect(await outcome("reviewer", tool, input, grantable)).toBe(reviewer);
			});
		});
	}

	it("runs a sandboxed-uncertain command unblocked, not adverse, and says why", async () => {
		const decision = await decide(
			{ toolName: "bash", toolCallId: "c1", input: { command: "npm test" } },
			{ profile: profileFor("sandbox"), cwd: "/work", home: "/home/u", lock: new ActionLock(), owned: OWNED_TOOLS },
		);
		expect(decision).toMatchObject({ outcome: "sandboxed-uncertain", block: false, adverse: false });
		expect(decision.reason).toContain("script-runner");
		expect(decision.reason).toContain('rules.onUncertain is "sandbox"');
	});

	// The sandbox is the boundary only while it has no network; no shipped
	// profile has network yet, so this guards the condition, not a setting.
	it("does not run an unreadable command sandboxed when the profile has network", async () => {
		const networked = (p: EffectiveProfile) => {
			(p.sandbox.network as { mode: string }).mode = "on";
		};
		expect(await outcome("sandbox", "bash", { command: "npm test" }, networked)).toBe("ask-denied");
		expect(await outcome("reviewer", "bash", { command: "npm test" }, networked)).toBe("ask-denied");
	});

	// Under trigger "boundary" the reviewer sees only capabilities, so an
	// unreadable command follows rules.onUncertain like deterministic mode.
	it("sends an unreadable command under trigger boundary through rules.onUncertain", async () => {
		const boundary = (p: EffectiveProfile) => {
			p.review.trigger = "boundary";
		};
		expect(await outcome("reviewer", "bash", { command: "npm test" }, boundary)).toBe("ask-denied");
		expect(
			await outcome("reviewer", "bash", { command: "npm test" }, (p) => {
				boundary(p);
				p.rules.onUncertain = "sandbox";
			}),
		).toBe("sandboxed-uncertain");
	});
});

describe("the recorded dev task (#18 acceptance target)", () => {
	async function tally(mode: Mode) {
		const layers = emptyTally();
		const inSandbox = emptyTally();
		for (const { tool, input } of DEV_TASK_IN_SANDBOX) {
			const result = await outcome(mode, tool, input);
			recordLayer(layers, result);
			recordLayer(inSandbox, result);
		}
		for (const { tool, input } of DEV_TASK_CROSSING) recordLayer(layers, await outcome(mode, tool, input));
		return { layers, inSandbox };
	}

	it(`keeps ask-denied at or under ${ASK_DENIED_TARGET * 100}% of in-sandbox actions with a reviewer`, async () => {
		const { layers, inSandbox } = await tally("reviewer");
		expect(inSandbox.askDenied / DEV_TASK_IN_SANDBOX.length).toBeLessThanOrEqual(ASK_DENIED_TARGET);
		// The crossing still needs a person: the reviewer did not clear it.
		expect(layers.askDenied - inSandbox.askDenied).toBe(DEV_TASK_CROSSING.length);
		expect(layers.L3).toBeGreaterThan(layers.L1);
	});

	it("measures the deterministic baseline the reviewer improves on", async () => {
		const { inSandbox } = await tally("deterministic");
		// Every unreadable command needs a person in deterministic mode with
		// rules.onUncertain "ask": 17 of the 38 recorded actions.
		expect(inSandbox.askDenied).toBe(17);
		expect(inSandbox.askDenied / DEV_TASK_IN_SANDBOX.length).toBeGreaterThan(ASK_DENIED_TARGET);
		const sandboxed = await tally("sandbox");
		expect(sandboxed.inSandbox.askDenied).toBe(0);
		expect(sandboxed.inSandbox.sandboxedUncertain).toBe(17);
	});
});

describe("the per-session layer tally", () => {
	it("assigns every outcome to one layer or to none", () => {
		const outcomes: Record<GateOutcome, ReturnType<typeof decisionLayer>> = {
			allow: "L1",
			deny: "L1",
			"skip-review": "L1",
			"sandboxed-uncertain": "L1",
			"batch-withheld": "L1",
			"review-allow": "L3",
			"review-deny": "L3",
			"ask-approved": "L4",
			"ask-denied": "L4",
			"breaker-open": undefined,
			error: undefined,
		};
		for (const [name, layer] of Object.entries(outcomes)) expect(decisionLayer(name as GateOutcome)).toBe(layer);
	});

	it("counts and describes shares of decided actions", () => {
		const tally = emptyTally();
		expect(describeTally(tally)).toBe("no gate decisions yet");
		for (const name of ["allow", "sandboxed-uncertain", "review-allow", "ask-denied", "breaker-open"] as const) {
			recordLayer(tally, name);
		}
		expect(tally).toEqual({ L1: 2, L3: 1, L4: 1, askDenied: 1, sandboxedUncertain: 1, other: 1 });
		expect(describeTally(tally)).toBe(
			"L1 2 (50%), L3 1 (25%), L4 1 (25%), ask-denied 1, sandboxed-uncertain 1, not decided 1",
		);
	});
});
