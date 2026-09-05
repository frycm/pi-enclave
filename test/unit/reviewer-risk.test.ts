import { describe, expect, it } from "vitest";
import { defaultProfile } from "../../src/config/defaults.ts";
import { canonicalize } from "../../src/policy/canonical.ts";
import { buildReviewEvidence, MAX_EVIDENCE_JSON_BYTES } from "../../src/reviewer/evidence.ts";
import { directAuthorizationCovers, enforceReview, minimumRisk } from "../../src/reviewer/risk.ts";

const PROFILE = defaultProfile({ cwd: "/work", home: "/home/u", tmp: "/tmp", agentDir: "/home/u/.pi/agent" });

function action(command: string, input: Record<string, unknown> = {}) {
	return canonicalize({
		tool: "bash",
		input: { command, ...input },
		cwd: "/work",
		home: "/home/u",
		profileName: "dev",
		writableRoots: PROFILE.sandbox.writableRoots,
	});
}

describe("deterministic reviewer risk", () => {
	it("raises a destructive shell action to high", () => {
		expect(minimumRisk(action("rm -rf build"), PROFILE)).toBe("high");
	});

	it("raises a broad capability to critical", () => {
		expect(minimumRisk(action("touch /etc/x", { allow_write: "/" }), PROFILE)).toBe("critical");
	});

	it("raises a system-tree write capability to critical", () => {
		expect(minimumRisk(action("touch /etc/x", { allow_write: "/etc/x" }), PROFILE)).toBe("critical");
	});

	it("rates an exact grantable read capability high, while an unconfigured one is critical", () => {
		const configured = structuredClone(PROFILE);
		configured.sandbox.readDeny.push("/work/private");
		configured.sandbox.grantableReadDeny.push("/work/private");
		expect(minimumRisk(action("cat /work/private/report", { allow_read: "/work/private" }), configured)).toBe("high");
		expect(minimumRisk(action("cat /work/other/report", { allow_read: "/work/other" }), configured)).toBe("critical");
	});

	it("does not treat every ordinary absolute write as a root write", () => {
		expect(minimumRisk(action("touch /work/output.txt"), PROFILE)).toBe("medium");
	});

	it("never permits critical risk even when the model says allow/low", () => {
		const proposed = action("touch /etc/x", { allow_write: "/" });
		const evidence = buildReviewEvidence({ action: proposed, trigger: "capability", attended: "tui" });
		const result = enforceReview(
			{ decision: "allow", risk: "low", reason: "looks fine" },
			proposed,
			PROFILE,
			evidence,
			evidence.authorization,
		);
		expect(result.decision).toBe("deny");
		expect(result.risk).toBe("critical");
		expect(result.modelRisk).toBe("low");
	});

	it("turns an uncovered high-risk allow into ask", () => {
		const proposed = action("rm -rf build");
		const evidence = buildReviewEvidence({
			action: proposed,
			trigger: "mutating",
			attended: "tui",
			authorization: [{ provenance: "direct", channel: "interactive", text: "clean up the repo" }],
		});
		expect(
			enforceReview(
				{ decision: "allow", risk: "low", reason: "requested" },
				proposed,
				PROFILE,
				evidence,
				evidence.authorization,
			),
		).toMatchObject({
			decision: "ask",
			risk: "high",
			authorizationCovers: false,
		});
	});

	it("accepts an exact direct authorization for an effective-high action", () => {
		const proposed = action("rm -rf build");
		const evidence = buildReviewEvidence({
			action: proposed,
			trigger: "mutating",
			attended: "tui",
			authorization: [{ provenance: "direct", channel: "interactive", text: "Please run rm -rf build" }],
		});
		expect(
			enforceReview(
				{ decision: "allow", risk: "medium", reason: "specific" },
				proposed,
				PROFILE,
				evidence,
				evidence.authorization,
			),
		).toMatchObject({
			decision: "allow",
			risk: "high",
			authorizationCovers: true,
		});
	});

	it("does not mistake a prohibition or a question for high-risk authorization", () => {
		const proposed = action("rm -rf build");
		for (const text of [
			"Do not run rm -rf build",
			"Can you explain what rm -rf build does?",
			"Should I run rm -rf build?",
		]) {
			const evidence = buildReviewEvidence({
				action: proposed,
				trigger: "mutating",
				attended: "tui",
				authorization: [{ provenance: "direct", channel: "interactive", text }],
			});
			expect(
				enforceReview(
					{ decision: "allow", risk: "low", reason: "specific" },
					proposed,
					PROFILE,
					evidence,
					evidence.authorization,
				),
			).toMatchObject({ decision: "ask", authorizationCovers: false });
		}
	});

	it("requires a positive direct request for a high-risk read capability", () => {
		const configured = structuredClone(PROFILE);
		configured.sandbox.readDeny.push("/work/private");
		configured.sandbox.grantableReadDeny.push("/work/private");
		const proposed = canonicalize({
			tool: "read",
			input: { path: "/work/private/report", allow_read: "/work/private" },
			cwd: "/work",
			home: "/home/u",
			profileName: "dev",
		});
		for (const [text, covered] of [
			["Please read /work/private", true],
			["Retry with allow_read=/work/private", true],
			["Never read /work/private", false],
			["What does allow_read=/work/private mean?", false],
		] as const) {
			const evidence = buildReviewEvidence({
				action: proposed,
				trigger: "capability",
				attended: "tui",
				authorization: [{ provenance: "direct", channel: "interactive", text }],
			});
			expect(
				enforceReview(
					{ decision: "allow", risk: "low", reason: "specific" },
					proposed,
					configured,
					evidence,
					evidence.authorization,
				).authorizationCovers,
			).toBe(covered);
		}
	});

	it("raises bounded action evidence to high and refuses an uncovered allow", () => {
		const proposed = canonicalize({
			tool: "write",
			input: { path: "/work/large.txt", content: "x".repeat(20_000) },
			cwd: "/work",
			home: "/home/u",
			profileName: "dev",
			writableRoots: PROFILE.sandbox.writableRoots,
		});
		const evidence = buildReviewEvidence({ action: proposed, trigger: "mutating", attended: "off" });
		expect(evidence.action.truncated).toBe(true);
		expect(JSON.stringify(evidence).length).toBeLessThan(32_768);
		expect(
			enforceReview(
				{ decision: "allow", risk: "low", reason: "fine" },
				proposed,
				PROFILE,
				evidence,
				evidence.authorization,
			),
		).toMatchObject({
			decision: "ask",
			risk: "high",
		});
	});

	it("keeps adversarial structures and escaped text inside the hard evidence byte bound", () => {
		const proposed = canonicalize({
			tool: "write",
			input: {
				path: "/work/large.txt",
				content: "\u0000".repeat(20_000),
				metadata: Array.from({ length: 100_000 }, () => false),
			},
			cwd: "/work",
			home: "/home/u",
			profileName: "dev",
			writableRoots: PROFILE.sandbox.writableRoots,
		});
		const evidence = buildReviewEvidence({
			action: proposed,
			trigger: "mutating",
			attended: "off",
			violation: {
				kind: "write",
				source: "kernel-log",
				op: "file-write",
				backend: "bwrap",
				raw: "\u0000".repeat(100_000),
			},
			authorization: Array.from({ length: 8 }, () => ({
				provenance: "direct" as const,
				channel: "interactive" as const,
				text: "\u0000".repeat(10_000),
			})),
		});
		expect(evidence.action.truncated).toBe(true);
		expect(Buffer.byteLength(JSON.stringify(evidence))).toBeLessThanOrEqual(MAX_EVIDENCE_JSON_BYTES);
	});
});

describe("complete current authorization", () => {
	const authorizations = (...texts: string[]) =>
		texts.map((text) => ({ provenance: "direct" as const, channel: "interactive" as const, text }));
	function review(command: string, texts: string[], input: Record<string, unknown> = {}) {
		const proposed = action(command, input);
		const authorization = authorizations(...texts);
		const evidence = buildReviewEvidence({ action: proposed, trigger: "mutating", attended: "off", authorization });
		return enforceReview(
			{ decision: "allow", risk: "low", reason: "optimistic fixture" },
			proposed,
			PROFILE,
			evidence,
			authorization,
		);
	}
	it("does not authorize hidden command operands or hidden authorization qualifications", () => {
		expect(
			review(`rm -rf build/cache${" ".repeat(2100)} build/important`, ["Please run rm -rf build/cache"]).decision,
		).toBe("ask");
		expect(review("rm -rf build", [`Please run rm -rf build${" ".repeat(2100)} but do not execute it`]).decision).toBe(
			"ask",
		);
	});
	it.each([
		["Please run rm -rf build"],
		["Please run rm -rf BUILD", "Do not run rm -rf BUILD"],
		["Please run rm -rf BUILD", "Wait"],
		["Please run rm -rf BUILD only after I confirm"],
	])("requires case-exact, current and unconditional scope: %j", (...texts) => {
		expect(review("rm -rf BUILD", texts).authorizationCovers).toBe(false);
	});
	it("preserves exact command and full hash authorizations, including long commands", () => {
		const command = `rm -rf build/${"x".repeat(2200)}`;
		expect(review(command, [`Please run ${command}`]).authorizationCovers).toBe(true);
		expect(review(command, [`I approve ${action(command).hash}`]).authorizationCovers).toBe(true);
		expect(review("rm -rf BUILD", ["Do not run rm -rf BUILD", "Please run rm -rf BUILD"]).decision).toBe("allow");
	});
	it("never derives authority from bounded display data alone", () => {
		const proposed = action("rm -rf build");
		const evidence = buildReviewEvidence({
			action: proposed,
			trigger: "mutating",
			attended: "off",
			authorization: authorizations("Please run rm -rf build"),
		});
		expect(
			enforceReview({ decision: "allow", risk: "low", reason: "fixture" }, proposed, PROFILE, evidence).decision,
		).toBe("ask");
	});
	it("requires complete-action approval for Bash capability requests with additional effects", () => {
		const proposed = action("cat /work/private/report; rm -rf /work/public", { allow_read: "/work/private" });
		expect(directAuthorizationCovers(proposed, authorizations("Please read /work/private"))).toBe(false);
		expect(directAuthorizationCovers(proposed, authorizations(`Approve ${proposed.hash}`))).toBe(true);
	});
	it("does not confuse case-distinct read capability roots", () => {
		const proposed = canonicalize({
			tool: "read",
			input: { path: "/work/Private/report", allow_read: "/work/Private" },
			cwd: "/work",
			home: "/home/u",
			profileName: "dev",
		});
		expect(directAuthorizationCovers(proposed, authorizations("Please read /work/private"))).toBe(false);
	});
});
