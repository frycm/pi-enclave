import { describe, expect, it } from "vitest";
import { defaultProfile } from "../../src/config/defaults.ts";
import { canonicalize } from "../../src/policy/canonical.ts";
import { buildReviewEvidence, MAX_EVIDENCE_JSON_BYTES } from "../../src/reviewer/evidence.ts";
import { enforceReview, minimumRisk } from "../../src/reviewer/risk.ts";

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
		const result = enforceReview({ decision: "allow", risk: "low", reason: "looks fine" }, proposed, PROFILE, evidence);
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
			enforceReview({ decision: "allow", risk: "low", reason: "requested" }, proposed, PROFILE, evidence),
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
			enforceReview({ decision: "allow", risk: "medium", reason: "specific" }, proposed, PROFILE, evidence),
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
				enforceReview({ decision: "allow", risk: "low", reason: "specific" }, proposed, PROFILE, evidence),
			).toMatchObject({ decision: "ask", authorizationCovers: false });
		}
	});

	it("requires a positive direct request for a high-risk read capability", () => {
		const configured = structuredClone(PROFILE);
		configured.sandbox.readDeny.push("/work/private");
		configured.sandbox.grantableReadDeny.push("/work/private");
		const proposed = action("cat /work/private/report", { allow_read: "/work/private" });
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
				enforceReview({ decision: "allow", risk: "low", reason: "specific" }, proposed, configured, evidence)
					.authorizationCovers,
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
			enforceReview({ decision: "allow", risk: "low", reason: "fine" }, proposed, PROFILE, evidence),
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
