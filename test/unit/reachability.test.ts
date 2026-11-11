import type { ToolInfo } from "@earendil-works/pi-coding-agent";
import { describe, expect, it } from "vitest";
import { defaultProfile } from "../../src/config/defaults.ts";
import { decide } from "../../src/gate/gate.ts";
import { ActionLock } from "../../src/gate/lock.ts";
import { toolReachability } from "../../src/gate/reachability.ts";
import { canonicalize } from "../../src/policy/canonical.ts";
import { buildReviewEvidence } from "../../src/reviewer/evidence.ts";

function tools(reachesTools: NonNullable<ToolInfo["reachesTools"]>): ToolInfo[] {
	return [
		{ name: "orchestrate", description: "", parameters: {}, reachesTools },
		{ name: "mcp__docs__read", description: "", parameters: {}, namespace: { name: "mcp__docs", aliases: ["docs"] } },
		{ name: "write", description: "", parameters: {} },
	].map((entry) => ({ ...entry, ...metadata }));
}

const metadata = {
	exposure: "direct" as const,
	sourceInfo: { path: "<test>", source: "test", scope: "user" as const, origin: "top-level" as const },
};

describe("advisory tool reachability", () => {
	it("matches tool and namespace words without exposing code or changing frozen input", () => {
		const input = Object.freeze({ code: "PRIVATE_CODE" });
		const result = toolReachability(
			tools((copy) => {
				copy.code = "changed";
				return ["tools.mcp__docs__read"];
			}),
			"orchestrate",
			input,
		);
		expect(result).toMatchObject({ provenance: "tool_declaration", scope: "hints", tools: ["mcp__docs__read"] });
		expect(input.code).toBe("PRIVATE_CODE");
		expect(JSON.stringify(result)).not.toContain("PRIVATE_CODE");
		expect(
			toolReachability(
				tools(() => ["docs"]),
				"orchestrate",
				{},
			)?.tools,
		).toEqual(["mcp__docs__read"]);
	});

	it("bounds all-tools declarations and treats broken declarations as unknown", () => {
		const entries = [
			...tools(() => "all"),
			...Array.from({ length: 50 }, (_, index) => ({
				name: `tool_${index}`,
				description: "",
				parameters: {},
				...metadata,
			})),
		];
		expect(toolReachability(entries, "orchestrate", {})).toMatchObject({ scope: "all", truncated: true });
		expect(toolReachability(entries, "orchestrate", {})?.tools).toHaveLength(32);
		expect(
			toolReachability(
				tools(() => {
					throw new Error("PRIVATE_ERROR");
				}),
				"orchestrate",
				{},
			),
		).toEqual({ provenance: "tool_declaration", scope: "unknown", tools: [], truncated: true });
	});

	it("labels declarations in reviewer evidence without treating them as authorization", () => {
		const reachability = toolReachability(
			tools(() => ["write"]),
			"orchestrate",
			{},
		);
		const action = canonicalize({
			tool: "orchestrate",
			input: { code: "run" },
			cwd: "/work",
			home: "/home/u",
			profileName: "dev",
		});
		const evidence = buildReviewEvidence({
			action,
			trigger: "mutating",
			attended: "off",
			...(reachability ? { toolReachability: reachability } : {}),
		});
		expect(evidence.toolReachability).toMatchObject({ provenance: "tool_declaration", tools: ["write"] });
		expect(evidence.authorization).toEqual([]);
	});

	it("cannot let a declared no-tool script bypass a denial of its actual child", async () => {
		const profile = defaultProfile({ cwd: "/work", home: "/home/u", agentDir: "/home/u/.pi/agent" });
		profile.rules.deny.push("write(**/blocked.txt)");
		expect(
			toolReachability(
				tools(() => []),
				"orchestrate",
				{},
			),
		).toMatchObject({ scope: "hints", tools: [] });
		const decision = await decide(
			{ toolName: "write", toolCallId: "child", input: { path: "/work/blocked.txt", content: "denied" } },
			{ profile, cwd: "/work", home: "/home/u", lock: new ActionLock(), owned: ["write"] },
		);
		expect(decision.block).toBe(true);
		expect(decision.outcome).toBe("deny");
	});
});
