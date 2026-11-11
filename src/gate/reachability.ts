/** Tool-declared reachability is bounded display evidence, never a grant. */
import type { ToolInfo } from "@earendil-works/pi-coding-agent";

export interface ToolReachability {
	provenance: "tool_declaration";
	scope: "all" | "hints" | "unknown";
	tools: string[];
	truncated: boolean;
}

/** Resolve pi's overmatching words against the currently registered tools/namespaces. */
export function toolReachability(
	tools: readonly ToolInfo[],
	name: string,
	input: Record<string, unknown>,
): ToolReachability | undefined {
	const tool = tools.find((entry) => entry.name === name);
	if (!tool?.reachesTools) return undefined;
	const unknown: ToolReachability = { provenance: "tool_declaration", scope: "unknown", tools: [], truncated: true };
	let reach: unknown;
	try {
		reach = tool.reachesTools(structuredClone(input));
	} catch {
		return unknown;
	}
	// Extension declarations are an input boundary. An invalid or excessive
	// declaration remains unknown rather than claiming a smaller action scope.
	if (
		reach !== "all" &&
		(!Array.isArray(reach) ||
			reach.length > 256 ||
			!reach.every((word) => typeof word === "string" && word.length <= 4096))
	)
		return unknown;
	const result: ToolReachability = {
		provenance: "tool_declaration",
		scope: reach === "all" ? "all" : "hints",
		tools: [],
		truncated: false,
	};
	for (const candidate of tools) {
		const identifiers = [
			candidate.name,
			candidate.name.replace(/[^a-zA-Z0-9_$]/g, "_"),
			...(candidate.namespace ? [candidate.namespace.name, ...(candidate.namespace.aliases ?? [])] : []),
		];
		if (
			reach !== "all" &&
			!(reach as string[]).some((word) =>
				identifiers.some((identifier) => identifier.length > 0 && word.includes(identifier)),
			)
		)
			continue;
		if (result.tools.length === 32) {
			result.truncated = true;
			break;
		}
		if (candidate.name.length > 256) result.truncated = true;
		result.tools.push(candidate.name.slice(0, 256));
	}
	return result;
}

export function describeReachability(value: ToolReachability): string {
	return `Tool-declared reachability (advisory; child calls still require policy checks): ${JSON.stringify(value)}`;
}
