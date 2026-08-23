/**
 * Who owns the tools, and what else is loaded.
 *
 * The README described this as a load-order check against an extension that
 * registers `bash` *after* pi-enclave. Verified against pi 0.84.2, the
 * direction is the other way round, and the difference decides what the check
 * has to be:
 *
 * - Within one extension, the last `registerTool` for a name wins.
 * - **Across extensions, the first in load order wins** (`runner.ts:451-461`):
 *   a later extension cannot displace an earlier one's tool.
 * - Extension tools always override built-ins.
 *
 * So an extension loaded *after* pi-enclave that registers `bash` is simply
 * ignored by pi and needs no handling at all. The dangerous one is loaded
 * *before* us: its `bash` wins, ours is discarded, and the sandbox is silently
 * not in the path. That is invisible to load-order reasoning and completely
 * visible in `getAllTools()`, which reports the `sourceInfo.path` of whoever
 * registered each tool. The check is therefore about *ownership*, not order.
 *
 * What it cannot see is another extension's `tool_call` handler. pi exposes no
 * API for enumerating extensions or handlers. One loaded after us cannot change
 * a frozen input; one loaded before us is inside the trusted-extension boundary
 * the threat model already accepts and states as a residual risk.
 */
import { existsSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { OWNED_TOOLS } from "../config/defaults.ts";

/** The subset of pi's `ToolInfo` this module needs. */
export interface ToolOwnership {
	name: string;
	sourceInfo?: { path?: string; scope?: string };
}

export interface OwnershipProblem {
	kind: "foreign-tool" | "missing-tool" | "project-extension";
	message: string;
}

export interface OwnershipOptions {
	/** From `pi.getAllTools()`. */
	tools: readonly ToolOwnership[];
	/** The path pi reports for pi-enclave's own registrations. */
	ownPath: string;
	cwd: string;
	projectTrusted: boolean;
	/** Injected by tests. */
	listProjectExtensions?: (cwd: string) => string[];
}

/**
 * Check that pi-enclave owns every tool it is supposed to, and that no
 * project-scoped extension is loaded.
 *
 * Returns problems rather than throwing; the caller decides that auto mode
 * refuses, and needs all of them to report at once.
 */
export function checkOwnership(options: OwnershipOptions): OwnershipProblem[] {
	const problems: OwnershipProblem[] = [];
	const byName = new Map(options.tools.map((tool) => [tool.name, tool]));

	for (const name of OWNED_TOOLS) {
		const tool = byName.get(name);
		if (!tool) {
			problems.push({
				kind: "missing-tool",
				message: `"${name}" is not registered at all, so pi-enclave cannot sandbox it.`,
			});
			continue;
		}
		const path = tool.sourceInfo?.path;
		if (path !== options.ownPath) {
			problems.push({
				kind: "foreign-tool",
				message: `"${name}" is provided by ${path ?? "an unknown source"}, not by pi-enclave. pi keeps the first extension's registration, so an extension loaded before pi-enclave takes the tool and the sandbox is not in its path.`,
			});
		}
	}

	// A project-scoped extension is one the sandboxed agent can write, and it
	// runs in the pi process with the user's privileges. pi will not load one
	// from an untrusted project, so this only fires where trust was granted --
	// which is exactly where the agent's own writes become executable code.
	if (options.projectTrusted) {
		const list = options.listProjectExtensions ?? listProjectExtensions;
		const found = list(options.cwd);
		if (found.length > 0) {
			problems.push({
				kind: "project-extension",
				message: `this project carries extensions the sandboxed agent can write (${found.join(", ")}). They execute in the pi process with your privileges and are outside the sandbox. Move them to ~/.pi/agent/extensions, or run without trusting this project.`,
			});
		}
		for (const tool of options.tools) {
			if (tool.sourceInfo?.scope === "project") {
				problems.push({
					kind: "project-extension",
					message: `the tool "${tool.name}" comes from a project-scoped extension (${tool.sourceInfo.path ?? "unknown path"}), which the agent can write and which runs outside the sandbox.`,
				});
			}
		}
	}

	return problems;
}

/** Entries pi would load from `<cwd>/.pi/extensions`, one level deep. */
export function listProjectExtensions(cwd: string): string[] {
	const dir = join(cwd, ".pi", "extensions");
	if (!existsSync(dir)) return [];
	try {
		return readdirSync(dir).filter((entry) => !entry.startsWith("."));
	} catch {
		// An unreadable extensions directory is reported as present: refusing on
		// a directory we cannot inspect is the safe direction.
		return ["<unreadable>"];
	}
}

export function formatOwnershipProblems(problems: readonly OwnershipProblem[]): string {
	return [
		"pi-enclave: refusing to enter auto mode.",
		...problems.map((problem) => `  ${problem.message}`),
		"  Auto mode needs every sandboxed tool to be pi-enclave's own.",
	].join("\n");
}
