/**
 * The tool allowlist.
 *
 * Tools pi-enclave does not own execute in the pi process with the user's full
 * privileges and never touch the sandbox. There is no hook in pi 0.84.2 that
 * would let an extension wrap another extension's tool execution, so the honest
 * answer is to deny by default and make the user name what they want.
 *
 * A note on vocabulary the README gets wrong: it calls these "MCP and custom
 * tools", but pi 0.84.2 has no MCP support at all -- no dependency, no setting,
 * no tool namespace. Every non-built-in tool arrives as a plain
 * `CustomToolCallEvent` with whatever flat name the registering extension
 * chose. An MCP bridge, when one exists, will be one of those.
 *
 * That is also why grants may pin a `source`. Names are not identities here:
 * two extensions can register `deploy`, and the one whose registration pi keeps
 * is decided by load order. A grant without a pin is a grant to whoever loads
 * first.
 */
import type { ToolGrant, ToolsSettings } from "../config/types.ts";

export type ToolDisposition =
	| { allowed: true; grant: ToolGrant; readOnly: boolean; reviewed: boolean }
	| { allowed: false; reason: string };

export interface ToolCheckOptions {
	tool: string;
	tools: ToolsSettings;
	/** The `sourceInfo.path` pi reports for the registering extension, if known. */
	source?: string;
	/** Tools pi-enclave executes inside the sandbox itself. */
	owned: readonly string[];
}

export function checkTool(options: ToolCheckOptions): ToolDisposition {
	const { tool, tools, source, owned } = options;
	const grant = tools.allow[tool];

	if (!grant) {
		const known = Object.keys(tools.allow).sort().join(", ");
		return {
			allowed: false,
			reason:
				`pi-enclave: "${tool}" is not in tools.allow, so it will not run in auto mode.\n` +
				`  Tools pi-enclave does not sandbox execute in the pi process with your full privileges.\n` +
				`  Allowed: ${known || "(nothing)"}.`,
		};
	}

	if (grant.source !== undefined && source !== undefined && grant.source !== source) {
		return {
			allowed: false,
			reason:
				`pi-enclave: "${tool}" is allowed only from ${grant.source}, but this registration comes from ${source}.\n` +
				`  A tool name is not an identity: another extension registering the same name would otherwise inherit the grant.`,
		};
	}

	// A tool pi-enclave owns is sandboxed whatever the grant says; `readOnly`
	// and `reviewed` on it describe the action, not the enforcement.
	const isOwned = owned.includes(tool);
	return {
		allowed: true,
		grant,
		readOnly: grant.readOnly === true,
		// Without a reviewer, `reviewed: true` cannot mean "a model looks at it".
		// It means the strongest thing still available, which is a human -- so an
		// unattended session denies it rather than running it unexamined.
		reviewed: grant.reviewed === true && !isOwned,
	};
}
