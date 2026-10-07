/**
 * The tool allowlist.
 *
 * Tools pi-enclave does not own execute in the pi process with the user's full
 * privileges and never touch the sandbox. Pi 1.1's nested execution hooks apply
 * the same gate to codemode child calls and deferred MCP tools, but do not turn
 * those executors into OS-sandboxed tools. Deny them by default.
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
	// `Object.hasOwn`, not a plain lookup: `tools.allow["toString"]` (and
	// `constructor`, `hasOwnProperty`, …) inherits a truthy function from
	// Object.prototype, so a tool named after a prototype member would otherwise
	// read as an allowed grant it never had.
	const grant = Object.hasOwn(tools.allow, tool) ? tools.allow[tool] : undefined;

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

	const isOwned = owned.includes(tool);
	if (grant.source !== undefined && grant.source !== source) {
		return {
			allowed: false,
			reason:
				`pi-enclave: "${tool}" is allowed only from ${grant.source}, but this registration comes from ${source ?? "an unknown source"}.\n` +
				`  A tool name is not an identity: another extension registering the same name would otherwise inherit the grant.`,
		};
	}

	// A tool pi-enclave owns is sandboxed whatever the grant says; `readOnly`
	// and `reviewed` on it describe the action, not the enforcement.
	return {
		allowed: true,
		grant,
		readOnly: grant.readOnly === true,
		// Without a reviewer this goes straight to a human. With one, the model may
		// veto or recommend, but gate.ts still leaves the final unsandboxed permit
		// to the human.
		reviewed: grant.reviewed === true && !isOwned,
	};
}
