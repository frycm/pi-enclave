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
import { parsePattern } from "../policy/match.ts";

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
		reviewed: isReviewedGrant(tool, grant, owned),
	};
}

/**
 * Does a call to this tool need a person, whatever `review.trigger` says (#22)?
 *
 * For a tool pi-enclave does not own, the only grant that runs it without one
 * is an explicit `readOnly: true`. A bare `{}` is the natural spelling for an
 * owned tool, where L2 applies, and the same spelling on an MCP or extension
 * tool used to mean full user privileges with no review in deterministic mode
 * and with `trigger: "boundary"`. It now means `reviewed`: without a reviewer
 * the call goes straight to a human, and with one the model may veto or
 * recommend but gate.ts still leaves the final unsandboxed permit to the human.
 */
export function isReviewedGrant(tool: string, grant: ToolGrant, owned: readonly string[]): boolean {
	if (owned.includes(tool)) return false;
	return grant.readOnly !== true;
}

/** Hints a tool declares about itself, with the meaning of MCP tool annotations. */
export interface DeclaredHints {
	readOnlyHint?: boolean;
	destructiveHint?: boolean;
}

/** The part of pi's `ToolInfo` the grant checks read. */
export interface RegisteredToolInfo {
	name: string;
	annotations?: DeclaredHints;
	sourceInfo?: { path?: string };
}

/**
 * Warnings about grants on tools that run outside the sandbox, for session start.
 *
 * The declared hints are written by the tool's author, so they only ever
 * narrow: a `readOnly: true` grant on a tool that says it is not read-only, or
 * that it is destructive, is worth a warning; a hint never widens a grant.
 */
export function grantWarnings(
	tools: ToolsSettings,
	registered: readonly RegisteredToolInfo[],
	owned: readonly string[],
): string[] {
	const warnings: string[] = [];
	for (const [name, grant] of Object.entries(tools.allow)) {
		if (owned.includes(name)) continue;
		const info = registered.find((entry) => entry.name === name);
		if (grant.readOnly === true && info?.annotations) {
			const said: string[] = [];
			if (info.annotations.readOnlyHint === false) said.push("readOnlyHint: false");
			if (info.annotations.destructiveHint === true) said.push("destructiveHint: true");
			if (said.length > 0) {
				warnings.push(
					`pi-enclave: tools.allow marks "${name}" readOnly, but the tool declares ${said.join(" and ")}. ` +
						"It runs outside the sandbox with no review or approval. Use reviewed: true unless you are sure.",
				);
			}
		}
		if (grant.source === undefined) {
			warnings.push(
				`pi-enclave: the grant for "${name}" has no source pin, so whichever extension registers that name first inherits it. ` +
					`Pin it with tools.allow.${name}.source${info?.sourceInfo?.path ? ` = "${info.sourceInfo.path}"` : ""}.`,
			);
		}
	}
	return warnings;
}

/** One way a tool can run outside the sandbox without a person deciding. */
export interface UnsandboxedPermit {
	tool: string;
	/** `readOnly` grant, or the user-global `skipReview` pattern that admits it. */
	via: string;
}

/**
 * Every tool that can run outside the sandbox without a human, for `/enclave status`.
 *
 * Two routes exist: a `readOnly: true` grant on a tool pi-enclave does not own,
 * and a user-global `rules.skipReview` pattern that names a granted non-owned
 * tool. Both are explicit, and listing them in one place makes the exposure
 * visible without reading the configuration.
 */
export function unsandboxedPermits(
	tools: ToolsSettings,
	skipReview: readonly string[],
	owned: readonly string[],
): UnsandboxedPermit[] {
	const permits: UnsandboxedPermit[] = [];
	for (const [name, grant] of Object.entries(tools.allow)) {
		if (owned.includes(name)) continue;
		if (grant.readOnly === true) permits.push({ tool: name, via: "readOnly grant" });
		for (const pattern of skipReview) {
			const parsed = parsePattern(pattern);
			if (!parsed.invalid && parsed.tool === name.toLowerCase())
				permits.push({ tool: name, via: `skipReview ${pattern}` });
		}
	}
	return permits;
}

/**
 * The declared hints of a tool outside the sandbox, as one line for the approval dialog.
 *
 * Only for tools pi-enclave does not own: for an owned tool the hints describe
 * pi's built-in, not what the sandbox lets it do.
 */
export function describeDeclaredHints(
	tool: string,
	registered: readonly RegisteredToolInfo[],
	owned: readonly string[],
): string | undefined {
	if (owned.includes(tool)) return undefined;
	const hints = registered.find((entry) => entry.name === tool)?.annotations;
	const parts: string[] = [];
	if (hints?.readOnlyHint !== undefined) parts.push(`readOnlyHint: ${hints.readOnlyHint}`);
	if (hints?.destructiveHint !== undefined) parts.push(`destructiveHint: ${hints.destructiveHint}`);
	return parts.length > 0
		? `  the tool declares ${parts.join(", ")} (its author's claim; it runs outside the sandbox)`
		: `  the tool declares no read-only or destructive hint; it runs outside the sandbox`;
}
