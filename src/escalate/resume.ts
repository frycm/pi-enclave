/**
 * Resuming an approved action, and the four checks that stand between the
 * approval and the execution.
 *
 * The subtle one is the last. A record carries the profile it was evaluated
 * under, and the obvious thing to do with that is execute under it -- which
 * would be wrong, and wrong in the direction that matters. The snapshot is
 * **evidence for the approver and an upper bound for the check**, never an
 * execution input. If the user has since removed a writable root or re-added a
 * `readDeny` entry, the resumed action runs under the narrower profile they
 * have now; the grant they removed is simply not there. If they have *widened*
 * config since, the resume is refused rather than quietly taking advantage of
 * it, because nobody approved the wider version.
 *
 * The other three:
 *
 * - **The hash is re-derived**, not read. The recorded hash is what the
 *   approver saw described; re-canonicalizing the recorded input and comparing
 *   is what proves the description matched the action.
 * - **L1 runs again, under the configuration as it is now.** A rule added since
 *   the record was written denies it. An approval is permission to proceed past
 *   an `ask`, never permission to bypass a `deny`.
 * - **The record is single-use**, enforced by renaming it out of `pending/`
 *   before anything runs.
 */

import { OWNED_TOOLS } from "../config/defaults.ts";
import { narrowerOrEqual, type OrderViolation } from "../config/merge.ts";
import type { EffectiveProfile } from "../config/types.ts";
import { checkTool } from "../gate/tools.ts";
import { type CanonicalAction, canonicalize } from "../policy/canonical.ts";
import type { RuleMatch } from "../policy/match.ts";
import { evaluateRules } from "../policy/match.ts";
import { matchesPathPattern } from "../policy/paths.ts";
import type { PendingRecord } from "./pending.ts";

export type ResumeCheck = { ok: true; action: CanonicalAction } | { ok: false; reason: string; detail?: string[] };

export interface ResumeOptions {
	record: PendingRecord;
	/** The configuration as it is *now*, not as the record remembers it. */
	current: EffectiveProfile;
	home: string;
}

/**
 * Run every check. Returns the action to execute, or the reason not to.
 *
 * Deliberately does not execute anything: the caller owns the backend, and a
 * function that both decides and acts is one whose decision cannot be tested on
 * its own.
 */
export function checkResume(options: ResumeOptions): ResumeCheck {
	const { record, current, home } = options;

	// 1. Re-derive the hash from the recorded input.
	const action = canonicalize({
		tool: record.action.tool,
		input: record.action.input,
		cwd: record.action.cwd,
		home,
		profileName: current.name,
		writableRoots: current.sandbox.writableRoots,
	});

	// The profile name is part of the canonical form, so a record written under
	// a different profile is compared on its own terms and the profile change
	// is reported by the order check below rather than as a hash mismatch.
	const recorded = canonicalize({
		tool: record.action.tool,
		input: record.action.input,
		cwd: record.action.cwd,
		home,
		profileName: record.action.profileName,
	});
	if (recorded.hash !== record.action.hash) {
		return {
			ok: false,
			reason: "the record's action does not hash to the value stored with it -- the file was edited",
			detail: [`recorded: ${record.action.hash}`, `derived:  ${recorded.hash}`],
		};
	}
	const recordedCapability = record.action.capability;
	if (
		recorded.capability?.kind !== recordedCapability?.kind ||
		recorded.capability?.value !== recordedCapability?.value
	) {
		return {
			ok: false,
			reason: "the record's capability metadata does not match the hash-checked action input -- the file was edited",
		};
	}

	// Revocation is a narrowing, but it is also an explicit veto. The partial
	// order below cannot substitute for re-authorizing the mechanism needed by
	// this exact action under current policy.
	if (action.capability && current.sandbox.capabilities !== "reviewed") {
		return { ok: false, reason: "the current profile has disabled capability requests" };
	}
	// The approval CLI has no live Pi registry to query, so it must use the
	// independently observed sourceInfo.path stored when the action was gated.
	// A legacy record without that evidence still works under an unpinned grant,
	// but fails closed when current policy requires an implementation identity.
	const tool = checkTool({
		tool: action.tool,
		tools: current.tools,
		owned: OWNED_TOOLS,
		...(record.toolSource !== undefined ? { source: record.toolSource } : {}),
	});
	if (!tool.allowed) {
		return { ok: false, reason: "the current profile no longer authorizes this tool", detail: [tool.reason] };
	}

	// 2. Host execution is not grantable by any profile in this version.
	if (record.requiresHuman && current.sandbox.hostExec !== "human") {
		return { ok: false, reason: 'this asked for unsandboxed host execution, and the profile has hostExec "never"' };
	}

	// 3. L1 again, under the current configuration.
	const evaluation = evaluateRules(action, current.rules, {
		protectedMatcher: (patterns) => {
			const matches: RuleMatch[] = [];
			for (const path of action.paths) {
				if (!path.writes) continue;
				const pattern = matchesPathPattern(patterns, path.resolved, action.cwd);
				if (pattern) matches.push({ list: "ask", pattern, target: path.resolved });
			}
			return matches;
		},
	});
	if (evaluation.verdict === "deny") {
		return {
			ok: false,
			reason: "the current policy denies this action outright; an approval is not a way past a deny rule",
			detail: evaluation.decisive.map((match) => `${match.list}: ${match.pattern} matched "${match.target}"`),
		};
	}

	// 4. The current profile must be no wider than the one that was approved.
	const violations: OrderViolation[] = narrowerOrEqual(current, record.profileSnapshot);
	if (violations.length > 0) {
		return {
			ok: false,
			reason: "the configuration has been widened since this record was written, and nobody approved the wider version",
			detail: violations.map((violation) => `${violation.field}: ${violation.message}`),
		};
	}

	return { ok: true, action };
}

/**
 * What changed between the snapshot and now, for the approver to read.
 *
 * A narrowing is not an error, but it does change what will happen -- a
 * writable root that has gone means the action may now fail where it would have
 * succeeded -- so it is shown rather than silently applied.
 */
export function describeNarrowing(record: PendingRecord, current: EffectiveProfile): string[] {
	const notes: string[] = [];
	const before = record.profileSnapshot;

	const lostRoots = before.sandbox.writableRoots.filter((root) => !current.sandbox.writableRoots.includes(root));
	if (lostRoots.length > 0) notes.push(`no longer writable: ${lostRoots.join(", ")}`);

	const addedDenies = current.sandbox.readDeny.filter((path) => !before.sandbox.readDeny.includes(path));
	if (addedDenies.length > 0) notes.push(`newly denied for reading: ${addedDenies.join(", ")}`);

	const addedRules = [
		...current.rules.deny.filter((rule) => !before.rules.deny.includes(rule)).map((rule) => `deny ${rule}`),
		...current.rules.ask.filter((rule) => !before.rules.ask.includes(rule)).map((rule) => `ask ${rule}`),
	];
	if (addedRules.length > 0) notes.push(`rules added since: ${addedRules.join(", ")}`);

	if (current.name !== before.name) notes.push(`the profile changed from "${before.name}" to "${current.name}"`);

	return notes;
}

export function formatResumeFailure(check: Extract<ResumeCheck, { ok: false }>): string {
	return [
		"pi-enclave: refusing to resume.",
		`  ${check.reason}`,
		...(check.detail ?? []).map((line) => `  ${line}`),
	].join("\n");
}
