/**
 * `rules defaults` and `rules config`.
 *
 * These exist because a rulebook nobody can read is a rulebook nobody can
 * check. `defaults` prints what `"$defaults"` splices, so a user who is about
 * to take ownership of a list can see what they are giving up. `config` prints
 * the effective rulebook after the fold, with every entry tagged by the source
 * that contributed it, so "why is this denied?" has an answer that does not
 * require reading three files and simulating a merge.
 */

import { READ_ONLY_CLASSIFIER } from "../reviewer/classifier.ts";
import { type DefaultProfileOptions, defaultProfile } from "./defaults.ts";
import type { EffectiveProfile, Provenance, SourceId } from "./types.ts";
import { provenanceOf } from "./types.ts";

const LIST_PATHS = [
	"sandbox.writableRoots",
	"sandbox.readDeny",
	"sandbox.grantableReadDeny",
	"sandbox.env.passthrough",
	"sandbox.env.envDeny",
	"rules.deny",
	"rules.ask",
	"rules.skipReview",
	"rules.protectedPaths.deny",
	"rules.protectedPaths.ask",
	"review.environment",
	"review.hard_deny",
	"review.soft_deny",
	"review.allow",
] as const;

function listAt(profile: EffectiveProfile, path: string): readonly string[] {
	switch (path) {
		case "sandbox.writableRoots":
			return profile.sandbox.writableRoots;
		case "sandbox.readDeny":
			return profile.sandbox.readDeny;
		case "sandbox.grantableReadDeny":
			return profile.sandbox.grantableReadDeny;
		case "sandbox.env.passthrough":
			return profile.sandbox.env.passthrough;
		case "sandbox.env.envDeny":
			return profile.sandbox.env.envDeny;
		case "rules.deny":
			return profile.rules.deny;
		case "rules.ask":
			return profile.rules.ask;
		case "rules.skipReview":
			return profile.rules.skipReview;
		case "rules.protectedPaths.deny":
			return profile.rules.protectedPaths.deny;
		case "rules.protectedPaths.ask":
			return profile.rules.protectedPaths.ask;
		case "review.environment":
			return profile.review.environment;
		case "review.hard_deny":
			return profile.review.hard_deny;
		case "review.soft_deny":
			return profile.review.soft_deny;
		case "review.allow":
			return profile.review.allow;
		default:
			return [];
	}
}

/** `pi-enclave rules defaults` — the built-in lists, as JSON. */
export function renderDefaults(options: DefaultProfileOptions, readonlyOnly = false): string {
	const profile = defaultProfile(options);
	if (readonlyOnly) {
		return JSON.stringify(
			{
				note: "the shell table is versioned code and intentionally not configurable; unknown means mutating",
				tools: Object.fromEntries(
					Object.entries(profile.tools.allow)
						.filter(([, grant]) => grant.readOnly)
						.map(([name]) => [name, { readOnly: true }]),
				),
				shell: READ_ONLY_CLASSIFIER,
			},
			null,
			2,
		);
	}
	const out: Record<string, unknown> = {};
	for (const path of LIST_PATHS) out[path] = listAt(profile, path);
	out["tools.allow"] = profile.tools.allow;
	return JSON.stringify(out, null, 2);
}

/**
 * `pi-enclave rules config` — the effective rulebook, tagged by source.
 *
 * The output is the artefact the Phase-3 qualification hash is computed over,
 * so it is deterministic: lists keep their fold order and nothing is sorted
 * into a prettier arrangement.
 */
export function renderConfig(profile: EffectiveProfile, provenance: Provenance): string {
	const lines: string[] = [];
	lines.push(
		`profile: ${profile.name}${profile.auto ? "" : "   (L1/L4 disabled by PI_ENCLAVE_AUTO=off; the sandbox is still in force)"}`,
	);
	lines.push("");
	lines.push(`sandbox.mode           ${profile.sandbox.mode}`);
	lines.push(`sandbox.network        ${profile.sandbox.network.mode}`);
	lines.push(`sandbox.capabilities   ${profile.sandbox.capabilities}`);
	lines.push(`sandbox.hostExec       ${profile.sandbox.hostExec}`);
	lines.push(`sandbox.allowPty       ${profile.sandbox.allowPty}`);
	lines.push(`review.trigger         ${profile.review.trigger}`);
	lines.push(`reviewer.model         ${profile.reviewer.model}`);
	lines.push(
		`attended.mode          ${profile.attended.mode} (confirm timeout ${profile.attended.confirmTimeoutMs} ms)`,
	);
	lines.push(
		`breaker                ${profile.breaker.consecutive} consecutive, ${profile.breaker.window[0]} of ${profile.breaker.window[1]}`,
	);
	lines.push(`audit.retention        ${profile.audit.retentionDays} days / ${profile.audit.retentionMb} MB`);

	for (const path of LIST_PATHS) {
		const entries = listAt(profile, path);
		lines.push("");
		lines.push(`${path}${heading(path)}`);
		if (entries.length === 0) {
			lines.push("  (empty)");
			continue;
		}
		for (const entry of entries) {
			const source = provenanceOf(provenance, path, entry) ?? "builtin";
			lines.push(`  ${pad(source)}  ${entry}`);
		}
	}

	lines.push("");
	lines.push("tools.allow");
	for (const [name, grant] of Object.entries(profile.tools.allow)) {
		const source = provenanceOf(provenance, "tools.allow", name) ?? "builtin";
		const kind = grant.reviewed ? "reviewed" : grant.readOnly ? "read-only" : "allowed";
		const pin = grant.source ? `  pinned to ${grant.source}` : "";
		lines.push(`  ${pad(source)}  ${name} (${kind})${pin}`);
	}

	return lines.join("\n");
}

/**
 * `skipReview` is the one list that grants rather than restricts, so it says so
 * in its heading rather than sitting among the denials looking like one.
 */
function heading(path: string): string {
	if (path === "rules.skipReview") return "   — ALLOW (skips review)";
	if (path.startsWith("review.") && path !== "review.trigger") return "   — prose, read by the reviewer (Phase 3)";
	return "";
}

function pad(source: SourceId): string {
	return source.padEnd(14);
}
