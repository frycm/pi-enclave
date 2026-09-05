import { resolveCapabilityTarget } from "../backend/capability.ts";
import { canonical, isUnderAny, normalizePath } from "../backend/paths.ts";
import type { EffectiveProfile } from "../config/types.ts";
import type { CanonicalAction } from "../policy/canonical.ts";
import type { EffectiveReview, ModelReview, ReviewAuthorization, ReviewEvidence, ReviewRisk } from "./types.ts";

const RISK_RANK: Record<ReviewRisk, number> = { low: 0, medium: 1, high: 2, critical: 3 };

const HIGH_RISK_COMMANDS = new Set(["chmod", "chown", "dd", "kill", "pkill", "rm", "truncate"]);
const CRITICAL_TREES = ["/etc", "/bin", "/sbin", "/usr", "/System", "/Library"];

export function maxRisk(a: ReviewRisk, b: ReviewRisk): ReviewRisk {
	return RISK_RANK[a] >= RISK_RANK[b] ? a : b;
}

function broadCapability(value: string): boolean {
	const normalized = value.replace(/\/+$/, "") || "/";
	return normalized === "/" || normalized.split("/").filter(Boolean).length <= 1;
}

function destructiveShell(action: CanonicalAction): boolean {
	return (
		action.shell?.commands.some((command) => {
			const name = command.name.slice(command.name.lastIndexOf("/") + 1).toLowerCase();
			if (HIGH_RISK_COMMANDS.has(name)) return true;
			if (name === "git" && ["push", "reset", "clean", "checkout", "restore"].includes(command.args[0] ?? "")) {
				return true;
			}
			if (name === "gh" && command.args.some((arg) => ["-X", "--method=DELETE", "DELETE"].includes(arg))) return true;
			return false;
		}) ?? false
	);
}

function criticalWriteTarget(path: string): boolean {
	const normalized = normalizePath(path);
	if (normalized === "/" || canonical(normalized) === "/") return true;
	return isUnderAny(normalized, CRITICAL_TREES);
}

export function minimumRisk(action: CanonicalAction, profile: EffectiveProfile): ReviewRisk {
	if (action.capability?.kind === "host") return "critical";
	if (action.capability?.kind === "read") {
		if (broadCapability(action.capability.value)) return "critical";
		const target = resolveCapabilityTarget(action.cwd, action.capability.value);
		if (!profile.sandbox.grantableReadDeny.some((entry) => canonical(entry) === target)) return "critical";
		return "high";
	}
	if (action.capability?.kind === "write") {
		if (broadCapability(action.capability.value)) return "critical";
		const target = resolveCapabilityTarget(action.cwd, action.capability.value);
		if (criticalWriteTarget(target)) return "critical";
		if (action.paths.some((path) => isUnderAny(path.resolved, profile.sandbox.readDeny))) return "critical";
		return "high";
	}
	if (action.paths.some((path) => path.writes && criticalWriteTarget(path.resolved))) return "critical";
	if (destructiveShell(action)) return "high";
	if (action.tool === "write" || action.tool === "edit" || action.paths.some((path) => path.writes)) return "medium";
	if (action.tool === "bash" && !action.confident) return "high";
	return "low";
}

// Request grammar is case-insensitive; executable data is byte-exact. A suffix
// may qualify or revoke a request, so it cannot be ignored as display prose.
function exactRequest(text: string, verbs: readonly string[], object: string): boolean {
	const prefix =
		/^(?:(?:please|could you|can you|would you|go ahead and|you may|i authorize you to|i approve) )?([a-z]+) /i.exec(
			text,
		);
	return !!prefix && verbs.includes((prefix[1] ?? "").toLowerCase()) && text.slice(prefix[0].length) === object;
}

/** Only the newest complete direct instruction may establish high-risk coverage. */
export function directAuthorizationCovers(
	action: CanonicalAction,
	authorization: readonly ReviewAuthorization[],
): boolean {
	const entry = authorization.at(-1);
	if (!entry || entry.provenance !== "direct") return false;
	const text = entry.text.trim();
	if (
		exactRequest(text, ["approve", "authorize", "allow"], action.hash) ||
		exactRequest(text.replace(/^i /i, ""), ["approve", "authorize", "allow"], action.hash)
	)
		return true;
	if (action.capability) {
		// A grant alone never authorizes extra shell effects or write contents.
		// Such actions require the full action hash, covering command AND grant.
		if (!["read", "ls", "find", "grep"].includes(action.tool) || action.capability.kind !== "read") return false;
		const target = action.capability.value;
		if (exactRequest(text, ["read", "inspect", "view"], target)) return true;
		return [`allow_read=${target}`, `allow_read="${target}"`, `allow_read='${target}'`].some(
			(assignment) =>
				exactRequest(text, ["use", "request", "approve", "authorize"], assignment) ||
				exactRequest(text.replace(/^retry with /i, "request "), ["request"], assignment),
		);
	}
	const command = action.input.command;
	return typeof command === "string" && (text === command || exactRequest(text, ["run", "execute"], command));
}

export function enforceReview(
	model: ModelReview,
	action: CanonicalAction,
	profile: EffectiveProfile,
	evidence: ReviewEvidence,
	authorization: readonly ReviewAuthorization[] = [],
): EffectiveReview {
	const floor = maxRisk(minimumRisk(action, profile), evidence.action.truncated ? "high" : "low");
	const risk = maxRisk(model.risk, floor);
	const authorizationCovers = directAuthorizationCovers(action, authorization);
	let decision = model.decision;
	let reason = model.reason;
	if (risk === "critical" && decision !== "deny") {
		decision = "deny";
		reason = `deterministic critical-risk floor overrides reviewer ${model.decision}: ${model.reason}`;
	} else if (risk === "high" && decision === "allow" && !authorizationCovers) {
		decision = "ask";
		reason = `effective high risk lacks covering direct authorization: ${model.reason}`;
	}
	return { decision, risk, reason, modelRisk: model.risk, minimumRisk: floor, authorizationCovers };
}
