import { resolveCapabilityTarget } from "../backend/capability.ts";
import { canonical, isUnderAny, normalizePath } from "../backend/paths.ts";
import type { EffectiveProfile } from "../config/types.ts";
import type { CanonicalAction } from "../policy/canonical.ts";
import type { EffectiveReview, ModelReview, ReviewEvidence, ReviewRisk } from "./types.ts";

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

const NEGATED_AUTHORIZATION =
	/\b(?:do\s+not|don't|dont|did\s+not|didn't|didnt|never|must\s+not|mustn't|should\s+not|shouldn't|without|avoid|forbid|forbidden|deny|denied|refuse|refused|stop)\b/u;

function startsWithRequest(text: string, verb: string, object: string): boolean {
	const requests = [
		`${verb} ${object}`,
		`please ${verb} ${object}`,
		`could you ${verb} ${object}`,
		`can you ${verb} ${object}`,
		`would you ${verb} ${object}`,
		`go ahead and ${verb} ${object}`,
		`you may ${verb} ${object}`,
		`i authorize you to ${verb} ${object}`,
		`i approve ${verb} ${object}`,
	];
	return requests.some((request) => text === request || text.startsWith(`${request} `));
}

function explicitHashAuthorization(text: string, hash: string): boolean {
	return [`approve ${hash}`, `authorize ${hash}`, `allow ${hash}`, `i approve ${hash}`, `i authorize ${hash}`].some(
		(request) => text === request || text.startsWith(`${request} `),
	);
}

function explicitCapabilityAuthorization(text: string, kind: "read" | "write" | "host", target: string): boolean {
	const verbs = kind === "read" ? ["read", "inspect", "view"] : kind === "write" ? ["write", "modify", "create"] : [];
	if (verbs.some((verb) => startsWithRequest(text, verb, target))) return true;
	const spelling = `allow_${kind}`;
	const assignments = [`${spelling}=${target}`, `${spelling}="${target}"`, `${spelling}='${target}'`];
	return assignments.some((assignment) =>
		["use", "request", "retry with", "approve", "authorize"].some((verb) => startsWithRequest(text, verb, assignment)),
	);
}

/**
 * Deliberately narrow deterministic coverage for an effective-high allow.
 * Natural-language ambiguity becomes an ask; it never becomes model authority.
 */
export function directAuthorizationCovers(evidence: ReviewEvidence): boolean {
	const action = evidence.action;
	for (const entry of evidence.authorization) {
		const text = entry.text.trim().toLowerCase();
		if (NEGATED_AUTHORIZATION.test(text)) continue;
		if (explicitHashAuthorization(text, action.hash.toLowerCase())) return true;
		if (evidence.requestedCapability) {
			const target = evidence.requestedCapability.value.toLowerCase();
			if (explicitCapabilityAuthorization(text, evidence.requestedCapability.kind, target)) return true;
		}
		const command = action.input.command;
		if (typeof command === "string") {
			const exact = command.trim().toLowerCase();
			if (text === exact || startsWithRequest(text, "run", exact) || startsWithRequest(text, "execute", exact)) {
				return true;
			}
		}
	}
	return false;
}

export function enforceReview(
	model: ModelReview,
	action: CanonicalAction,
	profile: EffectiveProfile,
	evidence: ReviewEvidence,
): EffectiveReview {
	const floor = maxRisk(minimumRisk(action, profile), evidence.action.truncated ? "high" : "low");
	const risk = maxRisk(model.risk, floor);
	const authorizationCovers = directAuthorizationCovers(evidence);
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
