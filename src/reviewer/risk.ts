import { resolveCapabilityTarget } from "../backend/capability.ts";
import { canonical, isUnder, isUnderAny, normalizePath } from "../backend/paths.ts";
import type { EffectiveProfile } from "../config/types.ts";
import type { CanonicalAction } from "../policy/canonical.ts";
import { matchesPathPattern } from "../policy/paths.ts";
import type { EffectiveReview, ModelReview, ReviewAuthorization, ReviewEvidence, ReviewRisk } from "./types.ts";

const RISK_RANK: Record<ReviewRisk, number> = { low: 0, medium: 1, high: 2, critical: 3 };

/** Commands that destroy or change what their path arguments name. */
const PATH_DESTRUCTIVE_COMMANDS = new Set(["chmod", "chown", "dd", "rm", "truncate"]);
/** Commands whose targets are not paths the sandbox bounds. */
const UNBOUNDED_DESTRUCTIVE_COMMANDS = new Set(["kill", "pkill", "killall"]);
/** Git subcommands that discard work in the repository at the working directory. */
const GIT_DISCARDING = new Set(["reset", "clean", "checkout", "restore"]);
const CRITICAL_TREES = ["/etc", "/bin", "/sbin", "/usr", "/System", "/Library"];

export function maxRisk(a: ReviewRisk, b: ReviewRisk): ReviewRisk {
	return RISK_RANK[a] >= RISK_RANK[b] ? a : b;
}

function broadCapability(value: string): boolean {
	const normalized = value.replace(/\/+$/, "") || "/";
	return normalized === "/" || normalized.split("/").filter(Boolean).length <= 1;
}

/**
 * The floor a destructive shell command sets (#18), or undefined for none.
 *
 * `high` used to apply wherever the command pointed, so `rm -f build/x` and
 * `git checkout -b feature` needed a person although the sandbox bounds them
 * exactly. Now a destructive command whose every write lands inside the
 * writable roots, run from inside them, is `medium`: L2 is the boundary, and
 * the reviewer may clear it. It stays `high` when a target is outside the
 * writable roots, is a protected path (`rules.protectedPaths`: `.git`, `.pi`,
 * workflows and the rest), or is not a path at all (`dd of=`, a process, a
 * remote), and for `git push`. The never-grantable trees are `critical`
 * separately.
 */
function destructiveShellRisk(action: CanonicalAction, profile: EffectiveProfile): ReviewRisk | undefined {
	const commands = action.shell?.commands ?? [];
	let destructive = false;
	let bounded = true;
	const roots = profile.sandbox.writableRoots;
	const inRoots = (path: string) => isUnderAny(normalizePath(path), roots);
	const protectedPatterns = [...profile.rules.protectedPaths.deny, ...profile.rules.protectedPaths.ask];
	const writes = action.paths.filter((path) => path.writes);
	const writesBounded = writes.every(
		(path) => inRoots(path.resolved) && !matchesPathPattern(protectedPatterns, path.resolved, action.cwd),
	);
	for (const command of commands) {
		const name = command.name.slice(command.name.lastIndexOf("/") + 1).toLowerCase();
		if (UNBOUNDED_DESTRUCTIVE_COMMANDS.has(name)) {
			destructive = true;
			bounded = false;
		} else if (PATH_DESTRUCTIVE_COMMANDS.has(name)) {
			destructive = true;
			// Only a command that names its targets as paths is bounded by them:
			// `dd of=x` and `rm` with no operand are not.
			if (name === "dd" || writes.length === 0 || !writesBounded) bounded = false;
		} else if (name === "git" && command.args[0] === "push") {
			destructive = true;
			bounded = false;
		} else if (name === "git" && GIT_DISCARDING.has(command.args[0] ?? "")) {
			destructive = true;
			if (!inRoots(action.cwd) || !writesBounded) bounded = false;
		} else if (name === "gh" && command.args.some((arg) => ["-X", "--method=DELETE", "DELETE"].includes(arg))) {
			destructive = true;
			bounded = false;
		}
	}
	if (!destructive) return undefined;
	return bounded ? "medium" : "high";
}

/**
 * Whether the sandbox alone bounds what an unreadable command can do (#18):
 * no network, and no capability widening it. Then a non-confident parse is a
 * judgement for the reviewer, not a crossing that needs a person.
 */
export function sandboxContains(action: CanonicalAction, profile: EffectiveProfile): boolean {
	return profile.sandbox.network.mode === "off" && !action.capability;
}

function criticalWriteTarget(path: string, profile: EffectiveProfile): boolean {
	const normalized = normalizePath(path);
	if (normalized === "/" || canonical(normalized) === "/") return true;
	if (isUnderAny(normalized, CRITICAL_TREES)) return true;
	// The never-grantable write list (#21): the trust boundary itself. Matched
	// as written and canonical, both ways; the canonical spellings are resolved
	// once per profile, because this runs for every write path of every action.
	return protectedSpellings(profile).some((entry) => isUnder(normalized, entry) || isUnder(entry, normalized));
}

const SPELLINGS = new WeakMap<object, readonly string[]>();

function protectedSpellings(profile: EffectiveProfile): readonly string[] {
	const list = profile.sandbox.protectedWrite;
	let spellings = SPELLINGS.get(list);
	if (!spellings) {
		spellings = [...new Set(list.flatMap((entry) => [normalizePath(entry.path), canonical(entry.path)]))];
		SPELLINGS.set(list, spellings);
	}
	return spellings;
}

/**
 * The deterministic floor under the reviewer's risk.
 *
 * Computed as the maximum over independent contributions rather than as a
 * chain of early returns, so adding a property to an action can never lower
 * its floor. The chain this replaced checked "has a write path" before "bash
 * parse is not confident", and every path-shaped argument of a non-reader is a
 * write, so appending `./x` to an opaque command moved it from `high` to
 * `medium` (#16).
 */
export function minimumRisk(action: CanonicalAction, profile: EffectiveProfile): ReviewRisk {
	let floor: ReviewRisk = "low";
	const raise = (risk: ReviewRisk) => {
		floor = maxRisk(floor, risk);
	};

	if (action.capability?.kind === "host") raise("critical");
	if (action.capability?.kind === "read") {
		const value = action.capability.value;
		const grantable = (): boolean => {
			const target = resolveCapabilityTarget(action.cwd, value);
			return profile.sandbox.grantableReadDeny.some((entry) => canonical(entry) === target);
		};
		raise(broadCapability(value) || !grantable() ? "critical" : "high");
	}
	if (action.capability?.kind === "write") {
		const value = action.capability.value;
		const critical =
			broadCapability(value) ||
			criticalWriteTarget(resolveCapabilityTarget(action.cwd, value), profile) ||
			action.paths.some((path) => isUnderAny(path.resolved, profile.sandbox.readDeny));
		raise(critical ? "critical" : "high");
	}
	if (action.paths.some((path) => path.writes && criticalWriteTarget(path.resolved, profile))) raise("critical");
	const destructive = destructiveShellRisk(action, profile);
	if (destructive) raise(destructive);
	if (action.tool === "write" || action.tool === "edit" || action.paths.some((path) => path.writes)) raise("medium");
	// A non-confident command: L1 matched its patterns against a guess. Inside
	// a sandbox with no network that is the reviewer's judgement, at medium
	// (#18); where the sandbox does not contain it, it needs a person or an
	// exact direct instruction, whatever else it carries.
	if (action.tool === "bash" && !action.confident) raise(sandboxContains(action, profile) ? "medium" : "high");
	return floor;
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
	if (entry?.provenance !== "direct") return false;
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
