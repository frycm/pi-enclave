/**
 * The gate: one `tool_call` handler, one path through it.
 *
 * Validate and freeze → canonicalize → L1 → allowlist → review/escalate → lock. Every tool call takes the
 * same route, and there is no second entry point, because a policy layer with
 * two paths is a policy layer with one bypass.
 *
 * **Everything that goes wrong here is a denial.** The whole body runs inside a
 * try/catch that converts any exception into a block. pi would already fail the
 * call if a handler threw -- `emitToolCall` does not catch, so `prepareToolCall`
 * turns it into an error result -- but a deliberate block carries the reason to
 * the model, and an unexplained failure is one the agent retries.
 *
 * **The gate never runs a tool.** It decides, records, and freezes. Execution
 * happens in the operations objects, which consult the lock again at the moment
 * they act -- see `lock.ts` for why that second check is not redundant.
 */

import { capabilityIntersects, resolveCapabilityTarget } from "../backend/capability.ts";
import { canonical as canonicalPath, isUnder } from "../backend/paths.ts";
import type { EffectiveProfile } from "../config/types.ts";
import { type CanonicalAction, canonicalize, describeAction } from "../policy/canonical.ts";
import { type Evaluation, evaluateRules, type RuleMatch } from "../policy/match.ts";
import { matchesPathPattern } from "../policy/paths.ts";
import { reviewerTrigger } from "../reviewer/classifier.ts";
import type { ActionReviewer, EffectiveReview, ReviewerResult, ReviewerTrigger } from "../reviewer/types.ts";
import { ActionLock, freezeToolInput } from "./lock.ts";
import { checkTool } from "./tools.ts";

/** What the gate is asked about. Mirrors pi's `ToolCallEvent`. */
export interface GateEvent {
	toolName: string;
	toolCallId: string;
	input: Record<string, unknown>;
}

export type GateOutcome =
	/** Ran the whole path and permitted it. */
	| "allow"
	/** L1 `deny`, a protected-path denial, or a disallowed tool. */
	| "deny"
	/** Went to L4 and was refused there, or there was nobody to ask. */
	| "ask-denied"
	/** Went to L4 and a human said yes. */
	| "ask-approved"
	/** Matched `skipReview` and nothing above it. */
	| "skip-review"
	/** L3 permitted the action after deterministic risk enforcement. */
	| "review-allow"
	/** L3 denied the action, or returned invalid output. */
	| "review-deny"
	/** The breaker was already open. */
	| "breaker-open"
	/** A non-owned call was withheld because an earlier sibling could open it at runtime. */
	| "batch-withheld"
	/** The gate itself failed. Always a denial. */
	| "error";

export interface GateDecision {
	outcome: GateOutcome;
	block: boolean;
	reason?: string;
	terminate?: boolean;
	action?: CanonicalAction;
	matches: RuleMatch[];
	/** True when the decision counts against the circuit breaker. */
	adverse: boolean;
}

/**
 * How the gate reaches a human. Supplied by the attendance layer.
 *
 * Returning `false` is the unattended answer and the timeout answer alike --
 * both are denials, and the escalator records which for the audit log.
 */
export interface Escalator {
	confirm(action: CanonicalAction, reason: string, toolSource?: string): Promise<boolean>;
}

/** The escalator in force before the attendance layer exists, and when nobody is there. */
export const DENY_ESCALATOR: Escalator = { confirm: async () => false };

export interface GateDeps {
	profile: EffectiveProfile;
	cwd: string;
	home: string;
	lock: ActionLock;
	owned: readonly string[];
	escalator?: Escalator;
	/** Present only for a configured, qualified named reviewer. */
	reviewer?: ActionReviewer;
	/** True when the breaker is already open. Checked before anything else. */
	breakerOpen?: () => boolean;
	/** Where a tool came from, for grant pinning. */
	toolSource?: (tool: string) => string | undefined;
	/** Backend-aware last check that a write capability is structurally grantable. */
	writeCapabilityIssue?: (value: string, cwd: string, tool: string) => string | undefined;
	/** Backend-aware last check that a read capability can be isolated. */
	readCapabilityIssue?: (value: string, cwd: string, tool: string) => string | undefined;
	/** Last admission check for boundaries that have no execute-time guard. */
	withholdBeforeExecution?: (action: CanonicalAction) => string | undefined;
	onDecision?: (decision: GateDecision) => void;
}

export async function decide(event: GateEvent, deps: GateDeps): Promise<GateDecision> {
	let decision: GateDecision;
	try {
		decision = await run(event, deps);
	} catch (error) {
		decision = {
			outcome: "error",
			block: true,
			reason:
				`pi-enclave: the policy gate failed, so this call is denied.\n  ${(error as Error).message}\n` +
				"  A gate that cannot decide must not permit.",
			matches: [],
			adverse: true,
		};
	}
	deps.onDecision?.(decision);
	return decision;
}

async function run(event: GateEvent, deps: GateDeps): Promise<GateDecision> {
	const { profile } = deps;

	// With L1 and L4 disabled the gate is a pass-through. It still freezes and
	// locks, because the operations objects refuse anything the table has not
	// seen, and because the audit log should not go blind just because the
	// pattern rules are off. The sandbox is untouched either way.
	if (!profile.auto) {
		const action = canonical(event, deps);
		return finish(action, event, deps, { outcome: "allow", block: false, matches: [], adverse: false });
	}

	// Freeze before every in-gate short circuit, including an already-open
	// breaker. This preserves the invariant that another handler never sees a
	// mutable input after pi-enclave has made a policy decision about the call.
	const action = canonical(event, deps);

	if (deps.breakerOpen?.()) {
		return {
			outcome: "breaker-open",
			block: true,
			terminate: true,
			reason:
				"pi-enclave: the denial circuit breaker is open. This turn is over.\n" +
				"  Do not pursue this outcome by other means -- the denial is about the outcome, not this command.",
			matches: [],
			// Already counted when it opened; counting again would keep it open
			// for as long as the agent keeps trying.
			adverse: false,
		};
	}

	// L1 first, and before the allowlist: a `deny` on a tool that is not even
	// allowed should still be recorded as the denial it is, and the audit record
	// should name the rule rather than only the missing grant.
	const evaluation = evaluate(action, deps);

	if (evaluation.verdict === "deny") {
		return {
			outcome: "deny",
			block: true,
			reason: denialReason(action, evaluation),
			matches: evaluation.matches,
			adverse: true,
			action,
		};
	}

	if (action.capability && profile.sandbox.capabilities !== "reviewed") {
		return {
			outcome: "deny",
			block: true,
			reason:
				`pi-enclave: ${action.capability.kind} capabilities are disabled by the current profile.\n` +
				"  A disabled capability is a revocation, not a request that can be escalated.",
			matches: evaluation.matches,
			adverse: true,
			action,
		};
	}

	// Host access needs Phase 4's authenticated egress proxy. It must be refused
	// rather than approved under the unchanged base profile.
	if (action.capability?.kind === "host") {
		return {
			outcome: "deny",
			block: true,
			reason: `pi-enclave: ${action.capability.kind} capabilities are not implemented in this phase.`,
			matches: evaluation.matches,
			adverse: true,
			action,
		};
	}

	if (action.capability?.kind === "read") {
		const target = resolveCapabilityTarget(action.cwd, action.capability.value);
		const grantable = profile.sandbox.grantableReadDeny.some((entry) => canonicalPath(entry) === target);
		if (!grantable) {
			return {
				outcome: "deny",
				block: true,
				reason:
					`pi-enclave: read capability ${target} is not an exact user-global grantableReadDeny entry.\n` +
					"  Built-in credential and enclave-state denials are immutable.",
				matches: evaluation.matches,
				adverse: true,
				action,
			};
		}
		const covered = action.paths.some((path) => !path.writes && isUnder(path.resolved, target));
		if (!covered) {
			return {
				outcome: "deny",
				block: true,
				reason:
					`pi-enclave: read capability ${target} does not cover a concrete read in this action.\n` +
					"  Capabilities cannot be requested speculatively or carried by an unrelated operation.",
				matches: evaluation.matches,
				adverse: true,
				action,
			};
		}
		const issue = deps.readCapabilityIssue?.(action.capability.value, action.cwd, action.tool);
		if (issue) {
			return {
				outcome: "deny",
				block: true,
				reason: `${issue}\n  This boundary is not grantable by approval.`,
				matches: evaluation.matches,
				adverse: true,
				action,
			};
		}
	}

	if (action.capability?.kind === "write") {
		// Write widening is implemented by one child process whose custom profile
		// dies with that process. File tools use the long-lived helper, so accepting
		// a forged allow_write field on one of them would approve authority the
		// executor cannot safely express.
		if (action.tool !== "bash") {
			return {
				outcome: "deny",
				block: true,
				reason:
					"pi-enclave: one-shot write capabilities are supported only by the sandboxed bash tool.\n" +
					"  File-tool write widening has no isolated invocation lifetime and is refused.",
				matches: evaluation.matches,
				adverse: true,
				action,
			};
		}
		const target = resolveCapabilityTarget(action.cwd, action.capability.value);
		const denied = capabilityIntersects(target, profile.sandbox.readDeny);
		if (denied) {
			return {
				outcome: "deny",
				block: true,
				reason:
					`pi-enclave: write capability ${target} intersects immutable read-deny path ${denied}.\n` +
					"  Read-denied credentials and state cannot be exposed by a write grant.",
				matches: evaluation.matches,
				adverse: true,
				action,
			};
		}
		const issue = deps.writeCapabilityIssue?.(action.capability.value, action.cwd, action.tool);
		if (issue) {
			return {
				outcome: "deny",
				block: true,
				reason: `${issue}\n  This boundary is not grantable by approval.`,
				matches: evaluation.matches,
				adverse: true,
				action,
			};
		}
		const covered = action.paths.some((path) => path.writes && isUnder(path.resolved, target));
		if (!covered) {
			return {
				outcome: "deny",
				block: true,
				reason:
					`pi-enclave: write capability ${target} does not cover a concrete write in this action.\n` +
					"  Capabilities cannot be requested speculatively or carried by an unrelated operation.",
				matches: evaluation.matches,
				adverse: true,
				action,
			};
		}
	}

	// Resolved once: in the wiring this is a fresh `getAllTools()` allocation and
	// a linear scan, and it ran twice per gated call for the `!== undefined` test
	// and then the value.
	const toolSource = deps.toolSource?.(action.tool);
	const disposition = checkTool({
		tool: action.tool,
		tools: profile.tools,
		owned: deps.owned,
		...(toolSource !== undefined ? { source: toolSource } : {}),
	});
	if (!disposition.allowed) {
		return {
			outcome: "deny",
			block: true,
			reason: disposition.reason,
			matches: evaluation.matches,
			adverse: true,
			action,
		};
	}

	const withheld = deps.withholdBeforeExecution?.(action);
	if (withheld !== undefined) {
		return {
			outcome: "batch-withheld",
			block: true,
			reason: withheld,
			matches: evaluation.matches,
			adverse: false,
			action,
		};
	}

	// L1 ask is always L4. It cannot be cleared by the reviewer or by
	// skipReview, because its meaning is precisely "a person decides".
	const deterministicAsk = deterministicAskReason(evaluation);
	if (deterministicAsk) return escalate(action, event, deps, evaluation, toolSource, deterministicAsk);

	// skipReview is an explicit user-global allow verdict for ordinary calls. A
	// capability still crosses L2 and therefore never takes this route.
	if (evaluation.verdict === "skipReview" && !action.capability) {
		return finish(action, event, deps, {
			outcome: "skip-review",
			block: false,
			matches: evaluation.matches,
			adverse: false,
		});
	}

	if (deps.reviewer) {
		const trigger = triggerForReviewer(profile.review.trigger, action, disposition.reviewed, disposition);
		if (trigger) {
			const result = await deps.reviewer.review({
				action,
				trigger,
				...(toolSource !== undefined ? { toolSource } : {}),
			});
			return handleReview(result, action, event, deps, evaluation, toolSource, !deps.owned.includes(action.tool));
		}
	}

	// In deterministic mode this is the only escalation there is. If a named
	// reviewer is configured but its trigger excludes an uncertain parse, the
	// uncertainty still goes to a person; it never becomes a fast path.
	const askReason = needsHumanWithoutReview(action, disposition.reviewed, deps.reviewer !== undefined);
	if (askReason) {
		return escalate(action, event, deps, evaluation, toolSource, askReason);
	}

	return finish(action, event, deps, {
		outcome: evaluation.verdict === "skipReview" ? "skip-review" : "allow",
		block: false,
		matches: evaluation.matches,
		adverse: false,
	});
}

function triggerForReviewer(
	configured: EffectiveProfile["review"]["trigger"],
	action: CanonicalAction,
	reviewed: boolean,
	disposition: ReturnType<typeof checkTool>,
): ReviewerTrigger | undefined {
	if (action.capability) return "capability";
	if (reviewed) return "mutating";
	return reviewerTrigger(configured, action, disposition);
}

async function handleReview(
	result: ReviewerResult,
	action: CanonicalAction,
	event: GateEvent,
	deps: GateDeps,
	evaluation: Evaluation,
	toolSource: string | undefined,
	outsideSandbox: boolean,
): Promise<GateDecision> {
	if (!result.ok) {
		if (result.kind === "invalid-output") {
			return {
				outcome: "review-deny",
				block: true,
				terminate: true,
				reason: `pi-enclave: reviewer output was invalid, so this action is denied.\n  ${result.reason}`,
				matches: evaluation.matches,
				adverse: true,
				action,
			};
		}
		return escalate(
			action,
			event,
			deps,
			evaluation,
			toolSource,
			`the reviewer is unavailable after bounded retries: ${result.reason}`,
		);
	}

	return reviewDecision(result.review, action, event, deps, evaluation, toolSource, outsideSandbox);
}

async function reviewDecision(
	review: EffectiveReview,
	action: CanonicalAction,
	event: GateEvent,
	deps: GateDeps,
	evaluation: Evaluation,
	toolSource: string | undefined,
	outsideSandbox: boolean,
): Promise<GateDecision> {
	const explanation = `reviewer: ${review.reason} (risk ${review.risk}, minimum ${review.minimumRisk})`;
	if (review.decision === "deny") {
		return {
			outcome: "review-deny",
			block: true,
			reason: `pi-enclave: denied by the isolated reviewer.\n  ${explanation}\n${describeAction(action)}`,
			matches: evaluation.matches,
			adverse: true,
			action,
		};
	}
	if (review.decision === "ask") {
		return escalate(action, event, deps, evaluation, toolSource, explanation);
	}
	// A reviewed third-party tool executes in pi's privileged process, outside
	// L2. The model may veto it or recommend it, but cannot be the authority that
	// admits unsandboxed execution; an allow therefore remains an L4 decision.
	if (outsideSandbox) {
		return escalate(
			action,
			event,
			deps,
			evaluation,
			toolSource,
			`${explanation}; "${action.tool}" runs outside the sandbox and requires human approval`,
		);
	}
	return finish(action, event, deps, {
		outcome: "review-allow",
		block: false,
		reason: explanation,
		matches: evaluation.matches,
		adverse: false,
	});
}

async function escalate(
	action: CanonicalAction,
	event: GateEvent,
	deps: GateDeps,
	evaluation: Evaluation,
	toolSource: string | undefined,
	reason: string,
): Promise<GateDecision> {
	const approved = await (deps.escalator ?? DENY_ESCALATOR).confirm(action, reason, toolSource);
	if (!approved) {
		return {
			outcome: "ask-denied",
			block: true,
			terminate: true,
			reason: `pi-enclave: this needs a person, and the answer was no.\n  ${reason}\n${describeAction(action)}`,
			matches: evaluation.matches,
			adverse: true,
			action,
		};
	}
	return finish(action, event, deps, {
		outcome: "ask-approved",
		block: false,
		matches: evaluation.matches,
		adverse: false,
	});
}

/** Register the already-frozen action. Only reached on a permit. */
function finish(
	action: CanonicalAction,
	event: GateEvent,
	deps: GateDeps,
	partial: Omit<GateDecision, "action">,
): GateDecision {
	deps.lock.register(action, event.toolCallId);
	return { ...partial, action };
}

function canonical(event: GateEvent, deps: GateDeps): CanonicalAction {
	// Validate and freeze before reading a single action field. Besides making
	// the reviewer's evidence a true snapshot, this rejects getters before
	// canonicalization can invoke attacker-controlled accessors. A denial does
	// not enter the lock table, but freezing it is harmless because pi
	// short-circuits later handlers after a block.
	freezeToolInput(event);
	return canonicalize({
		tool: event.toolName,
		input: event.input,
		cwd: deps.cwd,
		home: deps.home,
		profileName: deps.profile.name,
		writableRoots: deps.profile.sandbox.writableRoots,
	});
}

function evaluate(action: CanonicalAction, deps: GateDeps): Evaluation {
	return evaluateRules(action, deps.profile.rules, {
		// Only writes are escalated by protectedPaths. A read of `infra/main.tf`
		// is not the thing the rule is about, and escalating it would make the
		// list unusable in any repository where the agent has to look at what it
		// is not allowed to change.
		protectedMatcher: (patterns) => {
			const matches: RuleMatch[] = [];
			for (const path of action.paths) {
				if (!path.writes) continue;
				const pattern = matchesPathPattern(patterns, path.resolved, deps.cwd);
				if (pattern) matches.push({ list: "ask", pattern, target: path.resolved });
			}
			return matches;
		},
	});
}

/**
 * Does this need a person?
 *
 * Four reasons, and each is a boundary the sandbox cannot draw:
 *
 * - An L1 `ask` match: the user said so.
 * - A capability request: widening the sandbox is a boundary crossing by
 *   definition, and with no reviewer the only thing above L1 is L4.
 * - A `reviewed: true` grant on a tool pi-enclave cannot sandbox.
 * - A shell command the tokenizer could not follow. The rules were matched
 *   against a guess, so a `deny` may not have fired; asking is the only honest
 *   response to "I do not know what this command does".
 */
function deterministicAskReason(evaluation: Evaluation): string | undefined {
	if (evaluation.verdict === "ask") {
		return evaluation.decisive.map((match) => `matches ${match.list} rule ${match.pattern}`).join("; ");
	}
	return undefined;
}

function needsHumanWithoutReview(action: CanonicalAction, reviewed: boolean, hasReviewer: boolean): string | undefined {
	if (action.capability) {
		return hasReviewer
			? undefined
			: `requests ${action.capability.kind} access to ${action.capability.value}, which widens the sandbox for this one action`;
	}
	if (reviewed) {
		return hasReviewer
			? undefined
			: `"${action.tool}" is marked reviewed, and there is no reviewer in deterministic mode`;
	}
	if (action.shell && !action.confident) {
		return `the command could not be parsed with confidence (${action.shell.markers.join(", ")}), so the pattern rules were matched against a guess`;
	}
	return undefined;
}

function denialReason(action: CanonicalAction, evaluation: Evaluation): string {
	const lines = ["pi-enclave: denied by policy."];
	for (const match of evaluation.decisive) lines.push(`  ${match.list}: ${match.pattern} matched "${match.target}"`);
	// An overridden skipReview is shown rather than dropped: an entry that
	// looks like it grants something but never does is worth seeing.
	for (const match of evaluation.matches) {
		if (match.list === "skipReview") lines.push(`  (skipReview ${match.pattern} also matched, and was overridden)`);
	}
	lines.push(describeAction(action));
	lines.push("  Do not pursue this outcome by other means.");
	return lines.join("\n");
}

export { ActionLock };
