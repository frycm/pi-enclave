/**
 * `/enclave` and the status line.
 *
 * Rendering lives here, apart from the extension wiring, so it can be tested
 * against constructed states rather than only observed by eye in a TUI. That
 * matters more than it sounds: this is the surface where a user finds out what
 * the sandbox is actually doing, and a status line that overstates the boundary
 * is worse than none at all -- it converts "I should check" into "I already
 * know".
 *
 * The rule these functions follow is that anything which *weakens* the boundary
 * must appear without being asked for. A weakened backend, a profile that has
 * not started, an unsupported host: each shows in the one-line summary, not just
 * in the detailed report nobody opens.
 */

import { describeLimits, type ProcessLimitDecision } from "../backend/limits.ts";
import type { BackendName, CompiledProfile, Profile, Violation } from "../backend/types.ts";
import { OWNED_TOOLS } from "../config/defaults.ts";
import { renderConfig, renderDefaults } from "../config/render.ts";
import type { LoadedSource } from "../config/sources.ts";
import { renderSources } from "../config/sources.ts";
import type { EffectiveProfile, Provenance } from "../config/types.ts";
import { describeRecord, listPending } from "../escalate/pending.ts";
import { unsandboxedPermits } from "../gate/tools.ts";
import { formatPendingHits, type TripwireLedger } from "../persistence/ledger.ts";
import { formatProbeReport, type ProbeReport } from "../probe.ts";
import { formatVerifyResult, verifyLog } from "../state/audit.ts";

export interface EnclaveState {
	report: ProbeReport;
	backendName: BackendName;
	/** True when running in sandbox-runtime's weaker nested mode. */
	weakened: boolean;
	/** Whether the backend sets RLIMIT_NPROC (#24), once its first command has run. */
	processLimit?: ProcessLimitDecision;
	profile: Profile;
	/** Undefined until the profile is compiled at session start. */
	compiled: CompiledProfile | undefined;
	violations: readonly Violation[];
	/** The configured profile, once the fold has run. */
	effective?: EffectiveProfile;
	provenance?: Provenance;
	sources?: readonly LoadedSource[];
	/**
	 * Why the configuration was refused, if it was. Held rather than thrown so
	 * the status line and every tool refusal can quote the same diagnosis.
	 */
	configError?: string;
	/** Breaker counters, for the footer. Absent before the gate is running. */
	breaker?: { open: boolean; consecutive: number; limit: number };
	/** What attendance is actually in force, and what was configured. */
	attendance?: string;
	/** Where pending approval records live, and the session they belong to. */
	pendingRoot?: string;
	sessionId?: string;
	/** Unacknowledged tripwire hits for this workspace (#19). */
	tripwireLedger?: TripwireLedger;
	/**
	 * Every code root the pi process loaded, from the session_start check
	 * (#36), so a later check on trusted code has the list.
	 */
	loadedCode?: readonly string[];
	auditPath?: string;
	/** True once an audit write has failed. Shown without being asked for. */
	auditDegraded?: boolean;
	/** Present when `audit.syslog` is set: true once the mirror has stopped. */
	auditSyslogStopped?: boolean;
	/** How many session logs retention kept past the size budget for holding an incident. */
	auditKeptForIncidents?: number;
}

/** What the sandbox covers, and what it does not. Shown in `status`. */
export const COVERAGE_NOTE =
	"bash, the file tools and !/!! are OS-enforced. MCP and third-party tools run in the pi process and are not.";

/**
 * The footer line.
 *
 * Deliberately terse, and deliberately loud about the states that change what
 * the sandbox is worth.
 *
 * "Active" is decided by whether a profile compiled, not by whether the probe
 * passed. The probe is a startup gate; once a profile is in force, the compiled
 * profile is the fact. Deriving it from the probe made this line claim
 * NOT ACTIVE during a weakened run that was visibly denying reads -- the one
 * configuration where an inaccurate status line does the most damage, because
 * it invites someone to assume nothing is enforced and act accordingly.
 */
export function renderStatusLine(state: EnclaveState): string {
	if (state.configError) return "enclave: REFUSING ALL TOOLS (config rejected)";
	if (!state.compiled) {
		return state.report.ok ? "enclave: starting" : "enclave: REFUSING ALL TOOLS (probe failed)";
	}

	const parts = [state.backendName, state.profile.mode, `net ${state.profile.network}`];
	if (state.weakened) parts.push("WEAKENED");
	// L1 off is not a detail. It is the difference between "the pattern rules
	// and escalation are running" and "only the kernel is", and someone reading
	// this line to decide whether to walk away needs to see it without asking.
	if (state.effective && !state.effective.auto) parts.push("L1 off");
	// The mode *in force*, not the one configured: a session that degraded to
	// unattended must not keep displaying the mode it asked for.
	else if (state.effective) parts.push(`L4:${(state.attendance ?? state.effective.attended.mode).split(" ")[0]}`);
	// The breaker is shown only once it has something to say. A permanent
	// "0/3" would be noise, and a silent trip would be the opposite.
	// A log that has stopped recording is a weakened boundary, and the rule
	// this module follows is that those appear without being asked for.
	if (state.auditDegraded) parts.push("AUDIT FAILING");
	else if (state.auditSyslogStopped) parts.push("AUDIT SYSLOG STOPPED");
	if (state.breaker?.open) parts.push("BREAKER OPEN");
	else if (state.breaker && state.breaker.consecutive > 0) {
		parts.push(`breaker ${state.breaker.consecutive}/${state.breaker.limit}`);
	}
	if (state.violations.length > 0) parts.push(`${state.violations.length} denied`);
	return `enclave: ${parts.join(" · ")}`;
}

/**
 * The read boundary in one line (#23). Open mode is a deny-list and says so,
 * because "reads are open" is the property a reader most needs to know.
 */
export function describeReadMode(profile: Profile, backendName: string): string {
	if (backendName === "docker" || backendName === "podman") {
		return `allowlist (container: only the mounted roots${profile.readableRoots?.length ? ` and ${profile.readableRoots.length} readable root(s)` : ""})`;
	}
	if (profile.readMode === "allowlist") {
		return `allowlist: ${profile.readAllow?.length ?? 0} root(s) readable, everything else denied`;
	}
	return 'OPEN -- everything is readable except read-deny (sandbox.readMode "allowlist" to narrow)';
}

export function renderStatus(state: EnclaveState): string {
	const lines = [formatProbeReport(state.report), ""];

	lines.push(`backend:    ${state.backendName}${state.compiled ? "" : " (not started)"}`);
	if (state.weakened) {
		lines.push(
			"            WEAKENED nested mode: the sandboxed process keeps its capabilities.",
			"            Only use this where something else provides isolation.",
		);
	}
	// The compiled profile is the one in force: the backend may widen the
	// requested one by what it cannot avoid (sandbox-runtime's temp directory),
	// and the status must describe that, not the request.
	const profile = state.compiled?.profile ?? state.profile;
	lines.push(
		`profile:    ${profile.mode}, network ${profile.network}, pty ${profile.allowPty ? "on" : "off"}`,
		`writable:   ${profile.writableRoots.join(", ") || "(nothing)"}`,
		`reads:      ${describeReadMode(profile, state.backendName)}`,
		// Every root, as the writable ones are: a count alone would hide a root
		// that exposes more than its name suggests.
		...(profile.readMode === "allowlist" && state.backendName !== "docker" && state.backendName !== "podman"
			? [`readable:   ${(profile.readAllow ?? []).join(", ") || "(nothing)"}`]
			: []),
		`read-deny:  ${profile.readDeny.length} path(s)`,
		`limits:     ${describeLimits(profile.limits, state.backendName, process.platform, state.processLimit)}`,
		`violations: ${state.violations.length} this session`,
		`coverage:   ${COVERAGE_NOTE}`,
	);
	try {
		const ledger = state.tripwireLedger?.state();
		const pendingHits = ledger ? ledger.entries.length + ledger.droppedProject : 0;
		if (pendingHits > 0) {
			lines.push(`tripwire:   ${pendingHits} unacknowledged change(s); /enclave tripwire to review`);
		}
	} catch (error) {
		lines.push(`tripwire:   ledger unreadable: ${(error as Error).message}`);
	}
	// Skipped by the persistence scan, so the user can see what was not looked at.
	const unscanned = state.profile.unscanned ?? [];
	if (unscanned.length > 0) {
		lines.push(
			`unscanned:  ${unscanned.length} directory(ies) owned by another account and not searchable by this user:`,
			...unscanned.slice(0, 10).map((dir) => `            ${dir}`),
			...(unscanned.length > 10 ? [`            ... and ${unscanned.length - 10} more`] : []),
		);
	}
	// sandbox.allowSelfHosting: loaded code kept read-only rather than refused (#36).
	const selfHosted = state.profile.selfHosted ?? [];
	if (selfHosted.length > 0) {
		lines.push(
			`self-host:  ${selfHosted.length} loaded code root(s) below a writable root, write-denied for the session:`,
			...selfHosted.map((dir) => `            ${dir}`),
		);
	}

	if (state.configError) {
		lines.push("", "configuration REJECTED -- every tool refuses:", state.configError);
	} else if (state.effective) {
		lines.push(
			"",
			`config:     profile "${state.effective.name}"${state.effective.auto ? "" : "   L1/L4 disabled by PI_ENCLAVE_AUTO=off"}`,
			`rules:      ${state.effective.rules.deny.length} deny, ${state.effective.rules.ask.length} ask, ${state.effective.rules.skipReview.length} skipReview`,
			...renderUnsandboxed(state.effective),
			state.effective.reviewer.model === "none"
				? `reviewer:   none (deterministic mode: every crossing is an ask)`
				: `reviewer:   ${state.effective.reviewer.model} (${state.effective.reviewer.transport} transport, trigger ${state.effective.review.trigger})`,
			`attended:   ${state.attendance ?? state.effective.attended.mode}`,
			`breaker:    ${state.breaker?.open ? "OPEN -- the turn is stopped" : `${state.breaker?.consecutive ?? 0} of ${state.effective.breaker.consecutive} consecutive`}`,
			`audit:      ${state.auditPath ?? "(not open)"}${state.auditDegraded ? `   ${state.effective.audit.required ? "NOT RECORDING -- tool calls are refused (audit.required)" : "WRITES ARE FAILING"}` : ""}`,
			`            ${describeAudit(state.effective.audit, state.auditSyslogStopped)}`,
		);
		if (state.auditSyslogStopped) {
			lines.push(
				`            the syslog mirror STOPPED${state.effective.audit.required ? " -- tool calls are refused (audit.required)" : "; the head is kept beside the log only"}`,
			);
		}
		if (state.auditKeptForIncidents) {
			lines.push(
				`            over retentionMb: ${state.auditKeptForIncidents} session log(s) kept because they hold incidents`,
			);
		}
		if (state.sources) lines.push("sources:", renderSources(state.sources));
	}
	return lines.join("\n");
}

/**
 * Tools that can run outside the sandbox without a person deciding (#22).
 *
 * Shown whether or not there are any: "none" is the statement worth reading
 * before walking away from an unattended session.
 */
function renderUnsandboxed(effective: EffectiveProfile): string[] {
	const permits = unsandboxedPermits(effective.tools, effective.rules.skipReview, OWNED_TOOLS);
	if (permits.length === 0) return ["unsandboxed: no tool runs outside the sandbox without a person"];
	return [
		`unsandboxed: ${permits.length} route(s) run a tool outside the sandbox with no person deciding:`,
		...permits.map((permit) => `            ${permit.tool} (${permit.via})`),
	];
}

/**
 * The compiled profile, verbatim.
 *
 * The Seatbelt SBPL or the bwrap argv, unedited. Someone checking whether the
 * sandbox does what it claims needs the artefact the kernel was given, not our
 * description of it.
 */
export function renderBackend(state: EnclaveState): string {
	if (!state.compiled) return "sandbox not started yet; run a command first";
	return state.compiled.describe();
}

export function renderViolations(state: EnclaveState, limit = 20): string {
	if (state.violations.length === 0) return "no denials this session";

	const shown = state.violations.slice(-limit);
	const lines = shown.map((violation) => {
		const target = violation.path ?? violation.host ?? "";
		return `  ${violation.kind.padEnd(8)} ${violation.op} ${target}`.trimEnd();
	});

	const omitted = state.violations.length - shown.length;
	if (omitted > 0) lines.unshift(`  (${omitted} earlier denial(s) not shown)`);
	return [`${state.violations.length} denial(s) this session:`, ...lines].join("\n");
}

export type CommandLevel = "info" | "warning" | "error";

export interface CommandOutput {
	text: string;
	level: CommandLevel;
}

const USAGE =
	"usage: /enclave [status|backend|violations|rules defaults|rules config|rules critique|eval-reviewer|audit [verify]|pending|tripwire [ack]]";

/**
 * `rules defaults` and `rules config`.
 *
 * `config` needs a folded configuration, so it reports the refusal rather than
 * printing a profile that is not in force -- the one moment someone runs this
 * command is when they are trying to find out why something was denied.
 */
function renderRules(state: EnclaveState, argv: readonly string[]): CommandOutput {
	const verb = argv[0] ?? "config";
	switch (verb) {
		case "defaults":
			return {
				text: renderDefaults({ cwd: state.profile.writableRoots[0] ?? process.cwd() }, argv.includes("--readonly")),
				level: "info",
			};
		case "config":
			if (state.configError) return { text: state.configError, level: "error" };
			if (!state.effective || !state.provenance)
				return { text: "configuration has not been loaded yet", level: "warning" };
			return { text: renderConfig(state.effective, state.provenance), level: "info" };
		case "critique":
			return {
				text: "rulebook critique needs the live isolated reviewer; run /enclave rules critique after session startup",
				level: "warning",
			};
		default:
			return { text: `unknown rules subcommand "${verb}"\n${USAGE}`, level: "warning" };
	}
}

function describeAudit(audit: EffectiveProfile["audit"], syslogStopped = false): string {
	const syslog = !audit.syslog
		? "; no syslog mirror"
		: syslogStopped
			? "; syslog mirror stopped"
			: " and in syslog (authpriv)";
	return [
		`head anchor beside the log${syslog}`,
		`${audit.sessionMaxMb} MB per session`,
		audit.required ? "required: a failed write stops the session" : "not required",
		`retention ${audit.retentionDays} days / ${audit.retentionMb} MB`,
	].join("; ");
}

/** `audit` and `audit verify`. */
function renderAudit(state: EnclaveState, argv: readonly string[]): CommandOutput {
	if (!state.auditPath) return { text: "the audit log is not open yet", level: "warning" };
	if (argv[0] === "verify") {
		const result = verifyLog(state.auditPath);
		return { text: formatVerifyResult(state.auditPath, result), level: result.ok ? "info" : "error" };
	}
	return { text: `audit log: ${state.auditPath}\nRun "/enclave audit verify" to re-chain it.`, level: "info" };
}

/**
 * `pending`.
 *
 * Read-only, deliberately. Approving is `pi-enclave approve <nonce>` in a
 * terminal, not a slash command: the point of a pending record is that a person
 * looks at it outside the session the agent is driving, and offering to approve
 * one from inside that session would put the decision back where the agent can
 * see the prompt.
 */
function renderPending(state: EnclaveState): CommandOutput {
	if (!state.pendingRoot || !state.sessionId) return { text: "no state directory is open", level: "warning" };
	const records = listPending(state.pendingRoot, state.sessionId).filter((entry) => entry.state === "pending");
	if (records.length === 0) return { text: "nothing is waiting for approval", level: "info" };
	const body = records.map((entry) => describeRecord(entry.record)).join("\n\n");
	return {
		text: `${records.length} action(s) waiting for approval:\n\n${body}\n\nApprove one in a terminal with: pi-enclave approve <nonce>`,
		level: "warning",
	};
}

/**
 * `tripwire` and `tripwire ack`.
 *
 * Acknowledging is a slash command, unlike approving a pending action: it
 * changes no boundary, only stops a reminder, and the ledger lives in the
 * state directory, which the sandbox cannot write.
 */
function renderTripwire(state: EnclaveState, argv: readonly string[]): CommandOutput {
	const ledger = state.tripwireLedger;
	if (!ledger) return { text: "the tripwire is not running", level: "warning" };
	if (argv[0] === "ack") {
		const count = ledger.clear();
		return { text: count === 0 ? "nothing to acknowledge" : `acknowledged ${count} change(s)`, level: "info" };
	}
	if (argv[0] !== undefined) return { text: `unknown tripwire subcommand "${argv[0]}"\n${USAGE}`, level: "warning" };
	const text = formatPendingHits(ledger.state(), Number.POSITIVE_INFINITY);
	return text ? { text, level: "warning" } : { text: "no unacknowledged changes", level: "info" };
}

export function handleEnclaveCommand(state: EnclaveState, args: string): CommandOutput {
	const sub = args.trim().split(/\s+/)[0] || "status";

	switch (sub) {
		case "status":
			return { text: renderStatus(state), level: state.report.ok ? "info" : "error" };
		case "backend":
			return { text: renderBackend(state), level: "info" };
		case "violations":
			return { text: renderViolations(state), level: "info" };
		case "rules":
			return renderRules(state, args.trim().split(/\s+/).slice(1));
		case "audit":
			return renderAudit(state, args.trim().split(/\s+/).slice(1));
		case "pending":
			return renderPending(state);
		case "tripwire":
			return renderTripwire(state, args.trim().split(/\s+/).slice(1));
		default:
			return { text: `unknown subcommand "${sub}"\n${USAGE}`, level: "warning" };
	}
}
