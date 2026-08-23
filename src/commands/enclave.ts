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
import type { BackendName, CompiledProfile, Profile, Violation } from "../backend/types.ts";
import { renderConfig, renderDefaults } from "../config/render.ts";
import type { LoadedSource } from "../config/sources.ts";
import { renderSources } from "../config/sources.ts";
import type { EffectiveProfile, Provenance } from "../config/types.ts";
import { formatProbeReport, type ProbeReport } from "../probe.ts";
import { formatVerifyResult, verifyLog } from "../state/audit.ts";

export interface EnclaveState {
	report: ProbeReport;
	backendName: BackendName;
	/** True when running in sandbox-runtime's weaker nested mode. */
	weakened: boolean;
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
	auditPath?: string;
	/** True once an audit write has failed. Shown without being asked for. */
	auditDegraded?: boolean;
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
	if (state.breaker?.open) parts.push("BREAKER OPEN");
	else if (state.breaker && state.breaker.consecutive > 0) {
		parts.push(`breaker ${state.breaker.consecutive}/${state.breaker.limit}`);
	}
	if (state.violations.length > 0) parts.push(`${state.violations.length} denied`);
	return `enclave: ${parts.join(" · ")}`;
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
		`read-deny:  ${profile.readDeny.length} path(s)`,
		`violations: ${state.violations.length} this session`,
		`coverage:   ${COVERAGE_NOTE}`,
	);

	if (state.configError) {
		lines.push("", "configuration REJECTED -- every tool refuses:", state.configError);
	} else if (state.effective) {
		lines.push(
			"",
			`config:     profile "${state.effective.name}"${state.effective.auto ? "" : "   L1/L4 disabled by PI_ENCLAVE_AUTO=off"}`,
			`rules:      ${state.effective.rules.deny.length} deny, ${state.effective.rules.ask.length} ask, ${state.effective.rules.skipReview.length} skipReview`,
			`reviewer:   ${state.effective.reviewer.model} (deterministic mode: every crossing is an ask)`,
			`attended:   ${state.attendance ?? state.effective.attended.mode}`,
			`breaker:    ${state.breaker?.open ? "OPEN -- the turn is stopped" : `${state.breaker?.consecutive ?? 0} of ${state.effective.breaker.consecutive} consecutive`}`,
			`audit:      ${state.auditPath ?? "(not open)"}${state.auditDegraded ? "   WRITES ARE FAILING" : ""}`,
		);
		if (state.sources) lines.push("sources:", renderSources(state.sources));
	}
	return lines.join("\n");
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

const USAGE = "usage: /enclave [status|backend|violations|rules defaults|rules config|audit [verify]]";

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
		default:
			return { text: `unknown rules subcommand "${verb}"\n${USAGE}`, level: "warning" };
	}
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
		default:
			return { text: `unknown subcommand "${sub}"\n${USAGE}`, level: "warning" };
	}
}
