/**
 * pi-enclave extension entry point.
 *
 * Every tool pi-enclave owns is OS-enforced: `bash`, the `!`/`!!` shortcuts, and
 * all six file tools. Shell commands go through the backend; file operations go
 * through the sandboxed helper, so the `open` and `readdir` calls happen inside
 * the boundary rather than in this process.
 *
 * What is NOT covered: tools registered by other extensions and by MCP servers.
 * Those execute in the pi process with the user's privileges and never reach the
 * sandbox. `/enclave status` says so, because a status line that overstated the
 * boundary would be the one lie this project cannot afford. Closing that gap
 * needs either the policy layer (phase 2, which denies unlisted tools) or an
 * execution hook in pi core.
 */
import { homedir } from "node:os";
import { resolve as resolvePath } from "node:path";
import { fileURLToPath } from "node:url";
import type { ExtensionAPI, ExtensionContext } from "@earendil-works/pi-coding-agent";
import {
	createBashTool,
	createEditTool,
	createFindTool,
	createGrepTool,
	createLsTool,
	createReadTool,
	createWriteTool,
	VERSION as PI_VERSION,
} from "@earendil-works/pi-coding-agent";
import {
	resolveCapabilityTarget,
	shellCapabilityIssue,
	shellWriteCapabilityIssue,
	validateReadCapability,
	validateWriteCapability,
	WriteBoundaryError,
} from "./backend/capability.ts";
import { canonical as canonicalPath, isUnder } from "./backend/paths.ts";
import { selectBackend } from "./backend/select.ts";
import { SrtBackend } from "./backend/srt.ts";
import type { CompiledProfile, FsClient, FsClientLease, SandboxBackend, Violation } from "./backend/types.ts";
import { type EnclaveState, handleEnclaveCommand, renderStatusLine } from "./commands/enclave.ts";
import { OWNED_TOOLS } from "./config/defaults.ts";
import { createDevProfile, toBackendProfile } from "./config/profile.ts";
import { type LoadedSource, loadConfig } from "./config/sources.ts";
import type { EffectiveProfile, Provenance } from "./config/types.ts";
import {
	type AttendanceState,
	describeAttendance,
	recheckAttendance,
	resolveAttendance,
} from "./escalate/attendance.ts";
import { type ConfirmUI, createConfirmEscalator } from "./escalate/confirm.ts";
import { describeHandshakeFailure, runHandshake } from "./escalate/handshake.ts";
import { checkNotifyProgram, createNotifier } from "./escalate/notify.ts";
import { writePending } from "./escalate/pending.ts";
import { createQueueEscalation } from "./escalate/queue.ts";
import {
	BREAKER_ENTRY_TYPE,
	CircuitBreaker,
	isBreakerState,
	recordRuntimeViolation,
	resetAndPersistBreaker,
	shouldWithholdNonOwnedSibling,
	steerMessage,
} from "./gate/breaker.ts";
import {
	applySelfHosting,
	type CodeRoot,
	checkCodeRoots,
	collectCodeRoots,
	extensionArguments,
	formatCodeRootProblems,
	protectLoadedCode,
	resolveDependencyEntries,
} from "./gate/code-roots.ts";
import { createExecutionCheck, hasExecutionWrapper } from "./gate/execution.ts";
import { decide, type GateDecision } from "./gate/gate.ts";
import { describeTally, emptyTally, recordLayer } from "./gate/layers.ts";
import { ActionLock } from "./gate/lock.ts";
import { checkOwnership, formatOwnershipProblems } from "./gate/ownership.ts";
import { answerProjectTrust } from "./gate/project-trust.ts";
import { protectedEntryMatcher, protectedWriteTargets } from "./gate/protected-writes.ts";
import { PROVENANCE_ENTRY_TYPE, ProvenanceTracker } from "./gate/provenance.ts";
import { toolReachability } from "./gate/reachability.ts";
import { checkTool, describeDeclaredHints, grantWarnings } from "./gate/tools.ts";
import { persistenceSurface, protectedByProfile } from "./persistence/agent.ts";
import { formatPendingHits, TripwireLedger } from "./persistence/ledger.ts";
import { countsAgainstTurn, formatTripwireHits, PersistenceTripwire } from "./persistence/tripwire.ts";
import { formatProbeReport } from "./probe.ts";
import { probeHost, resolveSeccompHelper } from "./probe-host.ts";
import { critiqueRulebook, formatCritique } from "./reviewer/critique.ts";
import { MAX_AUTHORIZATION_ENTRIES } from "./reviewer/evidence.ts";
import { rememberReviewContext, restoreReviewHistory } from "./reviewer/history.ts";
import { formatQualificationRuns, qualifyConfiguredReviewers } from "./reviewer/qualify.ts";
import { IsolatedReviewer, isClassifier, REVIEWER_WARM_TIMEOUT_MS } from "./reviewer/reviewer.ts";
import { prepareQualifiedReviewer } from "./reviewer/setup.ts";
import type { ActionReviewer, ReviewAuthorization, ReviewContextEntry } from "./reviewer/types.ts";
import {
	AuditLog,
	configFields,
	configHash,
	decisionFields,
	executedFields,
	executionRefusedFields,
	reviewerVerdictFields,
	userCommandFields,
} from "./state/audit.ts";
import { ensureStateDirs, StateDirError, stateDirs } from "./state/dir.ts";
import { applyRetention } from "./state/retention.ts";
import { createSyslogMirror, type SyslogMirror } from "./state/syslog.ts";
import { BASH_PROMPT_GUIDELINES, createEnclaveBashOperations } from "./tools/bash.ts";
import {
	createEditOperations,
	createFindOperations,
	createLsOperations,
	createReadOperations,
	createWriteOperations,
} from "./tools/file-ops.ts";
import { GrepExecutionQueue, runSandboxedGrep } from "./tools/grep.ts";
import { bindOwnedTool } from "./tools/locked.ts";

/**
 * A fallback spelling of this module's path.
 *
 * Only a fallback: pi stores an extension's `sourceInfo.path` as the path it
 * was *configured* with (a package spec, a relative `-e` argument, a symlink),
 * which is not in general the resolved module URL. Comparing owned tools to
 * this resolved path made the ownership check refuse to start on every normal
 * install and matched only when the extension was loaded by its exact absolute
 * path. `resolveOwnPath` learns pi's actual spelling at runtime; this is used
 * only when that cannot be determined unambiguously.
 */
const OWN_SOURCE_PATH = fileURLToPath(import.meta.url);

/**
 * pi's own spelling of this extension's `sourceInfo.path`, learned from a
 * command we registered.
 *
 * Every tool and command a single extension registers shares one `sourceInfo`,
 * so the `enclave` command's path is the path our tools should have. Reading it
 * back from `getCommands()` sidesteps the configured-vs-resolved mismatch
 * entirely. If the name is ambiguous -- another extension squatting `enclave`,
 * which pi would suffix -- there is more than one candidate path and we return
 * undefined, leaving the caller to fall back.
 */
function resolveOwnPath(pi: ExtensionAPI): string | undefined {
	const commands = pi.getCommands?.() ?? [];
	const paths = new Set<string>();
	for (const command of commands) {
		if (command.name === "enclave" || command.name.startsWith("enclave:")) {
			const path = command.sourceInfo?.path;
			if (path) paths.add(path);
		}
	}
	return paths.size === 1 ? [...paths][0] : undefined;
}

/**
 * Where every loaded extension came from, for the code-root check (#36). pi
 * has no list of extensions: these are the sources of registered tools and
 * extension commands, and the `-e`/`--extension` values pi was started with,
 * which also name extensions that only register event handlers.
 *
 * `getCommands()` also returns prompt templates and skills. Those are
 * Markdown pi reads, not code it runs, and `.pi`/`.agents` already protect
 * them (#19), so only commands an extension registered are taken.
 */
function extensionSourcePaths(
	pi: ExtensionAPI,
	argv: readonly string[] = process.argv,
): { path: string; from: string }[] {
	const out: { path: string; from: string }[] = [];
	const add = (kind: string, name: string, info: { path?: string; baseDir?: string } | undefined) => {
		const from = `extension providing ${kind} "${name}"`;
		if (info?.path) out.push({ path: info.path, from });
		if (info?.baseDir) out.push({ path: info.baseDir, from });
	};
	for (const tool of pi.getAllTools?.() ?? []) add("tool", tool.name, tool.sourceInfo);
	for (const command of pi.getCommands?.() ?? []) {
		if (command.source === "extension") add("command", command.name, command.sourceInfo);
	}
	for (const value of extensionArguments(argv)) {
		out.push({ path: resolvePath(process.cwd(), value), from: `pi --extension ${value}` });
	}
	return out;
}

/** The text of a user message, whatever content shape pi used for it. */
function messageText(message: { content?: unknown }): string {
	const content = message.content;
	if (typeof content === "string") return content;
	if (!Array.isArray(content)) return "";
	return content
		.map((part) => (part && typeof part === "object" && "text" in part ? String((part as { text: unknown }).text) : ""))
		.join("");
}

/** Add optional capability fields without replacing pi's upstream tool schema. */
function addCapabilityParameters<T>(tool: T, fields: Readonly<Record<string, string>>): T {
	const shaped = tool as T & {
		parameters: { properties?: Record<string, unknown>; [key: string]: unknown };
	};
	return {
		...shaped,
		parameters: {
			...shaped.parameters,
			properties: {
				...(shaped.parameters.properties ?? {}),
				...Object.fromEntries(
					Object.entries(fields).map(([name, description]) => [name, { type: "string", description }]),
				),
			},
		},
	};
}

function isFsClientLease(value: FsClient | FsClientLease): value is FsClientLease {
	return "client" in value && "dispose" in value;
}

export default function (pi: ExtensionAPI): void {
	const nativeReport = probeHost(PI_VERSION ?? null);
	let report = nativeReport;
	let cwd = process.cwd();
	let backend: SandboxBackend = new SrtBackend();

	// The zero-configuration profile until the fold runs at session start. It is
	// never what a session executes under -- session_start replaces it -- but a
	// tool that somehow ran before then would run under the built-in defaults
	// rather than under nothing.
	let profile = createDevProfile({ cwd });
	let effective: EffectiveProfile | undefined;
	let provenance: Provenance | undefined;
	let sources: readonly LoadedSource[] | undefined;
	let configError: string | undefined;
	let ownershipError: string | undefined;
	/** Every code root this process loaded, inside writable roots or not (#36). */
	let loadedCode: readonly CodeRoot[] = [];

	let compiled: CompiledProfile | undefined;
	/**
	 * Watches Git, pi configuration and project files the compiled profile
	 * could not deny (#33, #19).
	 */
	let tripwire: PersistenceTripwire | undefined;
	/** Its hits, kept until the user acknowledges them, across sessions. */
	let tripwireLedger: TripwireLedger | undefined;
	/** Set by session_start, so the tripwire can warn outside an event with a context. */
	let warnUser: ((message: string) => void) | undefined;
	const violations: Violation[] = [];

	/**
	 * pi's tool registry, read once per turn (#28). The gate asks for a tool's
	 * source, its reachability and its declared hints on every call, and each
	 * was a fresh `getAllTools()` walk. Dropped at every point the registry
	 * can change under us: a new turn, a new prompt and a session start (an
	 * MCP server that connects in between is picked up by the next of these).
	 */
	let toolRegistry: ReturnType<NonNullable<typeof pi.getAllTools>> | undefined;
	/** Whether any session has started; before that, pi asks project trust with its startup UI. */
	let sessionStarted = false;
	const registeredTools = () => (toolRegistry ??= pi.getAllTools?.() ?? []);
	const forgetToolRegistry = () => {
		toolRegistry = undefined;
	};
	/** Tools pi-enclave took out of the declared set, so a later wider policy can put them back. */
	const hiddenTools = new Set<string>();

	/**
	 * The lock table, and the execute-time guards that read it.
	 *
	 * The guards are wired into every operations object below rather than only
	 * into the gate, because pi prepares a whole batch of tool calls before
	 * executing any of them: a call gated before something went wrong is already
	 * prepared when it does, and blocking cannot un-prepare it.
	 */
	// Built with the defaults until the fold runs; session_start rebuilds it
	// from the configured thresholds. A `let` so that rebuild is visible to the
	// closures below, which read `breaker` at call time rather than capturing it.
	let breaker = new CircuitBreaker({ consecutive: 3, window: [10, 50] });
	/** Which layer settled each gate decision this session (#18). */
	let layers = emptyTally();
	/**
	 * Whether the current turn ran an unparsed command that no person was asked
	 * about (#18). Then no protected-path rule saw what it wrote, so a changed
	 * project file counts against the turn.
	 */
	let unjudgedInTurn = false;
	/** Tool calls the gate let run unjudged; their protected paths are write-denied (#64). */
	const unjudgedCalls = new Set<string>();
	/** Every existing path `rules.protectedPaths` names, for one unjudged call (#64). */
	const protectedTargets = () => {
		const backendProfile = compiled?.profile ?? profile;
		const rules = effective?.rules.protectedPaths;
		return protectedWriteTargets({
			writableRoots: backendProfile.writableRoots,
			workspace: cwd,
			patterns: rules ? [...rules.deny, ...rules.ask] : [],
			writeDeny: backendProfile.writeDeny ?? [],
		});
	};
	const directInput = new ProvenanceTracker();
	// `pendingOpen`, not just `open`: the breaker only opens in turn_end, after a
	// batch has run, but the whole batch's outcome is recorded before any of it
	// executes -- so the execute-time guard stops the batch that trips the breaker
	// from running its remaining calls, not just the next turn's.
	const breakerBlocks = () => breaker.open || breaker.pendingOpen(currentTurn);
	const lock = new ActionLock({ breakerOpen: breakerBlocks });
	/** Whether pi re-checks every tool at the moment it runs (#29). */
	const executionCheck = hasExecutionWrapper(pi);

	/**
	 * L4. Rebuilt from live state on every call rather than captured, because a
	 * terminal can be lost and an RPC client can disconnect, and the answer to
	 * "is anyone there?" must be the one that is true now.
	 */
	/** `attended.notify`, rate-limited per session (#30). */
	const notify = createNotifier({
		argv: () => effective?.attended.notify ?? [],
		onEvent: (fields) => audit?.append("pending", fields),
	});
	const queue = createQueueEscalation({
		stateRoot: () => stateDirs().state,
		sessionId: () => sessionId,
		sessionFile: () => sessionFile,
		profile: () => effective,
		// Folded exactly as session start folds it, so an unchanged
		// configuration hashes the same.
		reload: () => {
			const loaded = loadConfig({ cwd, projectTrusted });
			return loaded.ok ? loaded.profile : undefined;
		},
		home: homedir(),
		timeoutMs: () => effective?.attended.queueTimeoutMs ?? 3_600_000,
		signal: () => toolCallSignal,
		audit: (kind, fields) => audit?.append(kind, fields),
		onQueued: (record) => notify(record),
	});
	const escalator = createConfirmEscalator({
		queue,
		reachability: (action) => toolReachability(registeredTools(), action.tool, action.input),
		declaredHints: (action) => describeDeclaredHints(action.tool, registeredTools(), OWNED_TOOLS),
		ui: () => uiContext,
		attendance: () => attendance,
		confirmTimeoutMs: () => effective?.attended.confirmTimeoutMs ?? 300_000,
		onUnattended: (action, reason, toolSource) => {
			// A record is written whenever an escalation did not get a yes --
			// unattended, declined or timed out. The turn is over either way, and
			// the difference between "nobody was asked" and "someone said not now"
			// is a decision the person may want to revisit with more context.
			//
			// The guard below should never trip -- both are set in session_start
			// before the escalator can fire -- but if it ever did, a *silent* drop
			// in exactly the unattended path the record exists to serve is the
			// worst failure, so it is announced rather than swallowed.
			if (!effective || !sessionId) {
				const message = "pi-enclave: an action needed approval but no record could be written (no active session).";
				audit?.append("pending", { event: "write-skipped", hash: action.hash, reason: "no session" });
				process.stderr.write(`${message}\n`);
				return;
			}
			try {
				const { path, record } = writePending({
					stateRoot: stateDirs().state,
					sessionId,
					...(sessionFile !== undefined ? { sessionFile } : {}),
					action,
					profile: effective,
					configHash: configHash(effective),
					reason,
					...(toolSource !== undefined ? { toolSource } : {}),
				});
				audit?.append("pending", { event: "written", nonce: record.nonce, hash: action.hash, path });
				notify(record);
				process.stderr.write(
					`pi-enclave: an action needs approval. Run:\n  pi-enclave approve ${record.nonce}\n${path}\n`,
				);
			} catch (error) {
				// A record that cannot be written must not be silent: without it the
				// user has no way to resume, and the only thing worse than that is
				// their not knowing.
				const message = `pi-enclave: could not write the approval record: ${(error as Error).message}`;
				audit?.append("pending", { event: "write-failed", hash: action.hash, error: (error as Error).message });
				process.stderr.write(`${message}\n`);
			}
		},
		onEscalation: (event) => {
			audit?.append("attendance", {
				event: "escalation",
				outcome: event.outcome,
				attended: event.attended,
				hash: event.action.hash,
				...(event.reachability ? { reachability: event.reachability } : {}),
				tool: event.action.tool,
				reason: event.reason,
			});
		},
	});
	/** Set by turn_start; every decision is attributed to the turn it happened in. */
	let currentTurn = 0;
	/** An admitted owned call earlier in the current prepared batch. */
	let queuedOwnedCall = false;
	let audit: AuditLog | undefined;
	/**
	 * Allowed calls waiting for pi to run them, by tool call id, and the exit
	 * code each bash action ended with, by action hash: together they make the
	 * `executed` record that follows a `decision: allow` (#37).
	 */
	const executions = new Map<string, { tool: string; hash: string; turnIndex: number }>();
	/**
	 * By tool call id, not action hash: two identical commands in one batch
	 * share a hash, and the second exit code would be reported for both.
	 */
	const exitCodes = new Map<string, number | null>();
	/** The tool call each executing bash action belongs to, for its exit code. */
	const callOfAction = new WeakMap<object, string>();
	/** The syslog copy of the head, when `audit.syslog` is set. */
	let syslogMirror: SyslogMirror | undefined;
	/** Sessions retention kept past the size budget because they hold an incident. */
	let keptForIncidents: string[] = [];
	/**
	 * Set when `audit.required` is on and the trail stopped recording: the log
	 * itself, or the syslog mirror the configuration asked for.
	 */
	const requiredAuditIssue = (): string | undefined => {
		if (!effective?.audit.required) return undefined;
		const why = audit?.degraded
			? audit.full
				? "the session reached audit.sessionMaxMb"
				: "a write failed"
			: syslogMirror?.stopped
				? "the syslog mirror stopped"
				: undefined;
		return why
			? `pi-enclave: the audit log is not recording (${why}), and audit.required is set, so nothing more may run in this session.`
			: undefined;
	};
	/**
	 * Under `audit.required`, wait for the queued records to land and say
	 * whether the trail is still recording. Without the wait the record of the
	 * very call being allowed could fail after the call ran.
	 */
	const auditLanded = async (): Promise<string | undefined> => {
		if (!effective?.audit.required) return undefined;
		await audit?.flush();
		return requiredAuditIssue();
	};
	let attendance: AttendanceState = { configured: "off", effective: "off" };
	/** Rebuilt per escalation from the live context, so a lost channel is seen. */
	let uiContext: ConfirmUI | undefined;
	/** The pi mode this session is running in, captured once at session start. */
	let piMode: "tui" | "rpc" | "json" | "print" = "print";
	let sessionId: string | undefined;
	let sessionFile: string | undefined;
	/** Whether session start folded the project files in; the queue reloads the same way. */
	let projectTrusted = false;
	/** The abort signal of the tool call being gated; an aborted turn stops a queue wait. */
	let toolCallSignal: AbortSignal | undefined;
	let actionReviewer: ActionReviewer | undefined;
	let reviewerSetup: Awaited<ReturnType<typeof prepareQualifiedReviewer>>;
	/** The reviewer model's warm-up request at session start (#25). */
	let warming: AbortController | undefined;
	const reviewAuthorization: ReviewAuthorization[] = [];
	let authorizationGeneration = 0;
	const reviewContext: ReviewContextEntry[] = [];

	/**
	 * When the lock is not the right thing to complain about.
	 *
	 * With a failed probe, a rejected configuration or a foreign tool, nothing
	 * was gated because nothing *could* be, and the operation is about to be
	 * refused anyway by `requireCompiled` with the diagnosis that tells the user
	 * what to fix. Letting the lock speak first would replace an actionable
	 * message with "this call did not pass the policy gate", which is true and
	 * useless. A Phase-1 test caught exactly that.
	 *
	 * With `PI_ENCLAVE_AUTO=off` there is deliberately no gate, so there is
	 * nothing for the table to know about.
	 */
	const lockNotApplicable = () =>
		!report.ok || configError !== undefined || ownershipError !== undefined || effective?.auto === false;

	const guardCommand = (command: string) => {
		if (lockNotApplicable()) return undefined;
		const entry = lock.beginExecution(`bash:${command}`);
		callOfAction.set(entry.action, entry.toolCallId);
		return entry.action;
	};
	const guardPath = (tool: string, path: string) => {
		if (lockNotApplicable()) return undefined;
		return lock.beginPathExecution(tool, path).action;
	};

	const registerOwnedTool = (tool: Parameters<typeof pi.registerTool>[0]) => {
		pi.registerTool(bindOwnedTool(tool, lock, lockNotApplicable));
	};
	const guardParent = (path: string) => (lockNotApplicable() ? undefined : lock.beginParentExecution(path).action);

	/** A snapshot for rendering. Rebuilt per call so it never goes stale. */
	const state = (): EnclaveState => ({
		report,
		backendName: backend.name,
		weakened: backend.weakened ?? false,
		...(backend.processLimit ? { processLimit: backend.processLimit } : {}),
		profile,
		compiled,
		violations,
		...(effective ? { effective } : {}),
		...(provenance ? { provenance } : {}),
		...(sources ? { sources } : {}),
		...(audit ? { auditPath: audit.path, auditDegraded: audit.degraded } : {}),
		...(syslogMirror ? { auditSyslogStopped: syslogMirror.stopped } : {}),
		...(keptForIncidents.length > 0 ? { auditKeptForIncidents: keptForIncidents.length } : {}),
		attendance: describeAttendance(attendance),
		pendingRoot: stateDirs().state,
		...(sessionId !== undefined ? { sessionId } : {}),
		...(tripwireLedger ? { tripwireLedger } : {}),
		loadedCode: loadedCode.map((root) => root.path),
		executionCheck,
		breaker: { open: breaker.open, consecutive: breaker.state.consecutive, limit: effective?.breaker.consecutive ?? 3 },
		layers: { ...layers },
		// A configuration refusal and an ownership refusal are both "auto mode
		// will not start"; the status line shows whichever came first.
		...(configError !== undefined
			? { configError }
			: ownershipError !== undefined
				? { configError: ownershipError }
				: {}),
	});

	/** Set by session_start, so denials can refresh the footer as they happen. */
	let refreshStatusLine: (() => void) | undefined;

	const recordViolations = (found: Violation[], adverseForBreaker: boolean) => {
		violations.push(...found);
		// Gate approval is provisional with respect to L2. A runtime denial is an
		// adverse outcome of the agent's action and must remain sticky for the turn,
		// even if the pre-execution gate already recorded an allow. Direct `!` input
		// is human-originated and passes false at its separate call site.
		if (effective?.auto) recordRuntimeViolation(breaker, currentTurn, found.length, adverseForBreaker);
		for (const violation of found) {
			audit?.append("violation", {
				// `violationKind`, not `kind`: the record's own `kind` is
				// "violation", and a field named `kind` would previously have
				// overwritten it (the reserved keys now win, so this would simply be
				// dropped -- either way the violation's own kind belongs on its own field).
				violationKind: violation.kind,
				op: violation.op,
				source: violation.source,
				backend: violation.backend,
				path: violation.path,
				host: violation.host,
				// Whether it counted for the breaker: a tripwire hit on a project
				// file counts only after an unjudged command (#18).
				adverse: adverseForBreaker,
			});
		}
		refreshStatusLine?.();
	};

	/**
	 * Report persistence paths that appeared or changed since the last check.
	 *
	 * `agent` says whether the change can only have come from the agent's
	 * turn. It then counts for the breaker like a denial. A change found
	 * between turns may be the user's own (an editor, a terminal), so it is
	 * reported and audited, but not counted.
	 */
	const checkTripwire = (agent: boolean) => {
		const hits = tripwire?.check() ?? [];
		if (hits.length === 0) return;
		const asViolations = (selected: typeof hits): Violation[] =>
			selected.map((hit) => ({
				kind: "write",
				source: "tripwire",
				op: hit.change,
				path: hit.path,
				backend: backend.name,
				...(hit.detail ? { raw: hit.detail } : {}),
			}));
		// Which hits count against the turn is decided in one place
		// (countsAgainstTurn): repeat reports never do, project files only in
		// a turn that ran an unparsed command nobody judged (#18).
		const unjudged = agent && unjudgedInTurn;
		const counted = hits.filter((hit) => countsAgainstTurn(hit, unjudged));
		const uncounted = hits.filter((hit) => !countsAgainstTurn(hit, unjudged));
		if (counted.length > 0) recordViolations(asViolations(counted), agent);
		if (uncounted.length > 0) recordViolations(asViolations(uncounted), false);
		try {
			tripwireLedger?.add(hits, agent);
		} catch (error) {
			process.stderr.write(`pi-enclave: could not record tripwire hits: ${(error as Error).message}\n`);
		}
		let message = formatTripwireHits(hits, agent ? "during the agent's turn" : "since the agent's last turn");
		if (unjudged && hits.some((hit) => hit.kind === "project")) {
			message +=
				"\npi-enclave: this turn ran a command L1 could not read, and no person was asked about it " +
				'(rules.onUncertain "sandbox", or a reviewer allow), so these project file changes count against the turn.';
		}
		process.stderr.write(`${message}\n`);
		warnUser?.(message);
	};

	// Denials seen by the filesystem helper reach the same counter and footer as
	// shell ones. Without this the file tools would enforce silently -- the whole
	// point of step 7 being invisible in the one place a user looks.
	backend.onFsViolation = (violation) => recordViolations([violation], true);

	if (report.checks.some((check) => ["pi-version", "node-version"].includes(check.id) && check.status === "fail")) {
		// Refuse loudly, on stderr, at load time. ctx.ui.notify from session_start
		// fires and returns cleanly in --print mode but never reaches stdout, and
		// unattended is exactly where a silent fail-closed is most dangerous.
		process.stderr.write(`${formatProbeReport(report)}\n`);
	}

	/**
	 * The profile in force, or the reason there is none.
	 *
	 * Every tool below resolves this per call rather than capturing it: tools
	 * are registered before any profile is compiled, and `backend.fs()` retires
	 * the helper when the profile changes. It is also the fail-closed gate. When
	 * the probe failed there is no profile and never will be, and the refusal
	 * carries the probe's own diagnosis so the agent and the user see the same
	 * remediation the stderr line gave.
	 */
	const requireCompiled = (): CompiledProfile => {
		// A rejected configuration is a refusal, not a fallback to the defaults.
		// Falling back would run the session under a profile nobody chose, which
		// is exactly the "half-applied configuration" the loader refuses to build.
		if (configError) throw new Error(configError);
		if (!report.ok) throw new Error(`pi-enclave: refusing to run unsandboxed.\n${formatProbeReport(report)}`);
		if (!compiled) throw new Error("pi-enclave: sandbox is not ready");
		return compiled;
	};

	const operations = createEnclaveBashOperations({
		get backend() {
			return backend;
		},
		getCompiled: requireCompiled,
		onViolations: (found) => recordViolations(found, true),
		onDeniedReadAttempt: (paths) => recordRuntimeViolation(breaker, currentTurn, paths.length, true),
		onExit: (exitCode, action) => {
			const toolCallId = action ? callOfAction.get(action) : undefined;
			if (toolCallId !== undefined) exitCodes.set(toolCallId, exitCode);
		},
		guard: guardCommand,
		protectWrites: (action) => {
			const toolCallId = callOfAction.get(action);
			if (toolCallId === undefined || !unjudgedCalls.has(toolCallId)) return undefined;
			const found = protectedTargets();
			if (!found.ok) {
				throw new Error(
					`pi-enclave: this command was not judged by anyone, and its protected paths cannot all be ` +
						`write-denied for it (${found.reason}); it does not run.`,
				);
			}
			return found.paths;
		},
	});

	/**
	 * Operations for the `!`/`!!` shortcut.
	 *
	 * `user_bash` is delivered on its own event and never goes through the
	 * `tool_call` gate, so no lock entry is ever registered for it -- and pi
	 * prepends a shell prefix before calling `exec`, so the command string would
	 * not match a registered key anyway. Using the gated `operations` here threw
	 * a LockViolation on every `!command`. The shortcut is direct human input, so
	 * it runs sandboxed (L2) with a breaker check but no lock lookup; the breaker
	 * still stops it once a turn has been shut down.
	 */
	const userBashOperations = createEnclaveBashOperations({
		get backend() {
			return backend;
		},
		getCompiled: requireCompiled,
		userCommand: true,
		onViolations: (found) => recordViolations(found, false),
		guard: () => {
			if (effective?.auto && breakerBlocks()) {
				throw new Error("pi-enclave: the denial circuit breaker is open; this turn is over.");
			}
			const auditIssue = requiredAuditIssue();
			if (auditIssue) throw new Error(auditIssue);
			return undefined;
		},
	});

	const fsClient = (action?: import("./policy/canonical.ts").CanonicalAction) => {
		const compiledProfile = requireCompiled();
		if (action?.capability?.kind === "read") {
			if (!backend.fsWithReadCapability)
				throw new Error("pi-enclave: this backend does not support reviewed read leases");
			return backend.fsWithReadCapability(compiledProfile, action.capability.value, action.hash, action.cwd);
		}
		return backend.fs(compiledProfile);
	};
	const grepQueue = new GrepExecutionQueue();

	// Registered unconditionally. pi's registry starts with every built-in tool
	// and an extension only displaces one by registering the same name, so
	// skipping the overrides when the probe fails would leave pi's own `bash`
	// and file tools running with the user's full privileges -- the one outcome a
	// fail-closed probe exists to prevent. A failed probe therefore still takes
	// the tools over; they just refuse every call with the diagnosis.
	{
		const base = addCapabilityParameters(createBashTool(cwd, { operations }), {
			allow_write: "One exact filesystem path to make writable for this action only, subject to review",
			allow_read: "One exact configured read-deny root to lift for this action only, subject to review",
		});
		registerOwnedTool({ ...base, label: "bash (sandboxed)", promptGuidelines: BASH_PROMPT_GUIDELINES });

		// `!` and `!!` run through the sandbox by construction, but not through the
		// policy gate: they arrive on their own event with no `tool_call`, so they
		// get `userBashOperations` (sandboxed, breaker-checked, no lock lookup)
		// rather than the gated `operations`, which would refuse them as unlocked.
		// With no sandbox the shortcut is answered outright rather than left to a
		// throwing exec, so the user sees the diagnosis and not a stack trace.
		// A `!` command is the user's own, so what it changes is accepted, not
		// reported. Anything already changed before it is checked first, so it
		// cannot be absorbed into the user's baseline.
		const userBashWithTripwire: typeof userBashOperations = {
			...userBashOperations,
			async exec(...args) {
				checkTripwire(false);
				try {
					return await userBashOperations.exec(...args);
				} finally {
					tripwire?.rebaseline();
				}
			},
		};
		// The person's own command is not gated, but it is recorded: on a shared
		// server it belongs in the trail as much as the agent's (#37).
		const recordedUserBash = (event: { command: string; cwd: string; excludeFromContext: boolean }) => ({
			...userBashWithTripwire,
			async exec(...args: Parameters<typeof userBashWithTripwire.exec>) {
				const started = performance.now();
				const record = (fields: { exitCode?: number | null; error?: string }) =>
					audit?.append(
						"user_command",
						userCommandFields({
							command: event.command,
							cwd: event.cwd,
							excludeFromContext: event.excludeFromContext,
							durationMs: performance.now() - started,
							...fields,
						}),
					);
				// Recorded before it runs as well as after, so a command that never
				// finishes (a killed session, a hung process) is still in the trail,
				// and under audit.required one that cannot be recorded never runs.
				audit?.append(
					"user_command",
					userCommandFields({
						command: event.command,
						cwd: event.cwd,
						excludeFromContext: event.excludeFromContext,
						event: "started",
					}),
				);
				const unrecorded = await auditLanded();
				if (unrecorded) throw new Error(unrecorded);
				try {
					const result = await userBashWithTripwire.exec(...args);
					record({ exitCode: result.exitCode ?? null });
					return result;
				} catch (error) {
					record({ error: (error as Error).message });
					throw error;
				}
			},
		});
		pi.on("user_bash", (event) => {
			if (report.ok) return { operations: recordedUserBash(event) };
			return {
				result: {
					output: `pi-enclave: refusing to run unsandboxed.\n${formatProbeReport(report)}\n`,
					exitCode: 1,
					cancelled: false,
					truncated: false,
				},
			};
		});

		// The five tools whose operations objects pi lets us replace outright.
		// Each closes over fsClient() rather than a captured client, so a
		// recompiled profile retires the old helper without leaving a tool bound
		// to it.
		registerOwnedTool(
			addCapabilityParameters(createReadTool(cwd, { operations: createReadOperations(fsClient, guardPath) }), {
				allow_read: "One exact configured read-deny root to lift for this action only, subject to review",
			}),
		);
		registerOwnedTool(createEditTool(cwd, { operations: createEditOperations(fsClient, guardPath) }));
		registerOwnedTool(createWriteTool(cwd, { operations: createWriteOperations(fsClient, guardPath, guardParent) }));
		registerOwnedTool(
			addCapabilityParameters(
				createLsTool(cwd, {
					operations: createLsOperations(fsClient, guardPath, (path) =>
						lockNotApplicable() ? undefined : lock.beginDirectoryEntryExecution(path).action,
					),
				}),
				{
					allow_read: "One exact configured read-deny root to lift for this action only, subject to review",
				},
			),
		);
		registerOwnedTool(
			addCapabilityParameters(createFindTool(cwd, { operations: createFindOperations(fsClient, guardPath) }), {
				allow_read: "One exact configured read-deny root to lift for this action only, subject to review",
			}),
		);

		// grep is the exception: its operations object cannot redirect the `rg`
		// spawn, so pi's tool is kept whole and only `execute` is replaced. It is
		// read-only, so the lock's execute-once does not apply, but the breaker
		// re-check does -- without it a grep queued before a breaker trip would
		// still run. `runSandboxedGrep` is only reached after that guard.
		const grepBase = addCapabilityParameters(createGrepTool(cwd), {
			allow_read: "One exact configured read-deny root to lift for this action only, subject to review",
		});
		registerOwnedTool({
			...grepBase,
			label: "grep (sandboxed)",
			execute: async (_id: string, params: unknown, signal?: AbortSignal) => {
				const args = params as Parameters<typeof runSandboxedGrep>[1];
				return grepQueue.run(async () => {
					// Begin execution only after this search reaches the head of the
					// queue. Otherwise a breaker that opens while it is waiting could
					// be missed between admission and the actual filesystem access.
					const action = guardPath("grep", args.path ?? cwd);
					const resolved = await fsClient(action);
					const lease = isFsClientLease(resolved) ? resolved : undefined;
					const client = isFsClientLease(resolved) ? resolved.client : resolved;
					try {
						return await runSandboxedGrep({ fs: client, cwd, ...(signal ? { signal } : {}) }, args);
					} finally {
						await lease?.dispose();
					}
				}, signal);
			},
		} as Parameters<typeof pi.registerTool>[0]);
	}

	/**
	 * The one `tool_call` handler.
	 *
	 * Registered unconditionally and before anything else can be. Until the
	 * configuration is loaded there is no profile to judge against, so the gate
	 * refuses -- a tool call that arrives before `session_start` has not been
	 * gated by anything, and permitting it would be the one case the whole layer
	 * exists to prevent.
	 */
	pi.on("tool_call", async (event, ctx) => {
		toolCallSignal = ctx?.signal;
		if (configError) return { block: true, reason: configError };
		if (!report.ok) return { block: true, reason: formatProbeReport(report) };
		if (ownershipError) return { block: true, reason: ownershipError };
		if (!effective) return { block: true, reason: "pi-enclave: no policy is loaded yet, so nothing may run." };
		const auditIssue = requiredAuditIssue();
		if (auditIssue) return { block: true, terminate: true, reason: auditIssue };

		const ownedTool = OWNED_TOOLS.includes(event.toolName);

		// A channel can be lost mid-session. Re-checked here rather than only at
		// session start, and only ever narrowing.
		attendance = recheckAttendance(attendance, {
			mode: piMode,
			hasUI: uiContext !== undefined,
			hasTty: process.stdin.isTTY === true,
		});

		const decisionGeneration = authorizationGeneration;
		const decision: GateDecision = await decide(
			{ toolName: event.toolName, toolCallId: event.toolCallId, input: event.input as Record<string, unknown> },
			{
				profile: effective,
				cwd,
				home: homedir(),
				lock,
				owned: OWNED_TOOLS,
				escalator,
				...(actionReviewer ? { reviewer: actionReviewer } : {}),
				toolSource: (tool) => registeredTools().find((entry) => entry.name === tool)?.sourceInfo?.path,
				toolAnnotations: (tool) => registeredTools().find((entry) => entry.name === tool)?.annotations,
				writeCapabilityIssue: (value, actionCwd, tool) => {
					try {
						const lifetimeIssue = tool === "bash" ? shellWriteCapabilityIssue() : undefined;
						if (lifetimeIssue) return lifetimeIssue;
						validateWriteCapability(profile, actionCwd, value);
						return undefined;
					} catch (error) {
						if (error instanceof WriteBoundaryError) return { message: error.message, boundary: true as const };
						return (error as Error).message;
					}
				},
				readCapabilityIssue: (value, actionCwd, tool) => {
					try {
						const lifetimeIssue = tool === "bash" ? shellCapabilityIssue("read") : undefined;
						if (lifetimeIssue) return lifetimeIssue;
						validateReadCapability(profile, actionCwd, value);
						return undefined;
					} catch (error) {
						return (error as Error).message;
					}
				},
				breakerOpen: breakerBlocks,
				unjudgedWriteIssue: () => {
					const found = protectedTargets();
					return found.ok ? undefined : found.reason;
				},
				// With an execution check the third-party call is asked again when it
				// runs, so it need not be kept out of the batch in advance (#29).
				withholdBeforeExecution: () =>
					!executionCheck && shouldWithholdNonOwnedSibling(breaker, queuedOwnedCall, ownedTool)
						? "pi-enclave: this third-party tool is withheld because an earlier sandboxed call in the same batch could open the denial circuit breaker at runtime."
						: undefined,
				onDecision: (result) => {
					// A breaker-open decision is not evidence: the breaker already
					// opened, and feeding this turn back in as a (non-adverse) outcome
					// would reset the consecutive counter at turn_end and quietly close
					// the breaker again -- handing the agent fresh attempts at exactly
					// the outcome the breaker exists to stop. Only real gate decisions
					// count.
					if (effective?.auto && result.outcome !== "breaker-open") breaker.record(currentTurn, result.adverse);
					if (effective?.auto) recordLayer(layers, result.outcome);
					if (result.unjudged) {
						unjudgedInTurn = true;
						unjudgedCalls.add(event.toolCallId);
					}
					if (!result.action) {
						audit?.append("decision", {
							outcome: result.outcome,
							tool: event.toolName,
							turnIndex: currentTurn,
							reason: result.reason,
						});
						return;
					}
					const reachability = toolReachability(registeredTools(), result.action.tool, result.action.input);
					audit?.append("decision", {
						...decisionFields({
							action: result.action,
							outcome: result.outcome,
							matches: result.matches,
							turnIndex: currentTurn,
							attended: effective?.attended.mode ?? "off",
							...(result.reason !== undefined ? { reason: result.reason } : {}),
						}),
						...(reachability ? { reachability } : {}),
					});
				},
			},
		);
		if (decisionGeneration !== authorizationGeneration) {
			lock.consume(event.toolCallId);
			return {
				block: true,
				reason:
					"pi-enclave: direct instructions or active session branch changed during review; retry for a fresh decision",
			};
		}
		if (decision.action) rememberReviewContext(reviewContext, decision.action, decision.block === true);
		if (!decision.block) {
			// The decision record is queued inside decide(); under audit.required
			// the call runs only once it is on disk (#37).
			const unrecorded = await auditLanded();
			if (unrecorded) {
				lock.consume(event.toolCallId);
				refreshStatusLine?.();
				return { block: true, terminate: true, reason: unrecorded };
			}
		}
		refreshStatusLine?.();
		if (!decision.block) {
			if (ownedTool) queuedOwnedCall = true;
			if (decision.action) {
				executions.set(event.toolCallId, {
					tool: decision.action.tool,
					hash: decision.action.hash,
					turnIndex: currentTurn,
				});
			}
			return {};
		}
		return { block: true, reason: decision.reason ?? "denied", ...(decision.terminate ? { terminate: true } : {}) };
	});

	/**
	 * The execution-boundary check (#29), only on a pi that offers
	 * `pi.wrapToolExecution` (the frycm/pi prototype). Upstream pi 1.5.2 does
	 * not, and there the batch withholding above stays in force.
	 */
	if (executionCheck) {
		pi.wrapToolExecution(
			createExecutionCheck({
				lock,
				owned: OWNED_TOOLS,
				refusal: () => {
					if (configError) return configError;
					if (!report.ok) return formatProbeReport(report);
					if (ownershipError) return ownershipError;
					if (!effective) return "pi-enclave: no policy is loaded yet, so nothing may run.";
					return requiredAuditIssue();
				},
				passThrough: () => effective?.auto === false,
				// The call did not run, so it gets this record and no `executed`
				// one: pi still ends it with an error result, which would otherwise
				// read as a tool that ran and failed.
				onRefused: (refusal) => {
					const pending = executions.get(refusal.toolCallId);
					executions.delete(refusal.toolCallId);
					exitCodes.delete(refusal.toolCallId);
					audit?.append(
						"execution_refused",
						executionRefusedFields({
							...refusal,
							...(pending ? { hash: pending.hash } : {}),
							turnIndex: pending?.turnIndex ?? currentTurn,
						}),
					);
				},
			}),
		);
	}

	// ---------------------------------------------------------------------
	// Turn lifecycle: a batch is a turn, and a turn contributes one strike.
	// ---------------------------------------------------------------------

	pi.on("turn_start", (event) => {
		forgetToolRegistry();
		currentTurn = event.turnIndex;
		queuedOwnedCall = false;
		unjudgedInTurn = false;
		unjudgedCalls.clear();
		// A server that connected mid-run has its tools judged here, not only
		// at the next prompt.
		applyActiveTools();
	});

	pi.on("turn_end", async (event, ctx) => {
		// Every call of the turn has run or been refused by now. A lock entry
		// still here belongs to a call a later extension's tool_call handler
		// blocked, for which pi emits no tool_result; it would otherwise wait
		// for the next direct message to be cleared (#28).
		lock.reset();
		for (const [id, pending] of executions) if (pending.turnIndex < event.turnIndex) executions.delete(id);
		// Before the breaker closes the turn, so a persistence path created in
		// this turn is a strike against it.
		checkTripwire(true);
		// Whether this turn contributed a strike, before finishTurn consumes it.
		const recorded = breaker.hasOutcome(event.turnIndex);
		const opened = breaker.finishTurn(event.turnIndex);
		// Persist after every turn that had a gated outcome, not only when the
		// breaker opens -- otherwise a partial count (one or two adverse turns) is
		// lost on resume and the agent gets a fresh three attempts.
		if (recorded) pi.appendEntry(BREAKER_ENTRY_TYPE, breaker.state);
		if (!opened) return;
		// pi honours `terminate` only when every finalized result in the batch
		// carries it, and the calls already prepared will not. Aborting is what
		// actually stops the turn; the message is what stops the next attempt.
		ctx.abort();
		pi.sendUserMessage(steerMessage(), { deliverAs: "followUp" });
		audit?.append("breaker", { event: "opened", turnIndex: event.turnIndex, state: breaker.state });
		refreshStatusLine?.();
	});

	// ---------------------------------------------------------------------
	// Provenance feeds the breaker reset and the reviewer's authorization
	// evidence. Only direct human input is allowed into the latter.
	// ---------------------------------------------------------------------

	pi.on("input", (event) => {
		directInput.observe({
			text: event.text,
			source: event.source,
			...(event.streamingBehavior ? { streamingBehavior: event.streamingBehavior } : {}),
		});
	});

	pi.on("before_agent_start", (event) => {
		// Tools registered since the last prompt (an extension's late
		// registration, an MCP server that finished connecting) are judged now.
		forgetToolRegistry();
		applyActiveTools();
		// Changes made while the agent was idle are reported now, and then
		// belong to the baseline, so the user's own edits are never counted
		// against the next turn.
		checkTripwire(false);
		if (event.messageType === "user") directInput.confirmPrompt(event.prompt);
	});

	pi.on("message_start", (event) => {
		if (event.message.role !== "user") return;
		const text = messageText(event.message);
		const record = directInput.recordForMessage(text, Date.now());
		if (!record) return;
		authorizationGeneration++;
		lock.reset();
		pi.appendEntry(PROVENANCE_ENTRY_TYPE, record);
		reviewAuthorization.push({
			provenance: "direct",
			channel: record.source,
			text: record.rawText ?? text,
		});
		if (reviewAuthorization.length > MAX_AUTHORIZATION_ENTRIES) {
			reviewAuthorization.splice(0, reviewAuthorization.length - MAX_AUTHORIZATION_ENTRIES);
		}
		// A person said something, so the count starts again. Only a *direct*
		// message resets it: an extension calling sendUserMessage reaches the
		// same event with source "extension", and letting that clear a trip
		// would hand the reset to the process the breaker exists to stop.
		resetAndPersistBreaker(breaker, (customType, state) => pi.appendEntry(customType, state));
		refreshStatusLine?.();
	});

	// One call is finished, so its lock entry is spent. `edit` reads and then
	// writes under one entry, which is why this is here and not in the guards.
	pi.on("tool_result", (event) => {
		lock.consume(event.toolCallId);
	});

	// The decision says the gate let a call through; this says what became of
	// it. pi emits it for every call it ran, including nested ones.
	pi.on("tool_execution_end", (event) => {
		const pending = executions.get(event.toolCallId);
		if (!pending) return;
		executions.delete(event.toolCallId);
		const hasExit = exitCodes.has(event.toolCallId);
		const exitCode = exitCodes.get(event.toolCallId);
		exitCodes.delete(event.toolCallId);
		audit?.append(
			"executed",
			executedFields({
				toolCallId: event.toolCallId,
				tool: pending.tool,
				hash: pending.hash,
				isError: event.isError,
				...(event.durationMs !== undefined ? { durationMs: event.durationMs } : {}),
				...(hasExit ? { exitCode: exitCode ?? null } : {}),
				turnIndex: pending.turnIndex,
			}),
		);
	});

	/**
	 * Declare to the model only the tools the gate would let run (#28).
	 *
	 * In auto mode a tool outside `tools.allow` is refused at call time, and
	 * each refusal is an adverse outcome for the breaker: a small model that
	 * sees `codemode` or an MCP tool in its list calls it, is denied, and three
	 * such turns end the session for no reason to do with intent. The gate
	 * still enforces; this only stops offering what it will refuse. Tools are
	 * only ever removed from pi's active set (never added that pi or the user
	 * did not activate), and put back if a later policy allows them.
	 */
	const applyActiveTools = () => {
		if (!pi.getActiveTools || !pi.setActiveTools) return;
		const active = pi.getActiveTools();
		const registered = registeredTools();
		const names = new Set(registered.map((tool) => tool.name));
		// Hidden tools that are still registered are candidates again.
		const candidates = [...new Set([...active, ...[...hiddenTools].filter((name) => names.has(name))])];
		const enforcing = effective?.auto === true && !configError && !ownershipError;
		const permitted = (name: string) => {
			if (!enforcing || !effective) return true;
			const source = registered.find((tool) => tool.name === name)?.sourceInfo?.path;
			return checkTool({
				tool: name,
				tools: effective.tools,
				owned: OWNED_TOOLS,
				...(source !== undefined ? { source } : {}),
			}).allowed;
		};
		const keep = candidates.filter((name) => {
			if (permitted(name)) {
				// Back only if it was ours to hide; a tool pi or the user deactivated stays off.
				if (hiddenTools.delete(name) || active.includes(name)) return true;
				return false;
			}
			if (active.includes(name)) hiddenTools.add(name);
			return false;
		});
		if (keep.length === active.length && keep.every((name, index) => name === active[index])) return;
		pi.setActiveTools(keep);
	};
	// Not on `mcp_servers_change`: handling that event marks an extension as
	// the one that connects MCP servers, which would silence pi's report that
	// nothing does. It also fires on registration, before a server's tools
	// exist. A server's tools are judged at the next prompt instead.

	// Before anything is loaded from the project: a headless run does not
	// trust project resources the user-global policy does not list (#28).
	pi.on("project_trust", (event, ctx) => {
		const headless = ctx.mode !== "tui" || !ctx.hasUI;
		let answer: ReturnType<typeof answerProjectTrust>;
		try {
			answer = answerProjectTrust({
				cwd: event.cwd,
				mode: ctx.mode,
				hasUI: ctx.hasUI,
				config: loadConfig({ cwd: event.cwd, projectTrusted: false }),
			});
		} catch (error) {
			// pi treats a throwing handler as no answer and falls back to its trust
			// store, which may hold the very "yes" this exists to override.
			answer = headless
				? {
						trusted: "no",
						message: `pi-enclave: could not decide project trust (${(error as Error).message}), so this headless run does not trust the project.`,
					}
				: { trusted: "undecided" };
		}
		if (answer.message) {
			// For the first runtime pi asks with a startup context whose notify
			// prints nothing in interactive mode, so until a session has started
			// the warning goes to stderr, above pi's own prompt.
			if (answer.trusted === "no" || !sessionStarted) process.stderr.write(`${answer.message}\n`);
			else ctx.ui.notify(answer.message, "warning");
		}
		return { trusted: answer.trusted };
	});

	const restoreBranch = (ctx: ExtensionContext) => {
		authorizationGeneration++;
		directInput.reset();
		lock.reset();
		const restored = restoreReviewHistory(ctx.sessionManager.getBranch());
		reviewAuthorization.splice(0, reviewAuthorization.length, ...restored.authorization);
		reviewContext.splice(0, reviewContext.length, ...restored.context);
	};
	pi.on("session_tree", (_event, ctx) => restoreBranch(ctx));

	pi.on("session_start", async (_event, ctx) => {
		sessionStarted = true;
		forgetToolRegistry();
		compiled = undefined;
		executions.clear();
		exitCodes.clear();
		tripwire = undefined;
		tripwireLedger = undefined;
		warnUser = (message) => ctx.ui.notify(message, "warning");
		// Pi 1.1 executes built-in operations relative to ctx.cwd. SDK sessions
		// can differ from process.cwd(), so policy, hashes and grep must agree.
		cwd = ctx.cwd;
		actionReviewer = undefined;
		reviewerSetup = undefined;
		directInput.reset();
		reviewAuthorization.length = 0;
		reviewContext.length = 0;
		// Configuration is loaded here rather than at extension load because it
		// depends on `ctx.isProjectTrusted()`, which only exists once there is a
		// context. Refusals still go to stderr as well as to notify: in --print
		// mode the notify is delivered and returns cleanly but never reaches the
		// user, and unattended is where a silent fail-closed does most damage.
		projectTrusted = ctx.isProjectTrusted();
		const loaded = loadConfig({ cwd, projectTrusted });
		sources = loaded.sources;
		if (!loaded.ok) {
			configError = loaded.message;
			process.stderr.write(`${loaded.message}\n`);
			ctx.ui.notify(loaded.message, "error");
			ctx.ui.setStatus?.("enclave", renderStatusLine(state()));
			return;
		}
		configError = undefined;
		effective = loaded.profile;
		provenance = loaded.provenance;
		profile = toBackendProfile(loaded.profile, cwd);
		try {
			await backend.dispose();
			const selected = await selectBackend(effective.sandbox.backend, PI_VERSION ?? null, {
				nativeReport: nativeReport,
			});
			backend = selected.backend;
			report = selected.report;
			backend.onFsViolation = (violation) => recordViolations([violation], true);
			if (!report.ok) throw new Error(formatProbeReport(report));
		} catch (error) {
			configError = (error as Error).message;
			process.stderr.write(`${configError}\n`);
			ctx.ui.notify(configError, "error");
			ctx.ui.setStatus?.("enclave", renderStatusLine(state()));
			return;
		}
		restoreBranch(ctx);

		// Ownership is checked after the configuration, because the diagnosis is
		// only actionable once we know auto mode was going to start at all.
		const problems = checkOwnership({
			tools: pi.getAllTools?.() ?? [],
			ownPath: resolveOwnPath(pi) ?? OWN_SOURCE_PATH,
			cwd,
			projectTrusted: ctx.isProjectTrusted(),
		});
		if (problems.length > 0) {
			ownershipError = formatOwnershipProblems(problems);
			process.stderr.write(`${ownershipError}\n`);
			ctx.ui.notify(ownershipError, "error");
			ctx.ui.setStatus?.("enclave", renderStatusLine(state()));
			return;
		}

		// Grants on tools outside the sandbox that are worth a second look (#22):
		// a readOnly grant the tool itself contradicts, and an unpinned name.
		for (const warning of grantWarnings(
			loaded.profile.tools,
			registeredTools(),
			OWNED_TOOLS,
			loaded.profile.sandbox.network.mode,
		)) {
			ctx.ui.notify(warning, "warning");
		}
		applyActiveTools();

		// Loaded code below a writable root would run the agent's changes outside
		// the sandbox at the next start (#36). Refused, or with the user-global
		// opt-in write-denied for the session.
		loadedCode = collectCodeRoots(
			{
				ownSource: OWN_SOURCE_PATH,
				dependencyEntries: resolveDependencyEntries(OWN_SOURCE_PATH),
				...(process.argv[1] ? { piEntry: process.argv[1] } : {}),
				extensionPaths: extensionSourcePaths(pi),
				execPath: process.execPath,
				seccompHelper: process.platform === "linux" ? resolveSeccompHelper() : null,
				...(loaded.profile.attended.notify[0] ? { notifyProgram: loaded.profile.attended.notify[0] } : {}),
				cwd,
			},
			profile.writableRoots,
		);
		const codeCheck = checkCodeRoots(loadedCode, profile.writableRoots);
		const codeError = formatCodeRootProblems(codeCheck, loaded.profile.sandbox.allowSelfHosting);
		if (codeError) {
			ownershipError = codeError;
			process.stderr.write(`${codeError}\n`);
			ctx.ui.notify(codeError, "error");
			ctx.ui.setStatus?.("enclave", renderStatusLine(state()));
			return;
		}
		if (loaded.profile.sandbox.allowSelfHosting) profile = applySelfHosting(profile, codeCheck);
		// A notify command that cannot run is said now, not in an audit line
		// nobody reads while a session waits for a person who was never told.
		const notifyProblem = checkNotifyProgram(loaded.profile.attended.notify);
		if (notifyProblem) {
			process.stderr.write(`${notifyProblem}\n`);
			ctx.ui.notify(notifyProblem, "warning");
		}
		// Every loaded code root is a trust root for write capabilities too
		// (#21): a one-shot write to pi-enclave's package, its node_modules or
		// pi's own package runs the agent's code in the pi process next start.
		profile = protectLoadedCode(profile, loadedCode);
		ownershipError = undefined;

		// The state directory is opened before anything is recorded, and a
		// failure to secure it stops auto mode: pending approval records and the
		// attendance secret live there, and a directory anyone can write is one
		// where an approval can be forged.
		let qualifiedDir: string;
		try {
			const dirs = ensureStateDirs();
			qualifiedDir = dirs.qualified;
			const retention = applyRetention({
				dir: dirs.audit,
				retentionDays: loaded.profile.audit.retentionDays,
				retentionMb: loaded.profile.audit.retentionMb,
				keepSessionId: ctx.sessionManager.getSessionId(),
			});
			keptForIncidents = retention.keptForIncidents;
			if (keptForIncidents.length > 0) {
				const message =
					`pi-enclave: the audit directory is over audit.retentionMb (${loaded.profile.audit.retentionMb} MB) ` +
					`because ${keptForIncidents.length} session log(s) hold incidents (breaker, violation, approval or tampering) ` +
					"and are never deleted for size. Review and archive them, or raise the budget.";
				process.stderr.write(`${message}\n`);
				ctx.ui.notify(message, "warning");
			}
			const auditSettings = loaded.profile.audit;
			syslogMirror = auditSettings.syslog
				? createSyslogMirror((error) => {
						process.stderr.write(`pi-enclave: the audit syslog mirror stopped: ${error.message}\n`);
						if (auditSettings.required) {
							process.stderr.write("pi-enclave: audit.required is set, so no further tool call will run.\n");
						}
						refreshStatusLine?.();
					})
				: undefined;
			const auditError = (error: Error) => {
				process.stderr.write(`pi-enclave: audit write failed: ${error.message}\n`);
				if (auditSettings.required) {
					process.stderr.write("pi-enclave: audit.required is set, so no further tool call will run.\n");
				}
				refreshStatusLine?.();
			};
			audit = new AuditLog({
				dir: dirs.audit,
				sessionId: ctx.sessionManager.getSessionId(),
				readDeny: loaded.profile.sandbox.readDeny,
				maxBytes: auditSettings.sessionMaxMb * 1024 * 1024,
				...(syslogMirror ? { mirror: syslogMirror } : {}),
				onError: auditError,
			});
			audit.touch();
			audit.append("session_start", {
				pi: PI_VERSION ?? null,
				backend: backend.name,
				weakened: backend.weakened,
				// Lets verify tell a log whose anchor was deleted from one written
				// before anchors existed.
				...(audit.anchorPath ? { anchored: true } : {}),
			});
			audit.append(
				"config",
				configFields(
					loaded.profile,
					configHash(loaded.profile),
					loaded.sources.map((entry) => entry.path ?? entry.source),
				),
			);
		} catch (error) {
			const message =
				error instanceof StateDirError
					? error.message
					: `pi-enclave: cannot prepare the state directory: ${(error as Error).message}`;
			configError = message;
			process.stderr.write(`${message}\n`);
			ctx.ui.notify(message, "error");
			ctx.ui.setStatus?.("enclave", renderStatusLine(state()));
			return;
		}

		try {
			reviewerSetup = await prepareQualifiedReviewer(
				loaded.profile,
				loaded.provenance,
				ctx.modelRegistry,
				qualifiedDir,
			);
		} catch (error) {
			const message = (error as Error).message;
			configError = message;
			process.stderr.write(`${message}\n`);
			ctx.ui.notify(message, "error");
			ctx.ui.setStatus?.("enclave", renderStatusLine(state()));
			return;
		}

		// Attendance. Resolved after the configuration because it is configured,
		// and before the breaker because a fatal mismatch stops the session.
		piMode = ctx.mode as "tui" | "rpc" | "json" | "print";
		sessionId = ctx.sessionManager.getSessionId();
		sessionFile = ctx.sessionManager.getSessionFile();
		const attendanceEnv = {
			mode: piMode,
			hasUI: ctx.hasUI,
			hasTty: process.stdin.isTTY === true,
		};
		if (loaded.profile.attended.mode === "rpc" && ctx.mode === "rpc") {
			const handshake = await runHandshake({
				ui: { input: (title, placeholder, options) => ctx.ui.input(title, placeholder, options) },
				sessionId: ctx.sessionManager.getSessionId(),
				secretPath: stateDirs().attendSecret,
			});
			if (handshake.verified) {
				attendance = resolveAttendance("rpc", { ...attendanceEnv, handshakeVerified: true });
			} else {
				attendance = resolveAttendance("rpc", attendanceEnv);
				attendance = { ...attendance, reason: describeHandshakeFailure(handshake.reason) };
			}
		} else {
			attendance = resolveAttendance(loaded.profile.attended.mode, attendanceEnv);
		}
		audit?.append("attendance", {
			event: "resolved",
			configured: attendance.configured,
			effective: attendance.effective,
			reason: attendance.reason,
		});

		if (attendance.fatal) {
			// The configuration describes a situation that is not the real one.
			// Continuing as unattended would be safe and dishonest: the user would
			// be waiting for a dialog that is never coming.
			const message = `pi-enclave: refusing to start -- ${attendance.reason}.`;
			configError = message;
			process.stderr.write(`${message}\n`);
			ctx.ui.notify(message, "error");
			ctx.ui.setStatus?.("enclave", renderStatusLine(state()));
			return;
		}

		uiContext = ctx.ui;
		if (reviewerSetup) {
			const isolated = new IsolatedReviewer({
				profile: loaded.profile,
				prompt: reviewerSetup.prompt,
				primary: reviewerSetup.primary,
				...(reviewerSetup.fallback ? { fallback: reviewerSetup.fallback } : {}),
				timeoutMs: loaded.profile.reviewer.timeoutMs,
				onTelemetry: (metrics, request) =>
					audit?.append("reviewer", { event: "timing", hash: request.action.hash, ...metrics }),
				evidence: (request) => {
					// A stale or unrelated denial is not evidence for this decision.
					// Violations are supplied only for a capability retry of the same
					// kind whose target actually contains the denied path.
					const capability = request.action.capability;
					const target =
						capability && capability.kind !== "host"
							? resolveCapabilityTarget(request.action.cwd, capability.value)
							: undefined;
					const violation = target
						? [...violations]
								.reverse()
								.find(
									(entry) =>
										entry.kind === capability?.kind &&
										entry.path !== undefined &&
										isUnder(canonicalPath(entry.path), target),
								)
						: undefined;
					const reachability = toolReachability(registeredTools(), request.action.tool, request.action.input);
					return {
						attended: attendance.effective,
						...(reachability ? { toolReachability: reachability } : {}),
						authorization: reviewAuthorization,
						context: reviewContext,
						...(violation ? { violation } : {}),
					};
				},
			});
			// Load the model now, so the first review's timeout is not spent on
			// loading it (#25). Nothing is read from the answer; a failure here
			// shows up in the first review, which checks identity as always.
			// Aborted at shutdown, so a load never keeps a finished run alive.
			warming?.abort();
			warming = new AbortController();
			const warmSignal = AbortSignal.any([warming.signal, AbortSignal.timeout(REVIEWER_WARM_TIMEOUT_MS)]);
			for (const transport of [reviewerSetup.primary, reviewerSetup.fallback]) {
				if (transport && !isClassifier(transport)) transport.warm?.(warmSignal).catch(() => {});
			}
			// Every verdict is recorded, not only its timing: the model's own
			// decision and reason next to what the deterministic floor made of
			// them is what a later tuning pass needs (#37).
			actionReviewer = {
				review: async (request) => {
					const result = await isolated.review(request);
					audit?.append("reviewer", reviewerVerdictFields(result, request));
					return result;
				},
			};
		}

		// The breaker survives a resume. Guardian deliberately drops its counters
		// at session start; here they persist, because an unattended run that is
		// resumed after tripping should not get three fresh attempts at whatever
		// tripped it.
		lock.reset();
		// Rebuilt from the configured thresholds now that the fold has run, then
		// restored from the session's persisted state. Building it here rather
		// than at load is what makes `breaker.consecutive` / `window` actually
		// take effect and keeps the status line's reported limit honest.
		layers = emptyTally();
		breaker = new CircuitBreaker({
			consecutive: loaded.profile.breaker.consecutive,
			window: [...loaded.profile.breaker.window],
		});
		for (const entry of ctx.sessionManager.getEntries()) {
			if (entry.type !== "custom" || entry.customType !== BREAKER_ENTRY_TYPE) continue;
			if (isBreakerState(entry.data)) breaker.restore(entry.data);
		}

		try {
			compiled = await backend.compile(profile);
			// After compiling, which materialises the protected anchors, so their
			// creation is not reported as the agent's.
			const roots = profile.writableRoots;
			// Directories the profile in force write-denies are watched by
			// identity only, so a large protected `.pi` costs nothing per turn.
			const isProtected = protectedByProfile(compiled.profile);
			// Every protected pattern, built-in and user-global (#64): what L2
			// cannot deny before it exists is reported, and counted after an
			// unjudged command.
			const protectedPaths = effective?.rules.protectedPaths;
			const isProtectedPath = protectedEntryMatcher(
				protectedPaths ? [...protectedPaths.deny, ...protectedPaths.ask] : [],
				cwd,
			);
			tripwire = new PersistenceTripwire(() => persistenceSurface(roots, { isProtected, isProtectedPath }), cwd);
			// Hits from earlier sessions nobody acknowledged: with attendance off,
			// the notice at the time may have reached no one.
			tripwireLedger = TripwireLedger.forWorkspace(stateDirs().state, cwd);
			const pendingHits = formatPendingHits(tripwireLedger.state());
			if (pendingHits) {
				ctx.ui.notify(pendingHits, "warning");
				process.stderr.write(`${pendingHits}\n`);
			}
		} catch (error) {
			configError = (error as Error).message;
			ctx.ui.notify(configError, "error");
			process.stderr.write(`${configError}\n`);
		}
		refreshStatusLine = () => ctx.ui.setStatus?.("enclave", renderStatusLine(state()));
		refreshStatusLine();
	});

	pi.on("session_shutdown", async () => {
		warming?.abort();
		// How often each layer settled a decision (#18): the only way to tell
		// from the log whether a reviewer reduced interruptions.
		if (effective?.auto) audit?.append("summary", { layers: { ...layers }, description: describeTally(layers) });
		// A request held by the notify rate limit is announced before exit: in
		// "off" mode nobody else will say it is there.
		notify.flush();
		// Flush, then dispose, then flush once more: tearing the backend down can
		// deliver a last `onFsViolation` (a denial during teardown), which queues
		// an audit append that the first flush has already passed. The second
		// flush is what keeps that final record from being lost on exit.
		await audit?.flush();
		try {
			await backend.dispose();
		} finally {
			await audit?.flush();
		}
	});

	pi.registerCommand("enclave", {
		description: "pi-enclave status and diagnostics",
		handler: async (args, ctx) => {
			if (args.trim() === "rules critique") {
				if (!effective || !provenance) {
					ctx.ui.notify(configError ?? "pi-enclave: configuration has not been loaded yet", "error");
					return;
				}
				const result = await critiqueRulebook({
					profile: effective,
					provenance,
					...(reviewerSetup?.primary ? { primary: reviewerSetup.primary } : {}),
					...(reviewerSetup?.fallback ? { fallback: reviewerSetup.fallback } : {}),
					timeoutMs: effective.reviewer.timeoutMs,
				});
				ctx.ui.notify(formatCritique(result), result.note?.startsWith("reviewer critique failed") ? "warning" : "info");
				return;
			}
			if (args.trim() === "eval-reviewer") {
				const loadedForEval =
					effective && provenance
						? { ok: true as const, profile: effective, provenance }
						: loadConfig({ cwd, projectTrusted: ctx.isProjectTrusted() });
				if (!loadedForEval.ok) {
					ctx.ui.notify(loadedForEval.message, "error");
					return;
				}
				ctx.ui.notify("pi-enclave: running the reviewer qualification corpus; this may take several minutes.", "info");
				try {
					const runs = await qualifyConfiguredReviewers({
						profile: loadedForEval.profile,
						provenance: loadedForEval.provenance,
						registry: ctx.modelRegistry,
						qualifiedDir: ensureStateDirs().qualified,
					});
					const allPassed = runs.every((run) => run.record.passed);
					ctx.ui.notify(
						`${formatQualificationRuns(runs)}\n\n${allPassed ? "Restart pi to activate this qualification." : "The reviewer remains disabled."}`,
						allPassed ? "info" : "error",
					);
				} catch (error) {
					ctx.ui.notify(`pi-enclave: reviewer evaluation failed: ${(error as Error).message}`, "error");
				}
				return;
			}
			const output = handleEnclaveCommand(state(), args);
			ctx.ui.notify(output.text, output.level);
		},
	});
}
