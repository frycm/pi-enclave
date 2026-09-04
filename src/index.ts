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
import { fileURLToPath } from "node:url";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
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
import { shellWriteCapabilityIssue, validateWriteCapability } from "./backend/capability.ts";
import { SrtBackend } from "./backend/srt.ts";
import type { CompiledProfile, Violation } from "./backend/types.ts";
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
import { createConfirmEscalator } from "./escalate/confirm.ts";
import { describeHandshakeFailure, runHandshake } from "./escalate/handshake.ts";
import { writePending } from "./escalate/pending.ts";
import {
	BREAKER_ENTRY_TYPE,
	CircuitBreaker,
	isBreakerState,
	recordRuntimeViolation,
	resetAndPersistBreaker,
	shouldWithholdNonOwnedSibling,
	steerMessage,
} from "./gate/breaker.ts";
import { decide, type GateDecision } from "./gate/gate.ts";
import { ActionLock } from "./gate/lock.ts";
import { checkOwnership, formatOwnershipProblems } from "./gate/ownership.ts";
import { PROVENANCE_ENTRY_TYPE, ProvenanceTracker } from "./gate/provenance.ts";
import { formatProbeReport } from "./probe.ts";
import { probeHost } from "./probe-host.ts";
import { AuditLog, configFields, configHash, decisionFields } from "./state/audit.ts";
import { ensureStateDirs, StateDirError, stateDirs } from "./state/dir.ts";
import { applyRetention } from "./state/retention.ts";
import { BASH_PROMPT_GUIDELINES, createEnclaveBashOperations } from "./tools/bash.ts";
import {
	createEditOperations,
	createFindOperations,
	createLsOperations,
	createReadOperations,
	createWriteOperations,
} from "./tools/file-ops.ts";
import { GrepExecutionQueue, runSandboxedGrep } from "./tools/grep.ts";

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

/** The text of a user message, whatever content shape pi used for it. */
function messageText(message: { content?: unknown }): string {
	const content = message.content;
	if (typeof content === "string") return content;
	if (!Array.isArray(content)) return "";
	return content
		.map((part) => (part && typeof part === "object" && "text" in part ? String((part as { text: unknown }).text) : ""))
		.join("");
}

type ConfirmFn = (
	title: string,
	message: string,
	options?: { timeout?: number; signal?: AbortSignal },
) => Promise<boolean>;

export default function (pi: ExtensionAPI): void {
	const report = probeHost(PI_VERSION ?? null);
	const cwd = process.cwd();
	const backend = new SrtBackend();

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

	let compiled: CompiledProfile | undefined;
	const violations: Violation[] = [];

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
	const directInput = new ProvenanceTracker();
	// `pendingOpen`, not just `open`: the breaker only opens in turn_end, after a
	// batch has run, but the whole batch's outcome is recorded before any of it
	// executes -- so the execute-time guard stops the batch that trips the breaker
	// from running its remaining calls, not just the next turn's.
	const breakerBlocks = () => breaker.open || breaker.pendingOpen(currentTurn);
	const lock = new ActionLock({ breakerOpen: breakerBlocks });

	/**
	 * L4. Rebuilt from live state on every call rather than captured, because a
	 * terminal can be lost and an RPC client can disconnect, and the answer to
	 * "is anyone there?" must be the one that is true now.
	 */
	const escalator = createConfirmEscalator({
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
	let attendance: AttendanceState = { configured: "off", effective: "off" };
	/** Rebuilt per escalation from the live context, so a lost channel is seen. */
	let uiContext: { confirm: ConfirmFn } | undefined;
	/** The pi mode this session is running in, captured once at session start. */
	let piMode: "tui" | "rpc" | "json" | "print" = "print";
	let sessionId: string | undefined;
	let sessionFile: string | undefined;

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
		return lock.beginExecution(`bash:${command}`).action;
	};
	const guardPath = (tool: string, path: string) => {
		if (lockNotApplicable()) return;
		lock.beginPathExecution(tool, path);
	};

	/** A snapshot for rendering. Rebuilt per call so it never goes stale. */
	const state = (): EnclaveState => ({
		report,
		backendName: backend.name,
		weakened: backend.weakened,
		profile,
		compiled,
		violations,
		...(effective ? { effective } : {}),
		...(provenance ? { provenance } : {}),
		...(sources ? { sources } : {}),
		...(audit ? { auditPath: audit.path, auditDegraded: audit.degraded } : {}),
		attendance: describeAttendance(attendance),
		pendingRoot: stateDirs().state,
		...(sessionId !== undefined ? { sessionId } : {}),
		breaker: { open: breaker.open, consecutive: breaker.state.consecutive, limit: effective?.breaker.consecutive ?? 3 },
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
			});
		}
		refreshStatusLine?.();
	};

	// Denials seen by the filesystem helper reach the same counter and footer as
	// shell ones. Without this the file tools would enforce silently -- the whole
	// point of step 7 being invisible in the one place a user looks.
	backend.onFsViolation = (violation) => recordViolations([violation], true);

	if (!report.ok) {
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
		if (!report.ok) throw new Error(`pi-enclave: refusing to run unsandboxed.\n${formatProbeReport(report)}`);
		// A rejected configuration is a refusal, not a fallback to the defaults.
		// Falling back would run the session under a profile nobody chose, which
		// is exactly the "half-applied configuration" the loader refuses to build.
		if (configError) throw new Error(configError);
		if (!compiled) throw new Error("pi-enclave: sandbox is not ready");
		return compiled;
	};

	const operations = createEnclaveBashOperations({
		backend,
		getCompiled: requireCompiled,
		onViolations: (found) => recordViolations(found, true),
		onDeniedReadAttempt: (paths) => recordRuntimeViolation(breaker, currentTurn, paths.length, true),
		guard: guardCommand,
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
		backend,
		getCompiled: requireCompiled,
		onViolations: (found) => recordViolations(found, false),
		guard: () => {
			if (effective?.auto && breakerBlocks()) {
				throw new Error("pi-enclave: the denial circuit breaker is open; this turn is over.");
			}
			return undefined;
		},
	});

	const fsClient = () => backend.fs(requireCompiled());
	const grepQueue = new GrepExecutionQueue();

	// Registered unconditionally. pi's registry starts with every built-in tool
	// and an extension only displaces one by registering the same name, so
	// skipping the overrides when the probe fails would leave pi's own `bash`
	// and file tools running with the user's full privileges -- the one outcome a
	// fail-closed probe exists to prevent. A failed probe therefore still takes
	// the tools over; they just refuse every call with the diagnosis.
	{
		const base = createBashTool(cwd, { operations });
		pi.registerTool({ ...base, label: "bash (sandboxed)", promptGuidelines: BASH_PROMPT_GUIDELINES });

		// `!` and `!!` run through the sandbox by construction, but not through the
		// policy gate: they arrive on their own event with no `tool_call`, so they
		// get `userBashOperations` (sandboxed, breaker-checked, no lock lookup)
		// rather than the gated `operations`, which would refuse them as unlocked.
		// With no sandbox the shortcut is answered outright rather than left to a
		// throwing exec, so the user sees the diagnosis and not a stack trace.
		pi.on("user_bash", () => {
			if (report.ok) return { operations: userBashOperations };
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
		pi.registerTool(createReadTool(cwd, { operations: createReadOperations(fsClient, guardPath) }));
		pi.registerTool(createEditTool(cwd, { operations: createEditOperations(fsClient, guardPath) }));
		pi.registerTool(createWriteTool(cwd, { operations: createWriteOperations(fsClient, guardPath) }));
		pi.registerTool(createLsTool(cwd, { operations: createLsOperations(fsClient, guardPath) }));
		pi.registerTool(createFindTool(cwd, { operations: createFindOperations(fsClient, guardPath) }));

		// grep is the exception: its operations object cannot redirect the `rg`
		// spawn, so pi's tool is kept whole and only `execute` is replaced. It is
		// read-only, so the lock's execute-once does not apply, but the breaker
		// re-check does -- without it a grep queued before a breaker trip would
		// still run. `runSandboxedGrep` is only reached after that guard.
		const grepBase = createGrepTool(cwd);
		pi.registerTool({
			...grepBase,
			label: "grep (sandboxed)",
			execute: async (_id: string, params: unknown, signal?: AbortSignal) => {
				if (effective?.auto && breakerBlocks()) {
					throw new Error("pi-enclave: the denial circuit breaker is open; this search will not run.");
				}
				return grepQueue.run(
					() =>
						runSandboxedGrep(
							{ fs: fsClient(), cwd, ...(signal ? { signal } : {}) },
							params as Parameters<typeof runSandboxedGrep>[1],
						),
					signal,
				);
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
	pi.on("tool_call", async (event) => {
		if (!report.ok) return { block: true, reason: formatProbeReport(report) };
		if (configError) return { block: true, reason: configError };
		if (ownershipError) return { block: true, reason: ownershipError };
		if (!effective) return { block: true, reason: "pi-enclave: no policy is loaded yet, so nothing may run." };

		const ownedTool = OWNED_TOOLS.includes(event.toolName);

		// A channel can be lost mid-session. Re-checked here rather than only at
		// session start, and only ever narrowing.
		attendance = recheckAttendance(attendance, {
			mode: piMode,
			hasUI: uiContext !== undefined,
			hasTty: process.stdin.isTTY === true,
		});

		const decision: GateDecision = await decide(
			{ toolName: event.toolName, toolCallId: event.toolCallId, input: event.input as Record<string, unknown> },
			{
				profile: effective,
				cwd,
				home: homedir(),
				lock,
				owned: OWNED_TOOLS,
				escalator,
				toolSource: (tool) => pi.getAllTools?.().find((entry) => entry.name === tool)?.sourceInfo?.path,
				writeCapabilityIssue: (value, actionCwd, tool) => {
					try {
						const lifetimeIssue = tool === "bash" ? shellWriteCapabilityIssue() : undefined;
						if (lifetimeIssue) return lifetimeIssue;
						validateWriteCapability(profile, actionCwd, value);
						return undefined;
					} catch (error) {
						return (error as Error).message;
					}
				},
				breakerOpen: breakerBlocks,
				withholdBeforeExecution: () =>
					shouldWithholdNonOwnedSibling(breaker, queuedOwnedCall, ownedTool)
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
					if (!result.action) {
						audit?.append("decision", {
							outcome: result.outcome,
							tool: event.toolName,
							turnIndex: currentTurn,
							reason: result.reason,
						});
						return;
					}
					audit?.append(
						"decision",
						decisionFields({
							action: result.action,
							outcome: result.outcome,
							matches: result.matches,
							turnIndex: currentTurn,
							attended: effective?.attended.mode ?? "off",
							...(result.reason !== undefined ? { reason: result.reason } : {}),
						}),
					);
				},
			},
		);
		refreshStatusLine?.();
		if (!decision.block) {
			if (ownedTool) queuedOwnedCall = true;
			return {};
		}
		return { block: true, reason: decision.reason ?? "denied", ...(decision.terminate ? { terminate: true } : {}) };
	});

	// ---------------------------------------------------------------------
	// Turn lifecycle: a batch is a turn, and a turn contributes one strike.
	// ---------------------------------------------------------------------

	pi.on("turn_start", (event) => {
		currentTurn = event.turnIndex;
		queuedOwnedCall = false;
	});

	pi.on("turn_end", async (event, ctx) => {
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
	// Provenance. Phase 2's only consumer is the breaker reset; Phase 3's is
	// the reviewer's authorization evidence.
	// ---------------------------------------------------------------------

	pi.on("input", (event) => {
		directInput.observe({
			text: event.text,
			source: event.source,
			...(event.streamingBehavior ? { streamingBehavior: event.streamingBehavior } : {}),
		});
	});

	pi.on("before_agent_start", (event) => {
		directInput.confirmPrompt(event.prompt);
	});

	pi.on("message_start", (event) => {
		if (event.message.role !== "user") return;
		const text = messageText(event.message);
		const record = directInput.recordForMessage(text, Date.now());
		if (!record) return;
		pi.appendEntry(PROVENANCE_ENTRY_TYPE, record);
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

	pi.on("session_start", async (_event, ctx) => {
		if (!report.ok) {
			ctx.ui.notify(formatProbeReport(report), "error");
			ctx.ui.setStatus?.("enclave", renderStatusLine(state()));
			return;
		}

		// Configuration is loaded here rather than at extension load because it
		// depends on `ctx.isProjectTrusted()`, which only exists once there is a
		// context. Refusals still go to stderr as well as to notify: in --print
		// mode the notify is delivered and returns cleanly but never reaches the
		// user, and unattended is where a silent fail-closed does most damage.
		const loaded = loadConfig({ cwd, projectTrusted: ctx.isProjectTrusted() });
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
		ownershipError = undefined;

		// The state directory is opened before anything is recorded, and a
		// failure to secure it stops auto mode: pending approval records and the
		// attendance secret live there, and a directory anyone can write is one
		// where an approval can be forged.
		try {
			const dirs = ensureStateDirs();
			applyRetention({
				dir: dirs.audit,
				retentionDays: loaded.profile.audit.retentionDays,
				retentionMb: loaded.profile.audit.retentionMb,
				keepSessionId: ctx.sessionManager.getSessionId(),
			});
			audit = new AuditLog({
				dir: dirs.audit,
				sessionId: ctx.sessionManager.getSessionId(),
				readDeny: loaded.profile.sandbox.readDeny,
				onError: (error) => process.stderr.write(`pi-enclave: audit write failed: ${error.message}\n`),
			});
			audit.touch();
			audit.append("session_start", { pi: PI_VERSION ?? null, backend: backend.name, weakened: backend.weakened });
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

		uiContext = { confirm: (title, message, options) => ctx.ui.confirm(title, message, options) };

		// The breaker survives a resume. Guardian deliberately drops its counters
		// at session start; here they persist, because an unattended run that is
		// resumed after tripping should not get three fresh attempts at whatever
		// tripped it.
		directInput.reset();
		lock.reset();
		// Rebuilt from the configured thresholds now that the fold has run, then
		// restored from the session's persisted state. Building it here rather
		// than at load is what makes `breaker.consecutive` / `window` actually
		// take effect and keeps the status line's reported limit honest.
		breaker = new CircuitBreaker({
			consecutive: loaded.profile.breaker.consecutive,
			window: [...loaded.profile.breaker.window],
		});
		for (const entry of ctx.sessionManager.getEntries()) {
			if (entry.type !== "custom" || entry.customType !== BREAKER_ENTRY_TYPE) continue;
			if (isBreakerState(entry.data)) breaker.restore(entry.data);
		}

		compiled = await backend.compile(profile);
		refreshStatusLine = () => ctx.ui.setStatus?.("enclave", renderStatusLine(state()));
		refreshStatusLine();
	});

	pi.on("session_shutdown", async () => {
		// Flush, then dispose, then flush once more: tearing the backend down can
		// deliver a last `onFsViolation` (a denial during teardown), which queues
		// an audit append that the first flush has already passed. The second
		// flush is what keeps that final record from being lost on exit.
		await audit?.flush();
		await backend.dispose();
		await audit?.flush();
	});

	pi.registerCommand("enclave", {
		description: "pi-enclave status and diagnostics",
		handler: async (args, ctx) => {
			const output = handleEnclaveCommand(state(), args);
			ctx.ui.notify(output.text, output.level);
		},
	});
}
