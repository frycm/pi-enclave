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
import { SrtBackend } from "./backend/srt.ts";
import type { CompiledProfile, Violation } from "./backend/types.ts";
import { type EnclaveState, handleEnclaveCommand, renderStatusLine } from "./commands/enclave.ts";
import { OWNED_TOOLS } from "./config/defaults.ts";
import { createDevProfile, toBackendProfile } from "./config/profile.ts";
import { type LoadedSource, loadConfig } from "./config/sources.ts";
import type { EffectiveProfile, Provenance } from "./config/types.ts";
import { decide, type GateDecision } from "./gate/gate.ts";
import { ActionLock } from "./gate/lock.ts";
import { checkOwnership, formatOwnershipProblems } from "./gate/ownership.ts";
import { formatProbeReport } from "./probe.ts";
import { probeHost } from "./probe-host.ts";
import { BASH_PROMPT_GUIDELINES, createEnclaveBashOperations } from "./tools/bash.ts";
import {
	createEditOperations,
	createFindOperations,
	createLsOperations,
	createReadOperations,
	createWriteOperations,
} from "./tools/file-ops.ts";
import { runSandboxedGrep } from "./tools/grep.ts";

/**
 * The path pi reports for tools this file registers.
 *
 * pi records the extension's own module path in `sourceInfo`, so the ownership
 * check compares against this rather than a name -- a name is something another
 * extension can also claim.
 */
const OWN_SOURCE_PATH = fileURLToPath(import.meta.url);

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
	const lock = new ActionLock();

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
		if (lockNotApplicable()) return;
		lock.beginExecution(`bash:${command}`);
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

	const recordViolations = (found: Violation[]) => {
		violations.push(...found);
		refreshStatusLine?.();
	};

	// Denials seen by the filesystem helper reach the same counter and footer as
	// shell ones. Without this the file tools would enforce silently -- the whole
	// point of step 7 being invisible in the one place a user looks.
	backend.onFsViolation = (violation) => recordViolations([violation]);

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
		onViolations: recordViolations,
		guard: guardCommand,
	});

	const fsClient = () => backend.fs(requireCompiled());

	// Registered unconditionally. pi's registry starts with every built-in tool
	// and an extension only displaces one by registering the same name, so
	// skipping the overrides when the probe fails would leave pi's own `bash`
	// and file tools running with the user's full privileges -- the one outcome a
	// fail-closed probe exists to prevent. A failed probe therefore still takes
	// the tools over; they just refuse every call with the diagnosis.
	{
		const base = createBashTool(cwd, { operations });
		pi.registerTool({ ...base, label: "bash (sandboxed)", promptGuidelines: BASH_PROMPT_GUIDELINES });

		// `!` and `!!` reach the same operations object rather than a parallel
		// path, so there is no shortcut that bypasses the sandbox by construction.
		// With no sandbox the shortcut is answered outright rather than left to a
		// throwing exec, so the user sees the diagnosis and not a stack trace.
		pi.on("user_bash", () => {
			if (report.ok) return { operations };
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
		// spawn, so pi's tool is kept whole and only `execute` is replaced.
		const grepBase = createGrepTool(cwd);
		pi.registerTool({
			...grepBase,
			label: "grep (sandboxed)",
			execute: async (_id: string, params: unknown, signal?: AbortSignal) =>
				runSandboxedGrep(
					{ fs: fsClient(), cwd, ...(signal ? { signal } : {}) },
					params as Parameters<typeof runSandboxedGrep>[1],
				),
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

		const decision: GateDecision = await decide(
			{ toolName: event.toolName, toolCallId: event.toolCallId, input: event.input as Record<string, unknown> },
			{
				profile: effective,
				cwd,
				home: homedir(),
				lock,
				owned: OWNED_TOOLS,
				toolSource: (tool) => pi.getAllTools?.().find((entry) => entry.name === tool)?.sourceInfo?.path,
			},
		);
		refreshStatusLine?.();
		if (!decision.block) return {};
		return { block: true, reason: decision.reason ?? "denied", ...(decision.terminate ? { terminate: true } : {}) };
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
		profile = toBackendProfile(loaded.profile);

		// Ownership is checked after the configuration, because the diagnosis is
		// only actionable once we know auto mode was going to start at all.
		const problems = checkOwnership({
			tools: pi.getAllTools?.() ?? [],
			ownPath: OWN_SOURCE_PATH,
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

		compiled = await backend.compile(profile);
		refreshStatusLine = () => ctx.ui.setStatus?.("enclave", renderStatusLine(state()));
		refreshStatusLine();
	});

	pi.on("session_shutdown", async () => {
		await backend.dispose();
	});

	pi.registerCommand("enclave", {
		description: "pi-enclave status and diagnostics",
		handler: async (args, ctx) => {
			const output = handleEnclaveCommand(state(), args);
			ctx.ui.notify(output.text, output.level);
		},
	});
}
