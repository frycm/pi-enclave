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
import { createDevProfile } from "./config/profile.ts";
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

export default function (pi: ExtensionAPI): void {
	const report = probeHost(PI_VERSION ?? null);
	const cwd = process.cwd();
	const backend = new SrtBackend();
	const profile = createDevProfile({ cwd });

	let compiled: CompiledProfile | undefined;
	const violations: Violation[] = [];

	/** A snapshot for rendering. Rebuilt per call so it never goes stale. */
	const state = (): EnclaveState => ({
		report,
		backendName: backend.name,
		weakened: backend.weakened,
		profile,
		compiled,
		violations,
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

	const operations = createEnclaveBashOperations({
		backend,
		// Compiled at session start, so the operations object is registered before
		// the profile exists and resolves it per call.
		getCompiled: () => {
			if (!compiled) throw new Error("pi-enclave: sandbox is not ready");
			return compiled;
		},
		onViolations: recordViolations,
	});

	/**
	 * The filesystem helper for the profile currently in force.
	 *
	 * Called per operation, never captured: tools are registered before any
	 * profile is compiled, and `backend.fs()` retires the helper when the profile
	 * changes.
	 */
	const fsClient = () => {
		if (!compiled) throw new Error("pi-enclave: sandbox is not ready");
		return backend.fs(compiled);
	};

	if (report.ok) {
		const base = createBashTool(cwd, { operations });
		pi.registerTool({ ...base, label: "bash (sandboxed)", promptGuidelines: BASH_PROMPT_GUIDELINES });

		// `!` and `!!` reach the same operations object rather than a parallel
		// path, so there is no shortcut that bypasses the sandbox by construction.
		pi.on("user_bash", () => ({ operations }));

		// The five tools whose operations objects pi lets us replace outright.
		// Each closes over fsClient() rather than a captured client, so a
		// recompiled profile retires the old helper without leaving a tool bound
		// to it.
		pi.registerTool(createReadTool(cwd, { operations: createReadOperations(fsClient) }));
		pi.registerTool(createEditTool(cwd, { operations: createEditOperations(fsClient) }));
		pi.registerTool(createWriteTool(cwd, { operations: createWriteOperations(fsClient) }));
		pi.registerTool(createLsTool(cwd, { operations: createLsOperations(fsClient) }));
		pi.registerTool(createFindTool(cwd, { operations: createFindOperations(fsClient) }));

		// grep is the exception: its operations object cannot redirect the `rg`
		// spawn, so pi's tool is kept whole and only `execute` is replaced.
		const grepBase = createGrepTool(cwd);
		pi.registerTool({
			...grepBase,
			label: "grep (sandboxed)",
			execute: async (_id: string, params: unknown) =>
				runSandboxedGrep({ fs: fsClient(), cwd }, params as Parameters<typeof runSandboxedGrep>[1]),
		} as Parameters<typeof pi.registerTool>[0]);
	}

	pi.on("session_start", async (_event, ctx) => {
		if (!report.ok) {
			ctx.ui.notify(formatProbeReport(report), "error");
			return;
		}
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
