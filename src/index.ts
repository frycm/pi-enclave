/**
 * pi-enclave extension entry point.
 *
 * Phase 1, step 4: shell execution is OS-enforced. The `bash` tool and the
 * `!`/`!!` shortcuts both run through the sandbox backend.
 *
 * The file tools are NOT yet sandboxed -- they still use pi's own
 * implementations, which read and write from the pi process. Until the helper
 * lands in step 6 the status line says so, because a status line that overstated
 * the boundary would be the one lie this project cannot afford.
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

/** What the sandbox covers, stated plainly wherever status is shown. */
const COVERAGE_NOTE = "shell and file tools are OS-enforced; MCP and third-party tools are not";

export default function (pi: ExtensionAPI): void {
	const report = probeHost(PI_VERSION ?? null);
	const cwd = process.cwd();
	const backend = new SrtBackend();
	const profile = createDevProfile({ cwd });

	let compiled: CompiledProfile | undefined;
	const violations: Violation[] = [];
	const recordViolations = (found: Violation[]) => violations.push(...found);

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
		ctx.ui.setStatus?.("enclave", `enclave: ${backend.name} - workspace-write - net off`);
	});

	pi.on("session_shutdown", async () => {
		await backend.dispose();
	});

	pi.registerCommand("enclave", {
		description: "pi-enclave status and diagnostics",
		handler: async (args, ctx) => {
			const sub = args.trim() || "status";
			if (sub === "status") {
				const lines = [
					formatProbeReport(report),
					"",
					`backend:    ${backend.name}${compiled ? "" : " (not started)"}${backend.weakened ? " [WEAKENED nested mode]" : ""}`,
					`profile:    ${profile.mode}, network ${profile.network}`,
					`writable:   ${profile.writableRoots.join(", ")}`,
					`violations: ${violations.length} this session`,
					`coverage:   ${COVERAGE_NOTE}`,
				];
				ctx.ui.notify(lines.join("\n"), report.ok ? "info" : "error");
				return;
			}
			if (sub === "backend") {
				ctx.ui.notify(compiled?.describe() ?? "sandbox not started", "info");
				return;
			}
			if (sub === "violations") {
				const recent = violations.slice(-20);
				const text = recent.length
					? recent.map((v) => `${v.kind}: ${v.op} ${v.path ?? v.host ?? ""}`).join("\n")
					: "no violations this session";
				ctx.ui.notify(text, "info");
				return;
			}
			ctx.ui.notify(`unknown subcommand: ${sub} (try: status, backend, violations)`, "warning");
		},
	});
}
