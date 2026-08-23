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
import { createBashTool, VERSION as PI_VERSION } from "@earendil-works/pi-coding-agent";
import { SrtBackend } from "./backend/srt.ts";
import type { CompiledProfile, Violation } from "./backend/types.ts";
import { createDevProfile } from "./config/profile.ts";
import { formatProbeReport } from "./probe.ts";
import { probeHost } from "./probe-host.ts";
import { BASH_PROMPT_GUIDELINES, createEnclaveBashOperations } from "./tools/bash.ts";

/** What the file tools currently are, stated plainly wherever status is shown. */
const COVERAGE_NOTE = "L2 covers shell execution only; file tools are not sandboxed yet (step 6)";

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

	if (report.ok) {
		const base = createBashTool(cwd, { operations });
		pi.registerTool({ ...base, label: "bash (sandboxed)", promptGuidelines: BASH_PROMPT_GUIDELINES });

		// `!` and `!!` reach the same operations object rather than a parallel
		// path, so there is no shortcut that bypasses the sandbox by construction.
		pi.on("user_bash", () => ({ operations }));
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
