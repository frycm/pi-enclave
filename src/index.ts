/**
 * pi-enclave extension entry point.
 *
 * Phase 1 scaffold: the probe gate and the `/enclave status` command. Tool
 * overrides arrive in steps 4-7 -- until then this registers nothing that
 * executes, so loading it cannot weaken an existing setup.
 */
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { VERSION as PI_VERSION } from "@earendil-works/pi-coding-agent";
import { formatProbeReport } from "./probe.ts";
import { probeHost } from "./probe-host.ts";

export default function (pi: ExtensionAPI): void {
	const report = probeHost(PI_VERSION ?? null);

	pi.registerCommand("enclave", {
		description: "pi-enclave status and diagnostics",
		handler: async (args, ctx) => {
			const sub = args.trim() || "status";
			if (sub !== "status") {
				ctx.ui.notify(`unknown subcommand: ${sub} (try: status)`, "warning");
				return;
			}
			ctx.ui.notify(formatProbeReport(report), report.ok ? "info" : "error");
		},
	});

	if (!report.ok) {
		// Refuse loudly, on stderr, at load time.
		//
		// `ctx.ui.notify` from a session_start handler is not enough on its own:
		// it fires and returns cleanly in --print mode, but the message does not
		// reach stdout there -- and unattended is exactly where a silent
		// fail-closed is most dangerous. stderr is visible in every mode and does
		// not depend on a UI being attached.
		process.stderr.write(`${formatProbeReport(report)}\n`);
	}

	pi.on("session_start", (_event, ctx) => {
		if (report.ok) return;
		// Interactive users get it in the TUI as well, where stderr is not visible.
		// Phase 2 turns this into a refusal to start auto mode; today there is
		// nothing registered yet to disable.
		ctx.ui.notify(formatProbeReport(report), "error");
	});
}
