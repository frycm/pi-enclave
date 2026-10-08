import { join } from "node:path";
import type { BackendSettings } from "../config/types.ts";
import type { ProbeReport } from "../probe.ts";
import { probeHost } from "../probe-host.ts";
import { stateDirs } from "../state/dir.ts";
import { ContainerBackend } from "./container/backend.ts";
import { requireContainerQualification } from "./container/qualification.ts";
import { SrtBackend } from "./srt.ts";
import type { SandboxBackend } from "./types.ts";

export async function selectBackend(
	settings: BackendSettings,
	piVersion: string | null,
	options: { nativeReport?: ProbeReport; root?: string } = {},
): Promise<{ backend: SandboxBackend; report: ProbeReport }> {
	const native = options.nativeReport ?? probeHost(piVersion);
	if (settings.kind === "native" || (settings.kind === "auto" && native.ok))
		return { backend: new SrtBackend(), report: native };
	const root = options.root ?? stateDirs().root;
	const backend = new ContainerBackend(settings, join(root, "containers"));
	const checks = native.checks.filter((check) => ["pi-version", "node-version"].includes(check.id));
	try {
		if (checks.some((check) => check.status === "fail")) throw new Error("pi-enclave: unsupported pi or Node version");
		await requireContainerQualification(backend, join(root, "qualified"));
		checks.push({
			id: "container-qualified",
			title: "Container qualification",
			status: "ok",
			detail: `${backend.name}: exact local image, engine and implementation qualified`,
		});
		return { backend, report: { ...native, backend: backend.name, ok: true, checks } };
	} catch (error) {
		await backend.dispose();
		throw error;
	}
}
