import type { ExtensionAPI, ExtensionContext } from "@earendil-works/pi-coding-agent";
import { describe, expect, it, vi } from "vitest";
import { loadConfig } from "../../src/config/sources.ts";
import register from "../../src/index.ts";

vi.mock("../../src/probe-host.ts", () => ({
	probeHost: () => ({ ok: true, platform: "linux", backend: "bwrap", piVersion: "0.85.0", checks: [] }),
}));
vi.mock("../../src/config/sources.ts", () => ({
	loadConfig: vi.fn(() => ({ ok: false, message: "fixture stops before backend startup", sources: [] })),
}));

describe("SDK session cwd", () => {
	it("loads policy from the same cwd pi uses to execute tools", async () => {
		const handlers = new Map<string, (event: unknown, context: ExtensionContext) => unknown>();
		const api = {
			registerTool: () => {},
			registerCommand: () => {},
			on: (event: string, handler: (event: unknown, context: ExtensionContext) => unknown) => {
				handlers.set(event, handler);
			},
		} as unknown as ExtensionAPI;
		const stderr = vi.spyOn(process.stderr, "write").mockImplementation(() => true);
		try {
			register(api);
			const context = {
				cwd: "/tmp/pi-enclave-sdk-session",
				isProjectTrusted: () => true,
				ui: { notify: () => {}, setStatus: () => {} },
			} as unknown as ExtensionContext;
			expect(context.cwd).not.toBe(process.cwd());
			await handlers.get("session_start")?.({}, context);
			expect(loadConfig).toHaveBeenCalledWith({ cwd: context.cwd, projectTrusted: true });
		} finally {
			stderr.mockRestore();
		}
	});
});
