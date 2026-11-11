import { describe, expect, it } from "vitest";
import { defaultProfile } from "../../src/config/defaults.ts";
import { applyPatch, narrowerOrEqual } from "../../src/config/merge.ts";
import { parseDocument } from "../../src/config/schema.ts";

const options = {
	cwd: "/workspace",
	home: "/home/user",
	tmp: "/tmp/scratch",
	agentDir: "/home/user/.pi/agent",
	env: {},
};
const backend = {
	kind: "podman",
	image: `sha256:${"a".repeat(64)}`,
	binary: "/usr/bin/podman",
	readableRoots: ["~/data"],
};
describe("trusted container selection", () => {
	it("accepts only immutable images selected by user-global configuration", () => {
		expect(parseDocument({ sandbox: { backend } }, "user_global", undefined, options).ok).toBe(true);
		for (const source of ["env", "project_local", "project_shared"] as const)
			expect(parseDocument({ sandbox: { backend } }, source, undefined, options).ok).toBe(false);
		expect(
			parseDocument({ sandbox: { backend: { ...backend, image: "node:latest" } } }, "user_global", undefined, options)
				.ok,
		).toBe(false);
	});
	it("expands trusted read mounts and rejects backend changes in resumed profiles", () => {
		const parsed = parseDocument({ sandbox: { backend } }, "user_global", undefined, options);
		if (!parsed.ok || !parsed.document.patch) throw new Error("fixture parse failed");
		const before = defaultProfile(options);
		const after = applyPatch(before, parsed.document.patch, { ...options, source: "user_global" });
		expect(after.sandbox.backend.readableRoots).toEqual(["/home/user/data"]);
		expect(narrowerOrEqual(after, before).map((violation) => violation.field)).toContain("sandbox.backend");
	});
});
