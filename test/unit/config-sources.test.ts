import { describe, expect, it } from "vitest";
import { renderConfig, renderDefaults } from "../../src/config/render.ts";
import { configPaths, loadConfig, renderSources } from "../../src/config/sources.ts";

const CWD = "/work";
const HOME = "/home/u";
const AGENT_DIR = "/home/u/.pi/agent";
const PATHS = configPaths({ cwd: CWD, agentDir: AGENT_DIR });

/** A fake filesystem: a map of path to contents; anything absent is missing. */
function files(entries: Record<string, string>) {
	return (path: string) => entries[path];
}

function load(entries: Record<string, string>, options: Partial<Parameters<typeof loadConfig>[0]> = {}) {
	return loadConfig({
		cwd: CWD,
		home: HOME,
		tmp: "/tmp",
		agentDir: AGENT_DIR,
		env: {},
		projectTrusted: true,
		readFile: files(entries),
		...options,
	});
}

describe("loadConfig", () => {
	it("works with no configuration at all", () => {
		const result = load({});
		if (!result.ok) throw new Error(result.message);
		expect(result.profile.name).toBe("dev");
		expect(result.sources.map((s) => s.source)).toEqual(["builtin"]);
	});

	it("applies the user-global file", () => {
		const result = load({ [PATHS.userGlobal]: JSON.stringify({ rules: { ask: ["$defaults", "bash(deploy*)"] } }) });
		if (!result.ok) throw new Error(result.message);
		expect(result.profile.rules.ask).toContain("bash(deploy*)");
	});

	// A file that exists and cannot be parsed must never be treated as absent:
	// that is how a syntax error becomes a silently wider sandbox.
	it("refuses on malformed JSON rather than carrying on", () => {
		const result = load({ [PATHS.userGlobal]: "{ not json" });
		expect(result.ok).toBe(false);
		if (result.ok) return;
		expect(result.message).toContain("not valid JSON");
	});

	it("refuses when a file is unreadable", () => {
		const result = load(
			{},
			{
				readFile: (path: string) => {
					if (path === PATHS.userGlobal) throw new Error("EACCES");
					return undefined;
				},
			},
		);
		expect(result.ok).toBe(false);
	});

	describe("project trust", () => {
		const project = { [PATHS.projectShared]: JSON.stringify({ rules: { deny: ["bash(terraform destroy*)"] } }) };

		it("reads project files when the project is trusted", () => {
			const result = load(project);
			if (!result.ok) throw new Error(result.message);
			expect(result.profile.rules.deny).toContain("bash(terraform destroy*)");
		});

		// Reported rather than passed over quietly: a rule someone wrote and never
		// saw applied is worse than one they know was skipped.
		it("ignores them when it is not, and says so", () => {
			const result = load(project, { projectTrusted: false });
			if (!result.ok) throw new Error(result.message);
			expect(result.profile.rules.deny).not.toContain("bash(terraform destroy*)");
			const ignored = result.sources.find((entry) => entry.source === "project_shared");
			expect(ignored?.ignored).toBe("project is not trusted");
		});

		it("does not list project files that are absent", () => {
			const result = load({}, { projectTrusted: false });
			if (!result.ok) throw new Error(result.message);
			expect(result.sources.some((entry) => entry.source === "project_shared")).toBe(false);
		});
	});

	it("rejects a widening project file and names the file and the field", () => {
		const result = load({
			[PATHS.projectLocal]: JSON.stringify({ sandbox: { writableRoots: ["/etc"] } }),
		});
		expect(result.ok).toBe(false);
		if (result.ok) return;
		expect(result.message).toContain(".pi/enclave.local.json");
		expect(result.message).toContain("sandbox.writableRoots");
	});

	it("rejects a project file carrying a prose list and names the key", () => {
		const result = load({
			[PATHS.projectShared]: JSON.stringify({ review: { soft_deny: ["be careful"] } }),
		});
		expect(result.ok).toBe(false);
		if (result.ok) return;
		expect(result.message).toContain("review.soft_deny");
	});

	it("folds the environment between user-global and the project", () => {
		const result = load(
			{ [PATHS.userGlobal]: JSON.stringify({ attended: { mode: "tui" } }) },
			{ env: { PI_ENCLAVE_ATTENDED: "off" } },
		);
		if (!result.ok) throw new Error(result.message);
		expect(result.profile.attended.mode).toBe("off");
	});

	it("refuses an unknown PI_ENCLAVE_ variable", () => {
		const result = load({}, { env: { PI_ENCLAVE_BACKEND: "docker" } });
		expect(result.ok).toBe(false);
	});

	it("records provenance for every list entry", () => {
		const result = load({ [PATHS.userGlobal]: JSON.stringify({ rules: { deny: ["$defaults", "bash(mine)"] } }) });
		if (!result.ok) throw new Error(result.message);
		expect(result.provenance.get("rules.deny")?.get("bash(mine)")).toBe("user_global");
		expect(result.provenance.get("rules.deny")?.get("bash(sudo *)")).toBe("builtin");
	});
});

describe("rendering", () => {
	it("prints the built-in lists as JSON", () => {
		const json = JSON.parse(renderDefaults({ cwd: CWD, home: HOME, agentDir: AGENT_DIR }));
		expect(json["rules.deny"]).toContain("bash(sudo *)");
		expect(json["review.hard_deny"]).toEqual([]);
	});

	it("tags every effective entry with its source", () => {
		const result = load({ [PATHS.userGlobal]: JSON.stringify({ rules: { ask: ["$defaults", "bash(deploy*)"] } }) });
		if (!result.ok) throw new Error(result.message);
		const rendered = renderConfig(result.profile, result.provenance);
		expect(rendered).toMatch(/user_global\s+bash\(deploy\*\)/);
		expect(rendered).toMatch(/builtin\s+bash\(git push \*\)/);
	});

	// skipReview grants rather than restricts, so it must not sit among the
	// denials looking like one.
	it("labels skipReview as an allow verdict", () => {
		const result = load({ [PATHS.userGlobal]: JSON.stringify({ rules: { skipReview: ["bash(npm test*)"] } }) });
		if (!result.ok) throw new Error(result.message);
		expect(renderConfig(result.profile, result.provenance)).toContain("ALLOW (skips review)");
	});

	it("says when L1 and L4 are off but the sandbox is not", () => {
		const result = load({}, { env: { PI_ENCLAVE_AUTO: "off" } });
		if (!result.ok) throw new Error(result.message);
		expect(renderConfig(result.profile, result.provenance)).toContain("the sandbox is still in force");
	});

	it("renders the source list", () => {
		const result = load({ [PATHS.userGlobal]: "{}" });
		if (!result.ok) throw new Error(result.message);
		expect(renderSources(result.sources)).toContain("applied  /home/u/.pi/agent/enclave.json");
	});
});
