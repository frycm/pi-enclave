import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { defaultProfile } from "../../src/config/defaults.ts";
import { writePending } from "../../src/escalate/pending.ts";
import { canonicalize } from "../../src/policy/canonical.ts";
import { configHash } from "../../src/state/audit.ts";
import { ensureStateDirs } from "../../src/state/dir.ts";

const root = dirname(dirname(dirname(fileURLToPath(import.meta.url))));

describe("packaged CLI entrypoint", () => {
	it("uses the package-relative wrapper", () => {
		const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8")) as {
			bin: { "pi-enclave": string };
		};
		expect(pkg.bin["pi-enclave"]).toBe("./bin/pi-enclave.mjs");
	});

	it("runs from a working directory outside the package", () => {
		const result = spawnSync(process.execPath, [join(root, "bin/pi-enclave.mjs"), "--help"], {
			cwd: tmpdir(),
			encoding: "utf8",
		});
		expect(result.status, result.stderr).toBe(0);
		expect(result.stdout).toContain("pi-enclave");
	});

	it("loads approval policy from the recorded action cwd, not the caller cwd", () => {
		const fixture = mkdtempSync(join(tmpdir(), "enclave-cli-cwd-"));
		try {
			const agentDir = join(fixture, "agent");
			const project = join(fixture, "project");
			const caller = join(fixture, "caller");
			mkdirSync(join(project, ".pi"), { recursive: true });
			mkdirSync(join(caller, ".pi"), { recursive: true });
			writeFileSync(join(caller, ".pi", "enclave.json"), "{ invalid caller config");
			const dirs = ensureStateDirs(agentDir);
			const profile = defaultProfile({ cwd: project, home: homedir(), agentDir });
			const nonce = "0123456789abcdef0123456789abcdef";
			writePending({
				stateRoot: dirs.state,
				sessionId: "session-cli",
				action: canonicalize({
					tool: "edit",
					input: { path: "notes.md", oldString: "before", newString: "after" },
					cwd: project,
					home: homedir(),
					profileName: profile.name,
				}),
				profile,
				configHash: configHash(profile),
				reason: "test approval",
				nonce,
			});

			const result = spawnSync(process.execPath, [join(root, "bin/pi-enclave.mjs"), "approve", nonce], {
				cwd: caller,
				encoding: "utf8",
				env: { ...process.env, PI_CODING_AGENT_DIR: agentDir },
			});
			expect(result.status).toBe(1);
			expect(result.stderr).toContain("only bash and write actions");
			expect(result.stderr).not.toContain("invalid JSON");
		} finally {
			rmSync(fixture, { recursive: true, force: true });
		}
	});
});
