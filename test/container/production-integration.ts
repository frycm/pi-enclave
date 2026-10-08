import { chmodSync, copyFileSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { fauxAssistantMessage, InMemoryCredentialStore } from "@earendil-works/pi-ai";
import {
	createAgentSession,
	DefaultResourceLoader,
	ModelRuntime,
	SessionManager,
	SettingsManager,
} from "@earendil-works/pi-coding-agent";
import { expect } from "vitest";
import { selectBackend } from "../../src/backend/select.ts";
import { approve } from "../../src/cli/approve.ts";
import { loadConfig } from "../../src/config/sources.ts";
import type { BackendSettings } from "../../src/config/types.ts";
import { writePending } from "../../src/escalate/pending.ts";
import register from "../../src/index.ts";
import { canonicalize } from "../../src/policy/canonical.ts";
import { configHash } from "../../src/state/audit.ts";
import { ensureStateDirs } from "../../src/state/dir.ts";

/** Drive the installed pi session and approval executor without an injected backend. */
export async function exerciseProduction(settings: BackendSettings, root: string): Promise<void> {
	const workspace = join(root, "production-workspace");
	mkdirSync(workspace);
	const agentDir = join(root, "agent");
	mkdirSync(agentDir);
	writeFileSync(join(agentDir, "enclave.json"), JSON.stringify({ sandbox: { backend: settings } }), { mode: 0o600 });
	const prior = process.env.PI_CODING_AGENT_DIR;
	const testEnv = Object.fromEntries(Object.entries(process.env).filter(([key]) => key.startsWith("PI_ENCLAVE_TEST_")));
	for (const key of Object.keys(testEnv)) delete process.env[key];
	process.env.PI_CODING_AGENT_DIR = agentDir;
	const dirs = ensureStateDirs(agentDir);
	// Copy only the record created by the complete real-engine corpus in this fixture.
	for (const name of readdirSync(join(root, "qualified"))) {
		copyFileSync(join(root, "qualified", name), join(dirs.qualified, name));
		chmodSync(join(dirs.qualified, name), 0o600);
	}
	const settingsManager = SettingsManager.inMemory({});
	const loader = new DefaultResourceLoader({
		cwd: workspace,
		agentDir,
		settingsManager,
		extensionFactories: [register],
		noExtensions: true,
		noSkills: true,
		noThemes: true,
		noPromptTemplates: true,
		noContextFiles: true,
	});
	const runtime = await ModelRuntime.create({
		credentials: new InMemoryCredentialStore(),
		modelsPath: null,
		allowModelNetwork: false,
	});
	let session: Awaited<ReturnType<typeof createAgentSession>>["session"] | undefined;
	try {
		await loader.reload();
		({ session } = await createAgentSession({
			cwd: workspace,
			agentDir,
			settingsManager,
			resourceLoader: loader,
			modelRuntime: runtime,
			sessionManager: SessionManager.inMemory(workspace),
		}));
		await session.bindExtensions({});
		session.agent.state.messages = [fauxAssistantMessage("fixture parent call")];
		const pipeline = session as unknown as {
			_executeNestedToolCall(
				parent: string,
				name: string,
				args: unknown,
				options: object,
			): Promise<{ isError: boolean; result: unknown }>;
		};
		const nested = (name: string, args: unknown) => pipeline._executeNestedToolCall("parent", name, args, {});
		const write = await nested("write", { path: "from-session.txt", content: "sandboxed session" });
		expect(write.isError, JSON.stringify(write.result)).toBe(false);
		expect(readFileSync(join(workspace, "from-session.txt"), "utf8")).toBe("sandboxed session");
		const shell = await nested("bash", { command: "echo session-shell > from-shell.txt" });
		expect(shell.isError, JSON.stringify(shell.result)).toBe(false);
		expect(readFileSync(join(workspace, "from-shell.txt"), "utf8")).toBe("session-shell\n");
		const read = await nested("read", { path: "from-session.txt" });
		expect(read.isError, JSON.stringify(read.result)).toBe(false);
		expect(JSON.stringify(read.result)).toContain("sandboxed session");

		const loaded = loadConfig({ cwd: workspace, agentDir, projectTrusted: true });
		if (!loaded.ok) throw new Error(loaded.message);
		const record = writePending({
			stateRoot: dirs.state,
			sessionId: "approval-fixture",
			action: canonicalize({
				tool: "bash",
				input: { command: "echo approved > from-approval.txt" },
				cwd: workspace,
				home: homedir(),
				profileName: "dev",
				writableRoots: loaded.profile.sandbox.writableRoots,
			}),
			profile: loaded.profile,
			configHash: configHash(loaded.profile),
			reason: "fixture human approval",
			nonce: "0123456789abcdef0123456789abcdef",
		}).record;
		expect(
			await approve({
				record,
				stateRoot: dirs.state,
				current: loaded.profile,
				reloadCurrent: () => loaded.profile,
				home: homedir(),
				io: { out: () => {}, err: () => {}, ask: async () => true },
			}),
		).toEqual({ outcome: "executed", exitCode: 0 });
		expect(readFileSync(join(workspace, "from-approval.txt"), "utf8")).toBe("approved\n");
		await expect(selectBackend(settings, "1.1.0", { root: join(root, "unqualified") })).rejects.toThrow(/unqualified/);
	} finally {
		await session?.extensionRunner.emit({ type: "session_shutdown", reason: "quit" });
		session?.dispose();
		if (prior === undefined) delete process.env.PI_CODING_AGENT_DIR;
		else process.env.PI_CODING_AGENT_DIR = prior;
		Object.assign(process.env, testEnv);
	}
}
