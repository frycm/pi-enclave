/**
 * #30 end to end: a headless pi session that hits an `ask` in queue mode holds
 * the tool call, `pi-enclave approve` in another process answers, and the
 * session runs the call itself, so the transcript's tool result is the real
 * one. A `decline` gives today's denial instead.
 *
 * The session is pi's own (`createAgentSession`, its nested tool pipeline);
 * the other terminal is the packaged CLI, run as a separate process with only
 * the state directory in common.
 */
import { type ChildProcess, spawn } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { fauxAssistantMessage, InMemoryCredentialStore } from "@earendil-works/pi-ai";
import {
	createAgentSession,
	createWriteTool,
	DefaultResourceLoader,
	type ExtensionFactory,
	ModelRuntime,
	SessionManager,
	SettingsManager,
} from "@earendil-works/pi-coding-agent";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { FsClient } from "../../src/backend/types.ts";
import { OWNED_TOOLS } from "../../src/config/defaults.ts";
import { loadConfig } from "../../src/config/sources.ts";
import { resolveAttendance } from "../../src/escalate/attendance.ts";
import { createConfirmEscalator } from "../../src/escalate/confirm.ts";
import { readPending } from "../../src/escalate/pending.ts";
import { createQueueEscalation } from "../../src/escalate/queue.ts";
import { decide } from "../../src/gate/gate.ts";
import { ActionLock } from "../../src/gate/lock.ts";
import { ensureStateDirs } from "../../src/state/dir.ts";
import { createWriteOperations } from "../../src/tools/file-ops.ts";
import { bindOwnedTool } from "../../src/tools/locked.ts";

const BIN = join(dirname(fileURLToPath(import.meta.url)), "../../bin/pi-enclave.mjs");
const SESSION = "session-queue-e2e";

let root: string;
let workspace: string;
let agentDir: string;

beforeEach(() => {
	root = mkdtempSync(join(tmpdir(), "enclave-queue-e2e-"));
	workspace = join(root, "workspace");
	agentDir = join(root, "agent");
	mkdirSync(workspace);
	mkdirSync(agentDir);
	writeFileSync(
		join(agentDir, "enclave.json"),
		JSON.stringify({ attended: { mode: "queue", queueTimeoutMs: 60_000 } }),
		{ mode: 0o600 },
	);
});

afterEach(() => {
	rmSync(root, { recursive: true, force: true });
});

/** The other terminal: the packaged CLI, answering on its stdin. */
function answer(verb: "approve" | "decline", nonce: string): Promise<{ status: number | null; stdout: string }> {
	return new Promise((resolve, reject) => {
		const child: ChildProcess = spawn(process.execPath, [BIN, verb, nonce], {
			cwd: root,
			env: { ...process.env, PI_CODING_AGENT_DIR: agentDir },
			stdio: ["pipe", "pipe", "pipe"],
		});
		let stdout = "";
		let stderr = "";
		child.stdout?.on("data", (chunk: Buffer) => {
			stdout += chunk.toString("utf8");
		});
		child.stderr?.on("data", (chunk: Buffer) => {
			stderr += chunk.toString("utf8");
		});
		child.on("error", reject);
		child.on("exit", (status) => resolve({ status, stdout: `${stdout}\n${stderr}` }));
		child.stdin?.end("y\n");
	});
}

async function headlessSession(verb: "approve" | "decline") {
	const loaded = loadConfig({ cwd: workspace, agentDir, projectTrusted: true });
	if (!loaded.ok) throw new Error(loaded.message);
	const profile = loaded.profile;
	expect(profile.attended.mode).toBe("queue");
	const dirs = ensureStateDirs(agentDir);
	const lock = new ActionLock();
	const answered: Promise<{ status: number | null; stdout: string }>[] = [];
	const escalator = createConfirmEscalator({
		ui: () => undefined,
		// print mode: no dialog can be drawn, nobody is at this terminal.
		attendance: () => resolveAttendance(profile.attended.mode, { mode: "print", hasUI: false, hasTty: false }),
		confirmTimeoutMs: () => profile.attended.confirmTimeoutMs,
		queue: createQueueEscalation({
			stateRoot: () => dirs.state,
			sessionId: () => SESSION,
			profile: () => profile,
			reload: () => {
				const again = loadConfig({ cwd: workspace, agentDir, projectTrusted: true });
				return again.ok ? again.profile : undefined;
			},
			home: homedir(),
			timeoutMs: () => profile.attended.queueTimeoutMs,
			onQueued: (record) => answered.push(answer(verb, record.nonce)),
			stderr: () => {},
			pollMs: 20,
		}),
	});

	const client = {
		mkdir: async (path: string) => {
			mkdirSync(path, { recursive: true });
		},
		writeFile: async (path: string, content: string) => writeFileSync(path, content),
	} as unknown as FsClient;
	const factories: ExtensionFactory[] = [
		(pi) => {
			const tool = createWriteTool(workspace, {
				operations: createWriteOperations(
					() => client,
					(name, path) => lock.beginPathExecution(name, path).action,
					(path) => lock.beginParentExecution(path).action,
				),
			});
			pi.registerTool(bindOwnedTool(tool, lock));
			pi.on("tool_call", async (event) =>
				decide(event, { profile, cwd: workspace, home: homedir(), owned: OWNED_TOOLS, lock, escalator }),
			);
			pi.on("tool_result", (event) => lock.consume(event.toolCallId));
		},
	];
	const settingsManager = SettingsManager.inMemory({});
	const loader = new DefaultResourceLoader({
		cwd: workspace,
		agentDir,
		settingsManager,
		extensionFactories: factories,
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
	await loader.reload();
	const { session } = await createAgentSession({
		cwd: workspace,
		agentDir,
		settingsManager,
		resourceLoader: loader,
		modelRuntime: runtime,
		sessionManager: SessionManager.inMemory(workspace),
	});
	try {
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
		// A Dockerfile is a protected path: writing it asks for a person.
		const result = await pipeline._executeNestedToolCall(
			"parent",
			"write",
			{ path: "Dockerfile", content: "FROM node:22-slim\n" },
			{},
		);
		const cli = await Promise.all(answered);
		return { result, cli, dirs };
	} finally {
		session.dispose();
	}
}

describe("queue mode, end to end (#30)", () => {
	it("continues after `pi-enclave approve` in another process, with the real tool result", async () => {
		const { result, cli, dirs } = await headlessSession("approve");
		expect(cli).toHaveLength(1);
		expect(cli[0]?.status, cli[0]?.stdout).toBe(0);
		expect(cli[0]?.stdout).toContain("Approved.");
		// The session ran the write itself and the agent got the write tool's own result.
		expect(result.isError, JSON.stringify(result.result)).toBe(false);
		expect(JSON.stringify(result.result)).toContain("Successfully wrote to Dockerfile");
		expect(readFileSync(join(workspace, "Dockerfile"), "utf8")).toBe("FROM node:22-slim\n");
		// One decision, one run.
		const consumed = readPending({
			stateRoot: dirs.state,
			sessionId: SESSION,
			nonce: /nonce: "([0-9a-f]{32})"/.exec(cli[0]?.stdout ?? "")?.[1] ?? "",
			state: "consumed",
		});
		expect(consumed.ok).toBe(true);
	}, 60_000);

	it("gives today's denial after `pi-enclave decline`, and nothing is written", async () => {
		const { result, cli } = await headlessSession("decline");
		expect(cli[0]?.status, cli[0]?.stdout).toBe(0);
		expect(result.isError).toBe(true);
		expect(JSON.stringify(result.result)).toContain("this needs a person, and the answer was no");
		expect(existsSync(join(workspace, "Dockerfile"))).toBe(false);
	}, 60_000);
});
