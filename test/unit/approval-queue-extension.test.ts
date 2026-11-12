/**
 * #30 through the real extension (`src/index.ts`): the escalator is wired to
 * the queue, the turn's abort signal reaches the wait, and the notifier runs
 * for a queued record and for an ordinary pending one. Same harness as the
 * audit-session tests: pi-enclave's own handlers, a fake backend.
 */
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, realpathSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { ExtensionAPI, ExtensionContext } from "@earendil-works/pi-coding-agent";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { CompiledProfile, Profile, RunRequest } from "../../src/backend/types.ts";
import { defaultProfile, OWNED_TOOLS } from "../../src/config/defaults.ts";
import type { EffectiveProfile } from "../../src/config/types.ts";
import { claimQueued } from "../../src/escalate/queue.ts";

const mocks = vi.hoisted(() => ({
	loadConfig: vi.fn(),
	runs: [] as RunRequest[],
	/** What the fake sandbox does for a command, for tests that need an effect. */
	onRun: undefined as ((request: RunRequest) => void) | undefined,
	/** What session start handed the code-root check. */
	codeRoots: [] as { path: string; from: string }[],
}));

vi.mock("../../src/probe-host.ts", async (original) => ({
	...(await original<typeof import("../../src/probe-host.ts")>()),
	probeHost: () => ({ ok: true, platform: "linux", backend: "bwrap", piVersion: "1.5.2", checks: [] }),
}));
vi.mock("../../src/config/sources.ts", () => ({ loadConfig: mocks.loadConfig }));
vi.mock("../../src/backend/select.ts", () => ({
	selectBackend: async () => ({
		backend: {
			name: "fake",
			compile: async (profile: Profile) =>
				({ profile, backend: "fake", describe: () => "" }) as unknown as CompiledProfile,
			run: async (_compiled: CompiledProfile, request: RunRequest) => {
				mocks.runs.push(request);
				mocks.onRun?.(request);
				return { exitCode: request.command.includes("fails") ? 3 : 0, violations: [] };
			},
			fs: () => ({}),
			dispose: async () => {},
		},
		report: { ok: true, platform: "linux", backend: "bwrap", piVersion: "1.5.2", checks: [] },
	}),
}));
// A named reviewer answers allow/low to everything; with "none" the real setup runs.
vi.mock("../../src/reviewer/setup.ts", async (original) => {
	const actual = await original<typeof import("../../src/reviewer/setup.ts")>();
	const { buildReviewerPrompt, reviewerRulebook } = await import("../../src/reviewer/prompt.ts");
	return {
		...actual,
		prepareQualifiedReviewer: async (profile: EffectiveProfile, ...rest: unknown[]) =>
			profile.reviewer.model === "none"
				? (actual.prepareQualifiedReviewer as (...args: unknown[]) => unknown)(profile, ...rest)
				: {
						prompt: buildReviewerPrompt(reviewerRulebook(profile.review, new Map(), profile.rules)),
						primary: {
							name: "always-allow",
							numCtx: 8_192,
							complete: async () => '{"authorized":false,"decision":"allow","risk":"low","reason":"fine"}',
						},
					},
	};
});
// The code-root check reads pi's real install; this suite is about the log.
vi.mock("../../src/gate/code-roots.ts", async (original) => ({
	...(await original<typeof import("../../src/gate/code-roots.ts")>()),
	checkCodeRoots: (roots: { path: string; from: string }[]) => {
		mocks.codeRoots = roots;
		return { exposed: [], refused: [] };
	},
}));

let root: string;
let ws: string;
let agentDir: string;
let previousAgentDir: string | undefined;

beforeEach(() => {
	root = realpathSync(mkdtempSync(join(tmpdir(), "enclave-queue-ext-")));
	ws = join(root, "ws");
	agentDir = join(root, "agent");
	mkdirSync(ws, { recursive: true });
	previousAgentDir = process.env.PI_CODING_AGENT_DIR;
	process.env.PI_CODING_AGENT_DIR = agentDir;
	mocks.runs.length = 0;
	mocks.onRun = undefined;
});
afterEach(() => {
	if (previousAgentDir === undefined) delete process.env.PI_CODING_AGENT_DIR;
	else process.env.PI_CODING_AGENT_DIR = previousAgentDir;
	rmSync(root, { recursive: true, force: true });
});

type Handler = (event: unknown, context: ExtensionContext) => unknown;
interface Tool {
	name: string;
	execute: (
		id: string,
		params: unknown,
		signal: undefined,
		onUpdate: undefined,
		ctx: ExtensionContext,
	) => Promise<unknown>;
}

/** A notify command that leaves one file per notification, outside the workspace. */
const notified = () => join(root, "notified");
// Written under a temporary name and renamed, so a test that sees the file
// never reads it half-written.
const NOTIFY = () => [
	"/bin/sh",
	"-c",
	`mkdir -p '${notified()}' && cat > '${notified()}'/".$ENCLAVE_NONCE" && mv '${notified()}'/".$ENCLAVE_NONCE" '${notified()}'/"$ENCLAVE_NONCE"`,
];

async function session(mode: "queue" | "off", signal?: AbortSignal) {
	vi.resetModules();
	const { default: register } = await import("../../src/index.ts");
	const effective = defaultProfile({ cwd: ws, agentDir });
	effective.attended.mode = mode;
	effective.attended.queueTimeoutMs = 20_000;
	effective.attended.notify = NOTIFY();
	mocks.loadConfig.mockReturnValue({ ok: true, profile: effective, provenance: new Map(), sources: [] });
	const handlers = new Map<string, Handler>();
	const tools = new Map<string, Tool>();
	const extension = { path: join(root, "ext", "index.ts"), baseDir: join(root, "ext") };
	const api = {
		registerTool: (tool: Tool) => tools.set(tool.name, tool),
		registerCommand: () => {},
		registerFlag: () => {},
		registerMessageRenderer: () => {},
		appendEntry: () => {},
		sendUserMessage: () => {},
		on: (event: string, handler: Handler) => handlers.set(event, handler),
		getAllTools: () => OWNED_TOOLS.map((name) => ({ name, sourceInfo: extension })),
		getCommands: () => [{ name: "enclave", source: "extension", sourceInfo: extension }],
	} as unknown as ExtensionAPI;
	register(api);
	const context = {
		cwd: ws,
		mode: "print",
		hasUI: false,
		isProjectTrusted: () => false,
		...(signal ? { signal } : {}),
		ui: { notify: () => {}, setStatus: () => {} },
		sessionManager: {
			getSessionId: () => "s1",
			getSessionFile: () => undefined,
			getEntries: () => [],
			getBranch: () => [],
		},
		modelRegistry: {},
	} as unknown as ExtensionContext;
	await handlers.get("session_start")?.({}, context);
	const state = (name: string) => join(agentDir, "enclave", "state", "s1", name);
	const records = () =>
		readFileSync(join(agentDir, "enclave", "audit", "s1.jsonl"), "utf8")
			.trim()
			.split("\n")
			.map((line) => JSON.parse(line) as Record<string, unknown>);
	const gate = (id: string, command: string) =>
		handlers.get("tool_call")?.({ toolName: "bash", toolCallId: id, input: { command } }, context) as Promise<
			{ block?: boolean; reason?: string; terminate?: boolean } | undefined
		>;
	const run = async (id: string, command: string) => {
		await tools.get("bash")?.execute(id, { command }, undefined, undefined, context);
		await handlers.get("tool_result")?.({ toolCallId: id }, context);
	};
	const shutdown = () => handlers.get("session_shutdown")?.({}, context);
	return { state, records, gate, run, shutdown };
}

const nonces = (dir: string) =>
	existsSync(dir)
		? readdirSync(dir)
				.filter((name) => /^[0-9a-f]{32}\.json$/.test(name))
				.map((n) => n.slice(0, 32))
		: [];

async function until<T>(probe: () => T | undefined, ms = 10_000): Promise<T> {
	const started = Date.now();
	for (;;) {
		const value = probe();
		if (value !== undefined) return value;
		if (Date.now() - started > ms) throw new Error("timed out waiting");
		await new Promise((resolve) => setTimeout(resolve, 10));
	}
}

describe("queue mode in the extension (#30)", () => {
	it("holds an ask, and runs it in session once another terminal approves", async () => {
		const stderr = vi.spyOn(process.stderr, "write").mockImplementation(() => true);
		try {
			const s = await session("queue");
			const held = s.gate("t1", "git push origin main");
			const nonce = await until(() => nonces(s.state("queued"))[0]);
			// The notify program went through the loaded-code check (#36).
			expect(mocks.codeRoots).toContainEqual(expect.objectContaining({ from: "the attended.notify program" }));
			// Nothing ran while it waited.
			expect(mocks.runs).toEqual([]);
			expect(claimQueued(join(agentDir, "enclave", "state"), "s1", nonce, "approved")).toBe(true);
			const result = await held;
			expect(result?.block).not.toBe(true);
			await s.run("t1", "git push origin main");
			expect(mocks.runs.map((request) => request.command)).toEqual(["git push origin main"]);
			expect(nonces(s.state("consumed"))).toEqual([nonce]);
			// The notifier ran for the queued record, outside the workspace.
			await until(() => (existsSync(join(notified(), nonce)) ? true : undefined));
			expect(readFileSync(join(notified(), nonce), "utf8")).toContain(`decline: pi-enclave decline ${nonce}`);
			await s.shutdown();
			const events = s
				.records()
				.filter((entry) => entry.kind === "pending")
				.map((entry) => entry.event);
			expect(events).toEqual(expect.arrayContaining(["queued", "queue-approved", "resumed"]));
			expect(s.records().find((entry) => entry.kind === "decision")).toMatchObject({ outcome: "ask-approved" });
		} finally {
			stderr.mockRestore();
		}
	});

	it("stops waiting when the turn is aborted, and denies with today's text", async () => {
		const stderr = vi.spyOn(process.stderr, "write").mockImplementation(() => true);
		try {
			const controller = new AbortController();
			const s = await session("queue", controller.signal);
			const held = s.gate("t1", "git push origin main");
			const nonce = await until(() => nonces(s.state("queued"))[0]);
			controller.abort();
			const result = await held;
			expect(result).toMatchObject({ block: true, terminate: true });
			expect(result?.reason).toContain("this needs a person, and the answer was no");
			expect(nonces(s.state("pending"))).toEqual([nonce]);
			expect(mocks.runs).toEqual([]);
			await s.shutdown();
			// Stopped by the abort, not by the 20 s timeout.
			const events = s
				.records()
				.filter((entry) => entry.kind === "pending")
				.map((entry) => entry.event);
			expect(events).toContain("queue-aborted");
			expect(events).not.toContain("queue-timeout");
		} finally {
			stderr.mockRestore();
		}
	});

	it("notifies for an ordinary pending record in off mode", async () => {
		const stderr = vi.spyOn(process.stderr, "write").mockImplementation(() => true);
		try {
			const s = await session("off");
			const result = await s.gate("t1", "git push origin main");
			expect(result).toMatchObject({ block: true });
			const nonce = await until(() => nonces(s.state("pending"))[0]);
			await until(() => (existsSync(join(notified(), nonce)) ? true : undefined));
			expect(readFileSync(join(notified(), nonce), "utf8")).toContain(`approve: pi-enclave approve ${nonce}`);
			// A second request inside the rate-limit interval is held, and
			// announced at shutdown rather than lost with the process.
			await s.gate("t2", "git push origin release");
			const second = await until(() => nonces(s.state("pending")).find((n) => n !== nonce));
			expect(existsSync(join(notified(), second))).toBe(false);
			await s.shutdown();
			await until(() => (existsSync(join(notified(), second)) ? true : undefined));
		} finally {
			stderr.mockRestore();
		}
	});
});
