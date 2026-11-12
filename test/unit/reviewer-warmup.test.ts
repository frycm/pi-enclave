/**
 * The reviewer model is loaded at session start, so the first review's timeout
 * is not spent loading it (#25), and the load is abandoned at shutdown.
 */
import { mkdirSync, mkdtempSync, realpathSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { ExtensionAPI, ExtensionContext } from "@earendil-works/pi-coding-agent";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import type { CompiledProfile, Profile } from "../../src/backend/types.ts";
import { defaultProfile, OWNED_TOOLS } from "../../src/config/defaults.ts";

const mocks = vi.hoisted(() => ({
	loadConfig: vi.fn(),
	signals: [] as AbortSignal[],
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
			run: async () => ({ exitCode: 0, violations: [] }),
			fs: () => ({}),
			dispose: async () => {},
		},
		report: { ok: true, platform: "linux", backend: "bwrap", piVersion: "1.5.2", checks: [] },
	}),
}));
vi.mock("../../src/gate/code-roots.ts", async (original) => ({
	...(await original<typeof import("../../src/gate/code-roots.ts")>()),
	checkCodeRoots: () => ({ exposed: [], refused: [] }),
}));
vi.mock("../../src/reviewer/setup.ts", async (original) => {
	const actual = await original<typeof import("../../src/reviewer/setup.ts")>();
	const { buildReviewerPrompt, reviewerRulebook } = await import("../../src/reviewer/prompt.ts");
	return {
		...actual,
		prepareQualifiedReviewer: async (profile: { review: Parameters<typeof reviewerRulebook>[0] }) => ({
			prompt: buildReviewerPrompt(reviewerRulebook(profile.review, new Map())),
			primary: {
				name: "ollama/reviewer",
				numCtx: 8_192,
				complete: async () => '{"authorized":false,"decision":"ask","risk":"high","reason":"fixture"}',
				warm: async (signal: AbortSignal) => {
					mocks.signals.push(signal);
					await new Promise((resolve) => signal.addEventListener("abort", resolve, { once: true }));
				},
			},
		}),
	};
});

let root: string;
let previousAgentDir: string | undefined;

beforeEach(() => {
	root = realpathSync(mkdtempSync(join(tmpdir(), "enclave-warmup-")));
	mkdirSync(join(root, "ws"), { recursive: true });
	previousAgentDir = process.env.PI_CODING_AGENT_DIR;
	process.env.PI_CODING_AGENT_DIR = join(root, "agent");
	mocks.signals.length = 0;
});
afterEach(() => {
	if (previousAgentDir === undefined) delete process.env.PI_CODING_AGENT_DIR;
	else process.env.PI_CODING_AGENT_DIR = previousAgentDir;
	rmSync(root, { recursive: true, force: true });
});

it("warms the reviewer model at session start and abandons the load at shutdown", async () => {
	const { default: register } = await import("../../src/index.ts");
	const ws = join(root, "ws");
	const agentDir = join(root, "agent");
	const effective = defaultProfile({ cwd: ws, agentDir });
	effective.attended.mode = "off";
	effective.auto = true;
	effective.reviewer.model = "ollama/reviewer";
	mocks.loadConfig.mockReturnValue({ ok: true, profile: effective, provenance: new Map(), sources: [] });
	type Handler = (event: unknown, context: ExtensionContext) => unknown;
	const handlers = new Map<string, Handler>();
	const extension = { path: join(root, "ext", "index.ts"), baseDir: join(root, "ext") };
	register({
		registerTool: () => {},
		registerCommand: () => {},
		registerFlag: () => {},
		registerMessageRenderer: () => {},
		appendEntry: () => {},
		sendUserMessage: () => {},
		on: (event: string, handler: Handler) => handlers.set(event, handler),
		getAllTools: () => OWNED_TOOLS.map((name) => ({ name, sourceInfo: extension })),
		getCommands: () => [{ name: "enclave", source: "extension", sourceInfo: extension }],
	} as unknown as ExtensionAPI);
	const errors: string[] = [];
	const context = {
		cwd: ws,
		mode: "print",
		hasUI: false,
		isProjectTrusted: () => false,
		ui: { notify: (message: string, level: string) => level === "error" && errors.push(message), setStatus: () => {} },
		sessionManager: {
			getSessionId: () => "s1",
			getSessionFile: () => undefined,
			getEntries: () => [],
			getBranch: () => [],
		},
		modelRegistry: {},
	} as unknown as ExtensionContext;
	await handlers.get("session_start")?.({}, context);
	expect(errors).toEqual([]);
	expect(mocks.signals).toHaveLength(1);
	expect(mocks.signals[0]?.aborted).toBe(false);
	await handlers.get("session_shutdown")?.({}, context);
	expect(mocks.signals[0]?.aborted).toBe(true);
});
