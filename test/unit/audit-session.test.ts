/**
 * The audit trail of a live session (#37), driven through the extension's own
 * handlers with a fake backend: the decision carries the raw command, an
 * `executed` record follows each allowed call, a `!` command is recorded, and
 * `audit.required` stops the session when the log stops.
 */
import { mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { ExtensionAPI, ExtensionContext } from "@earendil-works/pi-coding-agent";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { CompiledProfile, Profile, RunRequest } from "../../src/backend/types.ts";
import { defaultProfile, OWNED_TOOLS } from "../../src/config/defaults.ts";
import type { EffectiveProfile } from "../../src/config/types.ts";

const mocks = vi.hoisted(() => ({
	loadConfig: vi.fn(),
	runs: [] as RunRequest[],
	/** What the fake sandbox does for a command, for tests that need an effect. */
	onRun: undefined as ((request: RunRequest) => void) | undefined,
	/** When set, the #64 walk fails with this reason. */
	protectedFail: undefined as string | undefined,
}));

vi.mock("../../src/gate/protected-writes.ts", async (original) => {
	const actual = await original<typeof import("../../src/gate/protected-writes.ts")>();
	return {
		...actual,
		protectedWriteTargets: (...args: Parameters<typeof actual.protectedWriteTargets>) =>
			mocks.protectedFail ? { ok: false, reason: mocks.protectedFail } : actual.protectedWriteTargets(...args),
	};
});

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
	checkCodeRoots: () => ({ exposed: [], refused: [] }),
}));

let root: string;
let ws: string;
let agentDir: string;
let previousAgentDir: string | undefined;

beforeEach(() => {
	root = realpathSync(mkdtempSync(join(tmpdir(), "enclave-audit-session-")));
	ws = join(root, "ws");
	agentDir = join(root, "agent");
	mkdirSync(ws, { recursive: true });
	previousAgentDir = process.env.PI_CODING_AGENT_DIR;
	process.env.PI_CODING_AGENT_DIR = agentDir;
	mocks.runs.length = 0;
	mocks.onRun = undefined;
	mocks.protectedFail = undefined;
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

async function session(edit: (profile: EffectiveProfile) => void = () => {}) {
	vi.resetModules();
	const { default: register } = await import("../../src/index.ts");
	const effective = defaultProfile({ cwd: ws, agentDir });
	effective.attended.mode = "off";
	edit(effective);
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
	const auditPath = join(agentDir, "enclave", "audit", "s1.jsonl");
	const call = async (id: string, command: string) => {
		const gate = (await handlers.get("tool_call")?.(
			{ toolName: "bash", toolCallId: id, input: { command } },
			context,
		)) as {
			block?: boolean;
			reason?: string;
		};
		if (gate?.block) return gate;
		let isError = false;
		try {
			await tools.get("bash")?.execute(id, { command }, undefined, undefined, context);
		} catch {
			isError = true;
		}
		await handlers.get("tool_result")?.({ toolCallId: id }, context);
		await handlers.get("tool_execution_end")?.({ toolCallId: id, toolName: "bash", isError, durationMs: 7 }, context);
		return gate;
	};
	const flush = async () => {
		await handlers.get("session_shutdown")?.({}, context);
	};
	const records = () =>
		readFileSync(auditPath, "utf8")
			.trim()
			.split("\n")
			.map((line) => JSON.parse(line) as Record<string, unknown>);
	const execute = (id: string, command: string) =>
		tools.get("bash")?.execute(id, { command }, undefined, undefined, context) ?? Promise.resolve();
	return { handlers, context, call, flush, records, auditPath, execute };
}

describe("a session's audit trail (#37)", () => {
	it("records the raw command and then what became of it", async () => {
		const stderr = vi.spyOn(process.stderr, "write").mockImplementation(() => true);
		try {
			const s = await session();
			await s.call("t1", "ls 'a b' # it's fine");
			await s.call("t2", "ls fails");
			await s.flush();
			const all = s.records();
			const decision = all.find((entry) => entry.kind === "decision" && entry.command === "ls 'a b' # it's fine");
			expect(decision).toMatchObject({ outcome: "allow", tool: "bash" });
			const executed = all.filter((entry) => entry.kind === "executed");
			expect(executed).toEqual([
				expect.objectContaining({ toolCallId: "t1", hash: decision?.hash, exitCode: 0, isError: false, durationMs: 7 }),
				expect.objectContaining({ toolCallId: "t2", exitCode: 3 }),
			]);
		} finally {
			stderr.mockRestore();
		}
	});

	// #18: the decision names what ran with the sandbox as its only boundary,
	// and shutdown records which layer settled each decision.
	it("records sandboxed-uncertain decisions and a layer summary at shutdown", async () => {
		const stderr = vi.spyOn(process.stderr, "write").mockImplementation(() => true);
		try {
			const s = await session((profile) => {
				profile.rules.onUncertain = "sandbox";
			});
			await s.call("t1", "ls");
			await s.call("t2", "npm test");
			await s.call("t3", "sudo ls");
			await s.call("t4", "git push origin main");
			await s.flush();
			const all = s.records();
			expect(all.find((entry) => entry.kind === "decision" && entry.command === "npm test")).toMatchObject({
				outcome: "sandboxed-uncertain",
			});
			expect(all.filter((entry) => entry.kind === "summary")).toEqual([
				expect.objectContaining({
					layers: { L1: 3, L3: 0, L4: 1, askDenied: 1, sandboxedUncertain: 1, other: 0 },
					description: "L1 3 (75%), L3 0 (0%), L4 1 (25%), ask-denied 1, sandboxed-uncertain 1",
				}),
			]);
		} finally {
			stderr.mockRestore();
		}
	});

	// #18 review: an unparsed command that ran with nobody asked may write a
	// project file no protected-path rule saw, so the tripwire counts it.
	it("counts a changed project file against a turn that ran an unjudged command", async () => {
		const stderr = vi.spyOn(process.stderr, "write").mockImplementation(() => true);
		try {
			const s = await session((profile) => {
				profile.rules.onUncertain = "sandbox";
			});
			const turn = async (index: number, id: string, command: string, content: string) => {
				mocks.onRun = () => writeFileSync(join(ws, "AGENTS.md"), content);
				await s.handlers.get("turn_start")?.({ turnIndex: index }, s.context);
				await s.call(id, command);
				await s.handlers.get("turn_end")?.({ turnIndex: index }, { ...s.context, abort: () => {} });
			};
			// Control: a command L1 read, so the protected-path ask rule saw it.
			await turn(1, "t1", "ls", "one");
			await turn(2, "t2", "npm test", "two");
			await s.flush();
			const hits = s
				.records()
				.filter((entry) => entry.kind === "violation" && entry.source === "tripwire")
				.map((entry) => [entry.op, entry.adverse]);
			expect(hits).toEqual([
				["created", false],
				["modified", true],
			]);
		} finally {
			stderr.mockRestore();
		}
	});

	// The reviewer half of the same backstop: a reviewer allow of an unparsed
	// command is unjudged by any rule; one of a command L1 read is not.
	it("counts a changed project file after a reviewer allowed an unparsed command", async () => {
		const stderr = vi.spyOn(process.stderr, "write").mockImplementation(() => true);
		try {
			const s = await session((profile) => {
				profile.reviewer.model = "ollama/reviewer";
				profile.review.trigger = "mutating";
			});
			const turn = async (index: number, id: string, command: string, content: string) => {
				mocks.onRun = () => writeFileSync(join(ws, "AGENTS.md"), content);
				await s.handlers.get("turn_start")?.({ turnIndex: index }, s.context);
				await s.call(id, command);
				await s.handlers.get("turn_end")?.({ turnIndex: index }, { ...s.context, abort: () => {} });
			};
			// Control: the reviewer allows a command L1 read (confident).
			await turn(1, "t1", "rm -f build/x", "one");
			await turn(2, "t2", "npm test", "two");
			await s.flush();
			const all = s.records();
			expect(all.filter((entry) => entry.kind === "decision").map((entry) => [entry.command, entry.outcome])).toEqual([
				["rm -f build/x", "review-allow"],
				["npm test", "review-allow"],
			]);
			const hits = all
				.filter((entry) => entry.kind === "violation" && entry.source === "tripwire")
				.map((entry) => [entry.op, entry.adverse]);
			expect(hits).toEqual([
				["created", false],
				["modified", true],
			]);
		} finally {
			stderr.mockRestore();
		}
	});

	it("records a ! command the person typed", async () => {
		const stderr = vi.spyOn(process.stderr, "write").mockImplementation(() => true);
		try {
			const s = await session();
			const answer = (await s.handlers.get("user_bash")?.(
				{ type: "user_bash", command: "systemctl status nginx", cwd: ws, excludeFromContext: true },
				s.context,
			)) as { operations: { exec: (c: string, cwd: string, o: { onData: () => void }) => Promise<unknown> } };
			await answer.operations.exec("prefix; systemctl status nginx", ws, { onData: () => {} });
			await s.flush();
			expect(s.records().find((entry) => entry.kind === "user_command" && entry.event === "finished")).toMatchObject({
				command: "systemctl status nginx",
				cwd: ws,
				excludeFromContext: true,
				exitCode: 0,
			});
		} finally {
			stderr.mockRestore();
		}
	});

	it("with audit.required, stops the session once the log cannot be written", async () => {
		const stderr = vi.spyOn(process.stderr, "write").mockImplementation(() => true);
		try {
			const s = await session((profile) => {
				profile.audit.required = true;
			});
			expect((await s.call("t1", "ls")).block).toBeFalsy();
			expect(mocks.runs.map((run) => run.command)).toEqual([expect.stringContaining("ls")]);
			// A directory where the log file was: every later append fails, even as root.
			rmSync(s.auditPath);
			mkdirSync(s.auditPath);
			// The call whose own decision record fails is the first one refused:
			// nothing runs unrecorded.
			const unrecorded = await s.call("t2", "ls second");
			expect(unrecorded).toMatchObject({ block: true, terminate: true });
			expect(unrecorded.reason).toContain("audit.required");
			const blocked = await s.call("t3", "ls third");
			expect(blocked).toMatchObject({ block: true, terminate: true });
			expect(mocks.runs).toHaveLength(1);
			expect(stderr).toHaveBeenCalledWith(expect.stringContaining("audit.required is set"));
		} finally {
			stderr.mockRestore();
		}
	});

	it("with audit.required, records a ! command before it runs and refuses one it cannot record", async () => {
		const stderr = vi.spyOn(process.stderr, "write").mockImplementation(() => true);
		try {
			const s = await session((profile) => {
				profile.audit.required = true;
			});
			const run = async (command: string) => {
				const answer = (await s.handlers.get("user_bash")?.(
					{ type: "user_bash", command, cwd: ws, excludeFromContext: false },
					s.context,
				)) as { operations: { exec: (c: string, cwd: string, o: { onData: () => void }) => Promise<unknown> } };
				return answer.operations.exec(command, ws, { onData: () => {} });
			};
			await run("uptime");
			await s.flush();
			const recorded = s.records().filter((entry) => entry.kind === "user_command");
			expect(recorded.map((entry) => entry.event)).toEqual(["started", "finished"]);
			rmSync(s.auditPath);
			mkdirSync(s.auditPath);
			await expect(run("uptime again")).rejects.toThrow(/audit\.required/);
			expect(mocks.runs.map((entry) => entry.command)).toEqual([expect.stringContaining("uptime")]);
		} finally {
			stderr.mockRestore();
		}
	});

	it("records exit codes per call, so identical commands in one batch keep their own", async () => {
		const stderr = vi.spyOn(process.stderr, "write").mockImplementation(() => true);
		try {
			const s = await session();
			await s.call("a", "ls fails");
			await s.call("b", "ls fails");
			await s.flush();
			const executed = s.records().filter((entry) => entry.kind === "executed");
			expect(executed.map((entry) => [entry.toolCallId, entry.exitCode])).toEqual([
				["a", 3],
				["b", 3],
			]);
			expect(s.records().find((entry) => entry.kind === "session_start")).toMatchObject({ anchored: true });
		} finally {
			stderr.mockRestore();
		}
	});

	it("without audit.required, keeps running and says the log is failing", async () => {
		const stderr = vi.spyOn(process.stderr, "write").mockImplementation(() => true);
		try {
			const s = await session();
			rmSync(s.auditPath);
			mkdirSync(s.auditPath);
			await s.call("t1", "ls");
			await s.handlers.get("session_shutdown")?.({}, s.context);
			expect((await s.call("t2", "ls")).block).toBeFalsy();
			expect(stderr).toHaveBeenCalledWith(expect.stringContaining("audit write failed"));
		} finally {
			stderr.mockRestore();
		}
	});
});

describe("an unjudged command's protected paths (#64)", () => {
	const plant = () => {
		writeFileSync(join(ws, "AGENTS.md"), "original\n");
		mkdirSync(join(ws, ".husky"));
		writeFileSync(join(ws, ".husky", "pre-commit"), "original\n");
	};
	const unparsed = `f=AGENTS.md; echo x > "$f"`;

	it.each([
		[
			"rules.onUncertain: sandbox",
			(profile: EffectiveProfile) => {
				profile.rules.onUncertain = "sandbox";
			},
		],
		[
			"an always-allow reviewer",
			(profile: EffectiveProfile) => {
				profile.reviewer.model = "ollama/reviewer";
				profile.review.trigger = "mutating";
			},
		],
	])("are write-denied for the call under %s", async (_name, edit) => {
		const stderr = vi.spyOn(process.stderr, "write").mockImplementation(() => true);
		try {
			plant();
			const s = await session(edit);
			const gate = await s.call("t1", unparsed);
			expect(gate?.block).not.toBe(true);
			expect(mocks.runs).toHaveLength(1);
			expect(mocks.runs[0]?.protectWrites).toEqual(expect.arrayContaining([join(ws, "AGENTS.md"), join(ws, ".husky")]));
			await s.flush();
		} finally {
			stderr.mockRestore();
		}
	});

	it("are not denied for a command L1 could read", async () => {
		const stderr = vi.spyOn(process.stderr, "write").mockImplementation(() => true);
		try {
			plant();
			const s = await session((profile) => {
				profile.rules.onUncertain = "sandbox";
			});
			await s.call("t1", "ls");
			expect(mocks.runs).toHaveLength(1);
			expect(mocks.runs[0]?.protectWrites).toBeUndefined();
			await s.flush();
		} finally {
			stderr.mockRestore();
		}
	});

	it("ask a person instead when they cannot all be denied", async () => {
		const stderr = vi.spyOn(process.stderr, "write").mockImplementation(() => true);
		try {
			plant();
			const s = await session((profile) => {
				profile.rules.onUncertain = "sandbox";
			});
			mocks.protectedFail = "the writable roots hold more than 200000 entries";
			const gate = await s.call("t1", unparsed);
			expect(gate?.block).toBe(true);
			expect(gate?.reason).toContain("cannot all be write-denied for it");
			expect(mocks.runs).toEqual([]);
			await s.flush();
		} finally {
			stderr.mockRestore();
		}
	});

	it("refuse the command at execution when the walk fails after the gate", async () => {
		const stderr = vi.spyOn(process.stderr, "write").mockImplementation(() => true);
		try {
			plant();
			const s = await session((profile) => {
				profile.rules.onUncertain = "sandbox";
			});
			const gate = (await s.handlers.get("tool_call")?.(
				{ toolName: "bash", toolCallId: "t1", input: { command: unparsed } },
				s.context,
			)) as { block?: boolean } | undefined;
			expect(gate?.block).not.toBe(true);
			mocks.protectedFail = "a protected file has 2 hard links";
			await expect(s.execute("t1", unparsed)).rejects.toThrow(/not judged by anyone.*it does not run/s);
			expect(mocks.runs).toEqual([]);
			await s.flush();
		} finally {
			stderr.mockRestore();
		}
	});

	// What L2 cannot deny before it exists: the tripwire watches every
	// protected pattern, the configured ones too, and counts a hit after an
	// unjudged command.
	it("that do not exist yet are reported and counted by the tripwire, user-global entries included", async () => {
		const stderr = vi.spyOn(process.stderr, "write").mockImplementation(() => true);
		try {
			const s = await session((profile) => {
				profile.rules.onUncertain = "sandbox";
				profile.rules.protectedPaths.ask.push("infra/**");
			});
			mocks.onRun = () => {
				mkdirSync(join(ws, ".github", "workflows"), { recursive: true });
				writeFileSync(join(ws, ".github", "workflows", "deploy.yml"), "on: push\n");
				mkdirSync(join(ws, "infra"));
				writeFileSync(join(ws, "infra", "main.tf"), "x\n");
			};
			await s.handlers.get("turn_start")?.({ turnIndex: 1 }, s.context);
			await s.call("t1", unparsed);
			await s.handlers.get("turn_end")?.({ turnIndex: 1 }, { ...s.context, abort: () => {} });
			await s.flush();
			const hits = s
				.records()
				.filter((entry) => entry.kind === "violation" && entry.source === "tripwire")
				.map((entry) => [entry.path, entry.op, entry.adverse]);
			expect(hits).toEqual(
				expect.arrayContaining([
					[join(ws, ".github", "workflows"), "created", true],
					[join(ws, "infra"), "created", true],
				]),
			);
		} finally {
			stderr.mockRestore();
		}
	});
});
