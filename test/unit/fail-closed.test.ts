/**
 * The fail-closed gate, asserted where it matters: at the registry.
 *
 * pi's registry starts with every built-in tool and an extension displaces one
 * only by registering the same name. So "the probe failed" must still mean
 * "pi-enclave registered `bash` and every file tool" -- the earlier version of
 * the entry point skipped the overrides when the probe failed, which left pi's
 * own unsandboxed tools in place with nothing but a notification to say so. A
 * fail-closed probe that falls open is worse than no probe: it tells the user
 * they are protected precisely when they are not.
 */
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { ProbeReport } from "../../src/probe.ts";

const FAILED: ProbeReport = {
	ok: false,
	platform: "darwin",
	backend: "seatbelt",
	piVersion: "0.99.0",
	checks: [
		{
			id: "pi-version",
			title: "pi version",
			status: "fail",
			detail: "pi 0.99.0 is outside >=0.84.2 <0.85.0",
			remediation: "pin pi",
		},
	],
};

vi.mock("../../src/probe-host.ts", () => ({ probeHost: () => FAILED }));

type Handler = (...args: unknown[]) => unknown;

/** The slice of ExtensionAPI the entry point touches, recording what it gets. */
function fakePi() {
	const tools = new Map<string, { execute: Handler }>();
	const handlers = new Map<string, Handler[]>();
	return {
		tools,
		handlers,
		api: {
			registerTool: (definition: { name: string; execute: Handler }) => {
				tools.set(definition.name, definition);
			},
			on: (event: string, handler: Handler) => {
				handlers.set(event, [...(handlers.get(event) ?? []), handler]);
			},
			registerCommand: () => {},
		},
	};
}

const PI_TOOLS = ["bash", "read", "edit", "write", "ls", "find", "grep"];

describe("entry point with a failed probe", () => {
	let fake: ReturnType<typeof fakePi>;
	let stderr: string;

	beforeEach(async () => {
		stderr = "";
		vi.spyOn(process.stderr, "write").mockImplementation((chunk) => {
			stderr += String(chunk);
			return true;
		});
		fake = fakePi();
		const { default: register } = await import("../../src/index.ts");
		register(fake.api as never);
	});

	it("still displaces every built-in tool", () => {
		// The guarantee is about the registry, not about error messages: a name
		// pi-enclave did not register is a name pi serves unsandboxed.
		for (const name of PI_TOOLS) {
			expect(fake.tools.has(name), `${name} was left to pi's unsandboxed built-in`).toBe(true);
		}
	});

	it("refuses every tool call with the probe's diagnosis", async () => {
		// Just enough context for pi's bash tool to reach its operations object.
		const ctx = { sessionManager: { getSessionId: () => "s", getSessionFile: () => undefined } } as never;
		const calls: Record<string, unknown> = {
			bash: { command: "id" },
			read: { path: "/etc/hostname" },
			edit: { path: "/tmp/x", edits: [{ oldText: "a", newText: "b" }] },
			write: { path: "/tmp/x", content: "y" },
			ls: { path: "/" },
			find: { pattern: "*" },
			grep: { pattern: "x" },
		};
		for (const name of PI_TOOLS) {
			const tool = fake.tools.get(name);
			if (!tool) throw new Error(`${name} not registered`);
			const outcome = await Promise.resolve()
				.then(() => tool.execute("call-1", calls[name], undefined, undefined, ctx))
				.then(
					(result) => ({ threw: false, text: JSON.stringify(result) }),
					(error: Error) => ({ threw: true, text: error.message }),
				);
			// pi's tools either propagate the operations error or fold it into an
			// error result; both are refusals as long as the diagnosis is there and
			// nothing ran. What must never happen is a successful result.
			expect(outcome.text, `${name} did not carry the probe diagnosis`).toMatch(
				/refusing to run unsandboxed|pi 0\.99\.0/,
			);
			if (!outcome.threw) expect(outcome.text).toMatch(/"isError":true/);
		}
	});

	it("answers ! and !! with the diagnosis instead of running the command", async () => {
		const [handler] = fake.handlers.get("user_bash") ?? [];
		expect(handler, "user_bash is not intercepted").toBeDefined();
		const result = (await handler?.({ command: "id", cwd: "/" }, {})) as {
			operations?: unknown;
			result?: { output: string; exitCode: number };
		};
		expect(result.operations).toBeUndefined();
		expect(result.result?.exitCode).toBe(1);
		expect(result.result?.output).toContain("refusing to run unsandboxed");
	});

	it("writes the diagnosis to stderr at load, for the modes with no UI", () => {
		expect(stderr).toContain("pi 0.99.0");
	});
});
