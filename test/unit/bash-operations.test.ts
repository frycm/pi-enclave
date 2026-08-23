import { describe, expect, it, vi } from "vitest";
import type {
	CompiledProfile,
	Profile,
	RunRequest,
	RunResult,
	SandboxBackend,
	Violation,
} from "../../src/backend/types.ts";
import { createDevProfile, defaultReadDeny } from "../../src/config/profile.ts";
import { BASH_PROMPT_GUIDELINES, createEnclaveBashOperations, nextCommandId } from "../../src/tools/bash.ts";

const PROFILE: Profile = {
	mode: "workspace-write",
	writableRoots: ["/work"],
	readDeny: ["/home/u/.ssh"],
	network: "off",
	allowPty: true,
};

const COMPILED: CompiledProfile = { backend: "seatbelt", profile: PROFILE, describe: () => "compiled" };

/** Records what the operations layer hands the backend. */
function recordingBackend(result: Partial<RunResult> = {}) {
	const calls: RunRequest[] = [];
	const backend: SandboxBackend = {
		name: "seatbelt",
		compile: async () => COMPILED,
		run: async (_compiled, request) => {
			calls.push(request);
			return { exitCode: 0, violations: [], ...result };
		},
		fs: () => {
			throw new Error("not used");
		},
		dispose: async () => {},
	};
	return { backend, calls };
}

const collect = () => {
	const chunks: Buffer[] = [];
	return { onData: (c: Buffer) => chunks.push(c), text: () => Buffer.concat(chunks).toString("utf8") };
};

describe("createEnclaveBashOperations", () => {
	it("passes a sanitised environment, not the one pi supplies", async () => {
		// pi hands us the session environment, which carries the provider
		// credentials the agent is running on. Forwarding it would put them inside
		// the sandbox, where redirecting one into a file moves it into the
		// workspace for later disclosure.
		const { backend, calls } = recordingBackend();
		const ops = createEnclaveBashOperations({ backend, getCompiled: () => COMPILED });
		const out = collect();

		process.env.OPS_TEST_SECRET_TOKEN = "LEAKME";
		try {
			await ops.exec("true", "/work", {
				onData: out.onData,
				env: { ANTHROPIC_API_KEY: "sk-LEAK", PATH: "/usr/bin" } as NodeJS.ProcessEnv,
			});
		} finally {
			delete process.env.OPS_TEST_SECRET_TOKEN;
		}

		const env = calls[0]?.env ?? {};
		expect(Object.values(env).join("\n")).not.toContain("LEAK");
		expect(env.ANTHROPIC_API_KEY).toBeUndefined();
		expect(env.OPS_TEST_SECRET_TOKEN).toBeUndefined();
	});

	it("forwards the command, cwd, signal and timeout unchanged", async () => {
		const { backend, calls } = recordingBackend();
		const ops = createEnclaveBashOperations({ backend, getCompiled: () => COMPILED });
		const controller = new AbortController();

		await ops.exec("echo hi", "/work/sub", { onData: () => {}, signal: controller.signal, timeout: 42 });

		expect(calls[0]).toMatchObject({ command: "echo hi", cwd: "/work/sub", timeout: 42 });
		expect(calls[0]?.signal).toBe(controller.signal);
	});

	it("returns the backend's exit code", async () => {
		const { backend } = recordingBackend({ exitCode: 3 });
		const ops = createEnclaveBashOperations({ backend, getCompiled: () => COMPILED });
		expect(await ops.exec("false", "/work", { onData: () => {} })).toEqual({ exitCode: 3 });
	});

	it("appends violations to the output so the agent can change approach", async () => {
		// The operations interface can only return an exit code. An agent that
		// sees a bare failure retries it, often with sudo.
		const violation: Violation = {
			kind: "write",
			source: "kernel-log",
			op: "file-write-create",
			path: "/etc/passwd",
			backend: "seatbelt",
		};
		const { backend } = recordingBackend({ exitCode: 1, violations: [violation] });
		const ops = createEnclaveBashOperations({ backend, getCompiled: () => COMPILED });
		const out = collect();

		await ops.exec("echo x > /etc/passwd", "/work", { onData: out.onData });

		expect(out.text()).toContain("sandbox denied:");
		expect(out.text()).toContain("/etc/passwd");
	});

	it("adds nothing to the output when there are no violations", async () => {
		const { backend } = recordingBackend();
		const ops = createEnclaveBashOperations({ backend, getCompiled: () => COMPILED });
		const out = collect();
		await ops.exec("true", "/work", { onData: out.onData });
		expect(out.text()).toBe("");
	});

	it("reports violations to the audit callback as well as the agent", async () => {
		const violation: Violation = {
			kind: "network",
			source: "proxy",
			op: "network-outbound",
			host: "x.com",
			backend: "seatbelt",
		};
		const { backend } = recordingBackend({ violations: [violation] });
		const onViolations = vi.fn();
		const ops = createEnclaveBashOperations({ backend, getCompiled: () => COMPILED, onViolations });
		await ops.exec("curl x.com", "/work", { onData: () => {} });
		expect(onViolations).toHaveBeenCalledWith([violation]);
	});

	it("refuses to run before the profile is compiled", async () => {
		// Failing closed here matters: a bug that let commands run before the
		// sandbox was ready would run them unsandboxed.
		const { backend } = recordingBackend();
		const ops = createEnclaveBashOperations({
			backend,
			getCompiled: () => {
				throw new Error("pi-enclave: sandbox is not ready");
			},
		});
		await expect(ops.exec("true", "/work", { onData: () => {} })).rejects.toThrow("not ready");
	});

	it("gives each invocation a distinct correlation id", () => {
		// sandbox-runtime attributes violations by this key and compares only the
		// first 100 characters, so two long commands sharing a prefix would
		// cross-attribute if the command text were used.
		const ids = new Set(Array.from({ length: 100 }, () => nextCommandId()));
		expect(ids.size).toBe(100);
	});
});

describe("BASH_PROMPT_GUIDELINES", () => {
	it("is backend-neutral", () => {
		// An agent taught one platform's vocabulary would not recognise the other's.
		const text = BASH_PROMPT_GUIDELINES.join("\n");
		expect(text).not.toMatch(/seatbelt|bubblewrap|bwrap|sandbox-exec|EPERM|EROFS/i);
	});

	it("warns that a denied read can look like a missing file", () => {
		// True on Linux, where deny-read is a tmpfs overlay. Leaving the agent to
		// discover it costs a retry loop.
		expect(BASH_PROMPT_GUIDELINES.join("\n")).toMatch(/missing file/i);
	});
});

describe("createDevProfile", () => {
	it("makes the workspace and tmpdir writable and nothing else", () => {
		const profile = createDevProfile({ cwd: "/work", tmp: "/tmp" });
		expect(profile.writableRoots).toEqual(["/work", "/tmp"]);
		expect(profile.network).toBe("off");
		expect(profile.mode).toBe("workspace-write");
	});

	it("allows PTYs by default", () => {
		// Seatbelt denies PTYs unless enabled, which breaks vim, less and git
		// without a pager override, and an agent fighting the sandbox looks for
		// workarounds. bwrap does not restrict PTYs at all, so on Linux the field
		// is informational.
		expect(createDevProfile({ cwd: "/work" }).allowPty).toBe(true);
	});

	it("denies reads of pi's own credential store", () => {
		// An agent that can read this can spend the account running it.
		expect(defaultReadDeny("/home/u")).toContain("/home/u/.pi/agent/auth.json");
	});

	it("denies the live credential store wherever pi actually keeps it", () => {
		// pi resolves its agent directory from PI_CODING_AGENT_DIR. With that set,
		// the default path is empty and the real auth.json is elsewhere; denying
		// only the default would leave the live key readable through read, bash
		// or grep while the env allowlist hides the variable that points at it.
		const deny = defaultReadDeny("/home/u", "/srv/pi-agent");
		expect(deny).toContain("/srv/pi-agent/auth.json");
		expect(deny).toContain("/home/u/.pi/agent/auth.json");
	});

	it("follows PI_CODING_AGENT_DIR by default", () => {
		const previous = process.env.PI_CODING_AGENT_DIR;
		process.env.PI_CODING_AGENT_DIR = "/srv/elsewhere";
		try {
			expect(defaultReadDeny("/home/u")).toContain("/srv/elsewhere/auth.json");
		} finally {
			if (previous === undefined) delete process.env.PI_CODING_AGENT_DIR;
			else process.env.PI_CODING_AGENT_DIR = previous;
		}
	});

	it("denies the usual credential locations", () => {
		const deny = defaultReadDeny("/home/u");
		for (const suffix of [".ssh", ".aws", ".gnupg", ".kube", ".docker", ".netrc", ".npmrc"]) {
			expect(deny, suffix).toContain(`/home/u/${suffix}`);
		}
	});
});
