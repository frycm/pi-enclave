import { describe, expect, it } from "vitest";
import { checkUnixSocketBlocking, interpretUnixSocketProbe } from "../../src/backend/self-test.ts";
import type { CompiledProfile, RunRequest, SandboxBackend } from "../../src/backend/types.ts";

const compiled: CompiledProfile = {
	backend: "bwrap",
	profile: { mode: "workspace-write", writableRoots: ["/work"], readDeny: [], network: "off", allowPty: true },
	describe: () => "fake",
};

/** A backend that replays a fixed transcript, recording what it was asked to run. */
function scripted(output: string, exitCode: number | null = 0): Pick<SandboxBackend, "run"> & { seen: RunRequest[] } {
	const seen: RunRequest[] = [];
	return {
		seen,
		run: async (_compiled, request) => {
			seen.push(request);
			request.onData?.(Buffer.from(output));
			return { exitCode, violations: [] };
		},
	};
}

describe("Unix-socket self-test (#34)", () => {
	it("passes only when socket(AF_UNIX) itself is refused", () => {
		expect(interpretUnixSocketProbe(0, "PI-ENCLAVE-UNIX-SOCKET:EPERM\n").ok).toBe(true);
		expect(interpretUnixSocketProbe(0, "PI-ENCLAVE-UNIX-SOCKET:EACCES\n").ok).toBe(true);
	});

	it("fails when a socket could be created, which is what ENOENT on the missing path means", () => {
		const result = interpretUnixSocketProbe(0, "PI-ENCLAVE-UNIX-SOCKET:ENOENT\n");
		expect(result.ok).toBe(false);
		expect(result.detail).toContain("seccomp filter is not in force");
		expect(interpretUnixSocketProbe(0, "PI-ENCLAVE-UNIX-SOCKET:CONNECTED\n").ok).toBe(false);
		expect(interpretUnixSocketProbe(0, "PI-ENCLAVE-UNIX-SOCKET:ECONNREFUSED\n").ok).toBe(false);
	});

	it("fails closed when the probe gives no answer", () => {
		expect(interpretUnixSocketProbe(null, "").ok).toBe(false);
		expect(interpretUnixSocketProbe(127, "bash: node: command not found\n").detail).toContain("no answer");
		// The marker must start a line: an echo of the script source is not a verdict.
		expect(interpretUnixSocketProbe(1, 'SyntaxError near "PI-ENCLAVE-UNIX-SOCKET:EPERM"').ok).toBe(false);
	});

	it("runs the probe through backend.run with the given cwd and environment", async () => {
		const backend = scripted("PI-ENCLAVE-UNIX-SOCKET:EPERM\n");
		const result = await checkUnixSocketBlocking(backend, compiled, {
			cwd: "/work",
			env: { PATH: "/usr/bin" },
			nodePath: "/opt/node's bin/node",
		});
		expect(result.ok).toBe(true);
		expect(backend.seen).toHaveLength(1);
		expect(backend.seen[0]).toMatchObject({ cwd: "/work", env: { PATH: "/usr/bin" } });
		expect(backend.seen[0]?.command).toContain(`'/opt/node'\\''s bin/node' -e `);
		expect(backend.seen[0]?.timeout).toBeGreaterThan(0);
	});

	it("fails closed when the backend refuses to run the probe", async () => {
		const result = await checkUnixSocketBlocking(
			{
				run: async () => {
					throw new Error("bwrap: setting up uid map: Permission denied");
				},
			},
			compiled,
			{ cwd: "/work", env: {} },
		);
		expect(result.ok).toBe(false);
		expect(result.detail).toContain("could not run");
	});
});
