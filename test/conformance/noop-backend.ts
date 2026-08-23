/**
 * A backend that enforces nothing.
 *
 * This exists to keep the conformance suite honest. It runs commands with a
 * plain `spawn`, no profile, no isolation -- exactly the thing pi-enclave is
 * built to prevent. Every `denied` scenario must fail against it. If one starts
 * passing, that scenario has stopped testing the sandbox and is measuring
 * something incidental instead (a missing binary, a permission the test user
 * never had, a typo that makes a command exit non-zero for the wrong reason).
 *
 * It is test-only and must never be exported from `src/`.
 */
import { spawn } from "node:child_process";
import { constants, promises as fs } from "node:fs";
import type {
	CompiledProfile,
	FsClient,
	Profile,
	RunRequest,
	RunResult,
	SandboxBackend,
} from "../../src/backend/types.ts";

class NoopCompiledProfile implements CompiledProfile {
	readonly backend = "seatbelt" as const;

	constructor(readonly profile: Profile) {}

	describe(): string {
		return "noop: no profile is compiled and nothing is enforced";
	}
}

/** Run a search tool in this process, with no sandbox anywhere near it. */
function run(bin: string, args: string[]): Promise<{ stdout: string; exitCode: number | null }> {
	return new Promise((resolve, reject) => {
		const child = spawn(bin, args, { stdio: ["ignore", "pipe", "pipe"] });
		let stdout = "";
		child.stdout.on("data", (d: Buffer) => {
			stdout += d;
		});
		child.on("error", reject);
		child.on("close", (exitCode) => resolve({ stdout, exitCode }));
	});
}

export class NoopBackend implements SandboxBackend {
	readonly name = "seatbelt" as const;

	async compile(profile: Profile): Promise<CompiledProfile> {
		return new NoopCompiledProfile(profile);
	}

	async run(_compiled: CompiledProfile, request: RunRequest): Promise<RunResult> {
		return new Promise((resolve, reject) => {
			const child = spawn("bash", ["-c", request.command], {
				cwd: request.cwd,
				env: request.env,
				stdio: ["ignore", "pipe", "pipe"],
			});

			child.stdout.on("data", (chunk: Buffer) => request.onData?.(chunk));
			child.stderr.on("data", (chunk: Buffer) => request.onData?.(chunk));

			const timer =
				request.timeout === undefined ? undefined : setTimeout(() => child.kill("SIGKILL"), request.timeout * 1000);

			child.on("error", (error) => {
				if (timer) clearTimeout(timer);
				reject(error);
			});
			child.on("close", (exitCode) => {
				if (timer) clearTimeout(timer);
				// No profile, so no denials are ever observed.
				resolve({ exitCode, violations: [] });
			});
		});
	}

	fs(_compiled: CompiledProfile): FsClient {
		return {
			readFile: (path) => fs.readFile(path),
			writeFile: (path, content) => fs.writeFile(path, content, "utf8"),
			mkdir: async (path) => {
				await fs.mkdir(path, { recursive: true });
			},
			access: (path, mode) => fs.access(path, mode === "write" ? constants.W_OK : constants.R_OK),
			stat: (path) => fs.stat(path),
			readdir: (path) => fs.readdir(path),
			exists: async (path) => {
				try {
					await fs.access(path);
					return true;
				} catch {
					return false;
				}
			},
			// Real searches, unsandboxed, so the search rows can fail here. A stub
			// that returned nothing would pass F6 and F7 against a backend that
			// enforces nothing, which is the exact vacuity the control exists to
			// catch.
			glob: async (pattern, cwd, options) => {
				const args = ["--glob", "--color=never", "--hidden", "--max-results", String(options.limit)];
				if (pattern.includes("/")) args.push("--full-path");
				args.push("--", pattern, cwd);
				const { stdout } = await run("fd", args);
				return stdout.split("\n").filter(Boolean);
			},
			grep: async (args) => run("rg", [...args]),
		};
	}

	async dispose(): Promise<void> {
		// Nothing to release.
	}
}
