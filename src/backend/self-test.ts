/**
 * Per-host checks run inside a freshly compiled sandbox.
 *
 * The conformance suite proves a backend enforces its boundary on the hosts a
 * developer ran it on. These checks prove one property on the host the session
 * actually starts on, through the same `run()` path every agent command takes,
 * so a host that lost a piece of the sandbox (or a sandbox-runtime release that
 * changed behaviour) refuses to start instead of running with a thinner
 * boundary than the status line describes.
 */
import type { ChildEnv, CompiledProfile, SandboxBackend } from "./types.ts";

/** POSIX single quoting. Local rather than imported from `srt.ts`, which imports this module. */
function shellQuote(value: string): string {
	return `'${value.replace(/'/g, `'\\''`)}'`;
}

/** Printed by the probe script, so unrelated output can never be mistaken for a verdict. */
const MARKER = "PI-ENCLAVE-UNIX-SOCKET:";

/**
 * Errors that mean `socket(AF_UNIX, ...)` itself was refused. sandbox-runtime's
 * filter returns EPERM; EACCES is accepted as the same refusal from an LSM.
 */
const REFUSED = new Set(["EPERM", "EACCES"]);

/**
 * Node, asked to connect to a Unix socket under a directory that does not
 * exist. libuv creates the socket before it connects, so the error says which
 * step failed: EPERM is the seccomp filter refusing the socket, ENOENT means a
 * socket was created and only the path was missing. The path is never created
 * and nothing listens anywhere, so the probe has no side effects.
 */
const PROBE_SCRIPT = [
	`const s = require("net").connect("/nonexistent-pi-enclave-self-test/probe.sock");`,
	`s.on("error", (e) => { console.log(${JSON.stringify(MARKER)} + (e.code || "UNKNOWN")); process.exit(0); });`,
	`s.on("connect", () => { console.log(${JSON.stringify(MARKER)} + "CONNECTED"); process.exit(0); });`,
].join(" ");

export interface SelfTestResult {
	ok: boolean;
	detail: string;
}

/**
 * Decide from the probe's output whether Unix sockets were blocked.
 *
 * Anything other than an explicit refusal fails: a missing marker, a timeout or
 * an unexpected code is a probe that did not answer, and an unanswered
 * question is not a pass.
 */
export function interpretUnixSocketProbe(exitCode: number | null, output: string): SelfTestResult {
	const line = output
		.split("\n")
		.map((entry) => entry.trim())
		.find((entry) => entry.startsWith(MARKER));
	if (line === undefined) {
		const excerpt = output.trim().split("\n")[0]?.slice(0, 160) ?? "";
		return {
			ok: false,
			detail: `the Unix-socket self-test gave no answer (exit ${exitCode ?? "signal"}${excerpt ? `: ${excerpt}` : ""})`,
		};
	}
	const code = line.slice(MARKER.length);
	if (REFUSED.has(code)) {
		return { ok: true, detail: `socket(AF_UNIX) is refused inside the sandbox (${code})` };
	}
	return {
		ok: false,
		detail:
			`a sandboxed process could create a Unix socket (${code}); the seccomp filter is not in force, ` +
			"so the session bus, container engine sockets and agent sockets would be reachable",
	};
}

/**
 * Inside the compiled sandbox, try to create an `AF_UNIX` socket and require
 * the attempt to be refused.
 *
 * Runs through `backend.run()`, so it exercises exactly the wrapper, filter and
 * environment an agent command gets. Uses the Node binary running pi, which the
 * sandboxed filesystem helper already depends on being readable.
 */
export async function checkUnixSocketBlocking(
	backend: Pick<SandboxBackend, "run">,
	compiled: CompiledProfile,
	options: { cwd: string; env: ChildEnv; nodePath?: string; timeoutSeconds?: number },
): Promise<SelfTestResult> {
	const node = options.nodePath ?? process.execPath;
	let output = "";
	try {
		const result = await backend.run(compiled, {
			command: `exec ${shellQuote(node)} -e ${shellQuote(PROBE_SCRIPT)}`,
			cwd: options.cwd,
			env: options.env,
			commandId: "enclave-self-test-unix-socket",
			timeout: options.timeoutSeconds ?? 15,
			onData: (chunk) => {
				if (output.length < 8192) output += chunk.toString("utf8");
			},
		});
		return interpretUnixSocketProbe(result.exitCode, output);
	} catch (error) {
		return { ok: false, detail: `the Unix-socket self-test could not run: ${(error as Error).message}` };
	}
}
