/**
 * pi-enclave-fs: the sandboxed filesystem helper.
 *
 * Runs INSIDE the sandbox under the same compiled profile as `bash`, and
 * performs every file operation the pi tools need. The point is that the
 * `open`, `readdir` and `spawn` calls happen on this side of the boundary, so
 * the kernel decides -- rather than the pi process resolving a path, checking it
 * against a policy, and then opening it, which is a privileged process doing a
 * check with a race window between the check and the syscall.
 *
 * Plain JavaScript on purpose. This is spawned as its own `node` process inside
 * the sandbox, with no TypeScript loader available and no dependency on how pi
 * loaded the extension.
 *
 * It reports raw errnos and never a verdict: only the pi process holds the
 * compiled profile, and on Linux an ENOENT is a denied read or a missing file
 * depending on it.
 */
import { spawn } from "node:child_process";
import {
	accessSync,
	constants,
	lstatSync,
	mkdirSync,
	readdirSync,
	readFileSync,
	readlinkSync,
	realpathSync,
	statSync,
	writeFileSync,
} from "node:fs";
import { basename, dirname, resolve } from "node:path";

const HEADER_BYTES = 4;
const MAX_FRAME_BYTES = 64 * 1024 * 1024;
const PROTOCOL_VERSION = 1;

function writeFrame(message) {
	const payload = Buffer.from(JSON.stringify(message), "utf8");
	const header = Buffer.allocUnsafe(HEADER_BYTES);
	header.writeUInt32BE(payload.length, 0);
	process.stdout.write(Buffer.concat([header, payload]));
}

/**
 * Where to find the search tools.
 *
 * pi downloads `rg` and `fd` on demand into its own directory, so they are often
 * absent from PATH -- and the helper cannot fetch them itself, because it has no
 * network. The pi process therefore resolves them before the sandbox starts and
 * passes the absolute paths in. Falling back to a bare name keeps the helper
 * working when they are simply installed normally.
 */
const TOOL_PATHS = {
	rg: process.env.PI_ENCLAVE_RG || "rg",
	fd: process.env.PI_ENCLAVE_FD || "fd",
};

/** Run a search tool and collect its output. Spawned here so it runs under the profile. */
function runTool(bin, args) {
	return new Promise((resolve) => {
		const child = spawn(bin, args, { stdio: ["ignore", "pipe", "pipe"] });
		let stdout = "";
		let stderr = "";
		child.stdout.on("data", (d) => {
			stdout += d;
		});
		child.stderr.on("data", (d) => {
			stderr += d;
		});
		child.on("error", (error) =>
			resolve({ stdout: "", stderr: String(error.message), exitCode: null, code: error.code }),
		);
		child.on("close", (exitCode) => resolve({ stdout, stderr, exitCode }));
	});
}

async function handle(request) {
	switch (request.op) {
		case "ping":
			return "pong";
		case "readFile":
			// Base64 so arbitrary bytes survive a JSON frame.
			return readFileSync(request.path).toString("base64");
		case "writeFile":
			writeFileSync(request.path, request.content, "utf8");
			return null;
		case "mkdir":
			mkdirSync(request.path, { recursive: true });
			return null;
		case "access":
			accessSync(request.path, request.mode === "write" ? constants.R_OK | constants.W_OK : constants.R_OK);
			return null;
		case "stat": {
			const stats = statSync(request.path);
			return { isDirectory: stats.isDirectory(), size: stats.size, mtimeMs: stats.mtimeMs };
		}
		case "readdir":
			return readdirSync(request.path);
		case "exists":
			try {
				accessSync(request.path, constants.F_OK);
				return true;
			} catch {
				return false;
			}
		case "glob": {
			// A deliberately conservative flag set. `--no-require-git`, which pi
			// passes, does not exist in fd 8.x -- and an unknown flag makes fd exit
			// 2 with an empty stdout, which is indistinguishable from "no files
			// matched" unless the exit code is checked. Stick to flags every
			// supported fd understands.
			const args = ["--glob", "--color=never", "--hidden"];
			for (const pattern of request.ignore ?? []) args.push("--exclude", pattern);
			args.push("--max-results", String(request.limit ?? 1000), request.pattern, request.cwd);
			const result = await runTool(TOOL_PATHS.fd, args);
			if (result.code === "ENOENT")
				throw Object.assign(new Error(`fd is not available (looked for ${TOOL_PATHS.fd})`), { code: "ENOENT" });
			// fd exits 1 when nothing matched, which is a real answer. Anything
			// higher is a failure, and reporting it as an empty result would tell
			// the agent the files do not exist.
			if (result.exitCode !== null && result.exitCode > 1) {
				throw Object.assign(new Error(`fd failed (exit ${result.exitCode}): ${result.stderr.trim().slice(0, 200)}`), {
					code: "EIO",
				});
			}
			return result.stdout.split("\n").filter(Boolean);
		}
		case "grep": {
			const result = await runTool(TOOL_PATHS.rg, request.args);
			if (result.code === "ENOENT")
				throw Object.assign(new Error(`rg is not available (looked for ${TOOL_PATHS.rg})`), { code: "ENOENT" });
			// Same reasoning as glob: rg exits 1 for "no matches", and anything
			// higher is a failure that must not be reported as an empty search.
			if (result.exitCode !== null && result.exitCode > 1) {
				throw Object.assign(new Error(`rg failed (exit ${result.exitCode}): ${result.stderr.trim().slice(0, 200)}`), {
					code: "EIO",
				});
			}
			return { stdout: result.stdout, stderr: result.stderr, exitCode: result.exitCode };
		}
		default:
			throw Object.assign(new Error(`unknown operation: ${request.op}`), { code: "EINVAL" });
	}
}

/**
 * Where a failed operation actually landed.
 *
 * A denied read reached through a symlink inside the workspace fails with the
 * caller's path, which is not under any deny root, so the pi process cannot
 * classify it. Resolving here -- on this side of the boundary, with the same
 * view of the filesystem the failing syscall had -- gives it the path the
 * kernel judged. `realpath` alone is not enough: on Linux a denied directory is
 * an empty tmpfs, so the final components do not exist and realpath fails.
 * Resolve the deepest existing ancestor, follow a dangling link at the
 * frontier, and re-join what is left.
 */
function resolveForReport(path) {
	let current = path;
	let remainder = "";
	for (let depth = 0; depth < 64; depth++) {
		try {
			return remainder ? resolve(realpathSync(current), remainder) : realpathSync(current);
		} catch {
			// Fall through to the ancestor or the link target.
		}
		try {
			if (lstatSync(current).isSymbolicLink()) {
				current = resolve(dirname(current), readlinkSync(current));
				continue;
			}
		} catch {
			// Absent: step up.
		}
		const parent = dirname(current);
		if (parent === current) return path;
		remainder = remainder ? `${basename(current)}/${remainder}` : basename(current);
		current = parent;
	}
	return path;
}

let buffer = Buffer.alloc(0);

process.stdin.on("data", (chunk) => {
	buffer = buffer.length === 0 ? chunk : Buffer.concat([buffer, chunk]);

	while (buffer.length >= HEADER_BYTES) {
		const length = buffer.readUInt32BE(0);
		if (length > MAX_FRAME_BYTES) {
			process.stderr.write(`pi-enclave-fs: oversized frame (${length} bytes)\n`);
			process.exit(1);
		}
		if (buffer.length < HEADER_BYTES + length) break;

		const payload = buffer.subarray(HEADER_BYTES, HEADER_BYTES + length);
		buffer = buffer.subarray(HEADER_BYTES + length);

		let request;
		try {
			request = JSON.parse(payload.toString("utf8"));
		} catch (error) {
			process.stderr.write(`pi-enclave-fs: unparseable frame: ${error.message}\n`);
			continue;
		}

		// Requests are served concurrently and answered by id, so one slow search
		// does not stall every read behind it.
		void handle(request).then(
			(result) => writeFrame({ id: request.id, ok: true, result }),
			(error) =>
				writeFrame({
					id: request.id,
					ok: false,
					code: error?.code,
					syscall: error?.syscall,
					message: String(error?.message ?? error),
					...(typeof request.path === "string" ? { resolvedPath: resolveForReport(request.path) } : {}),
				}),
		);
	}
});

// Exiting when stdin closes is what makes the helper die with its parent even
// where the backend cannot address it by pid -- on Linux it is PID 1 inside a
// nested namespace and invisible to the host.
process.stdin.on("end", () => process.exit(0));

writeFrame({ ready: true, pid: process.pid, protocol: PROTOCOL_VERSION });
