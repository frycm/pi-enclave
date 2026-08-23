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
	closeSync,
	constants,
	lstatSync,
	mkdirSync,
	openSync,
	readdirSync,
	readFileSync,
	readlinkSync,
	readSync,
	realpathSync,
	statSync,
	writeFileSync,
} from "node:fs";
import { basename, dirname, resolve } from "node:path";

const HEADER_BYTES = 4;
const MAX_FRAME_BYTES = 64 * 1024 * 1024;
const PROTOCOL_VERSION = 2;
/**
 * The most a single read returns. Base64 inflates by a third, and a frame the
 * client must reject takes down the helper and every operation in flight, so
 * the bound is applied here, before encoding, and reported as an error the
 * caller can act on rather than a crash nobody can.
 */
const MAX_READ_BYTES = 32 * 1024 * 1024;
/**
 * The most output -- stdout and stderr together -- a single grep or glob may
 * accumulate before the tool is stopped. One budget for both: a walk over a
 * tree of unreadable paths emits one diagnostic per path on stderr, which is
 * the same unbounded growth as matches on stdout.
 */
const MAX_SEARCH_OUTPUT_BYTES = 16 * 1024 * 1024;

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

/** Search tools still running, by request id, so a cancel can reach them. */
const running = new Map();

/**
 * Run a search tool and collect its output. Spawned here so it runs under the
 * profile.
 *
 * Bounded in two ways, because a search over `/` would otherwise accumulate
 * the whole filesystem in memory before the client ever saw a match limit:
 * `stopAfterLines(line)` is consulted per output line and kills the tool once
 * it returns true, and the output is capped in bytes regardless. Both are
 * reported in the result so the caller can say so.
 */
function runTool(requestId, bin, args, stopAfterLines) {
	return new Promise((resolve) => {
		const child = spawn(bin, args, { stdio: ["ignore", "pipe", "pipe"] });
		running.set(requestId, child);
		let stdout = "";
		let stderr = "";
		let partial = "";
		let stopped = false;
		let capped = false;
		const stop = (why) => {
			if (stopped) return;
			stopped = true;
			if (why === "cap") capped = true;
			child.kill("SIGKILL");
		};
		child.stdout.on("data", (d) => {
			if (stopped) return;
			stdout += d;
			if (stdout.length + stderr.length > MAX_SEARCH_OUTPUT_BYTES) {
				stop("cap");
				return;
			}
			if (!stopAfterLines) return;
			partial += d;
			const lines = partial.split("\n");
			partial = lines.pop() ?? "";
			for (const line of lines) {
				if (stopAfterLines(line)) {
					stop("limit");
					return;
				}
			}
		});
		child.stderr.on("data", (d) => {
			if (stopped) return;
			stderr += d;
			if (stdout.length + stderr.length > MAX_SEARCH_OUTPUT_BYTES) stop("cap");
		});
		child.on("error", (error) => {
			running.delete(requestId);
			resolve({ stdout: "", stderr: String(error.message), exitCode: null, code: error.code });
		});
		child.on("close", (exitCode) => {
			running.delete(requestId);
			// A tool we stopped ourselves exited on our signal, not on an error.
			resolve({ stdout, stderr, exitCode: stopped ? 0 : exitCode, stopped, capped });
		});
	});
}

async function handle(request) {
	switch (request.op) {
		case "ping":
			return "pong";
		case "readFile": {
			const size = statSync(request.path).size;
			if (size > MAX_READ_BYTES) {
				throw Object.assign(
					new Error(`${request.path} is ${size} bytes; the sandboxed read tool returns at most ${MAX_READ_BYTES}`),
					{ code: "EFBIG" },
				);
			}
			// Base64 so arbitrary bytes survive a JSON frame.
			return readFileSync(request.path).toString("base64");
		}
		case "head": {
			// A bounded read from the start of the file, for image sniffing: the
			// whole point is not to pay for a full read (and not to exceed the
			// frame) just to learn a file is a PNG.
			const fd = openSync(request.path, "r");
			try {
				const buffer = Buffer.alloc(Math.min(request.bytes, MAX_READ_BYTES));
				const read = readSync(fd, buffer, 0, buffer.length, 0);
				return buffer.subarray(0, read).toString("base64");
			} finally {
				closeSync(fd);
			}
		}
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
			} catch (error) {
				// Only "not there" is a false. A permission error is the answer to a
				// different question, and swallowing it here would turn a denied
				// directory into "Path not found" before the client could classify.
				if (error?.code === "ENOENT" || error?.code === "ENOTDIR") return false;
				throw error;
			}
		case "cancel": {
			const child = running.get(request.target);
			if (child) child.kill("SIGKILL");
			return null;
		}
		case "glob": {
			// A deliberately conservative flag set. `--no-require-git`, which pi
			// passes, does not exist in fd 8.x -- and an unknown flag makes fd exit
			// 2 with an empty stdout, which is indistinguishable from "no files
			// matched" unless the exit code is checked. Stick to flags every
			// supported fd understands.
			const args = ["--glob", "--color=never", "--hidden"];
			for (const pattern of request.ignore ?? []) args.push("--exclude", pattern);
			args.push("--max-results", String(request.limit ?? 1000));
			// fd --glob matches the basename unless --full-path is set, and in
			// --full-path mode a relative pattern like `src/**/*.spec.ts` needs a
			// leading `**/` to match anything. Same normalisation as pi's own tool,
			// so the patterns its description advertises keep working here.
			// Same reasoning as grep: fd's "Operation not permitted" is prose.
			accessSync(request.cwd, constants.R_OK);
			let pattern = request.pattern;
			if (pattern.includes("/")) {
				args.push("--full-path");
				if (!pattern.startsWith("/") && !pattern.startsWith("**/") && pattern !== "**") pattern = `**/${pattern}`;
			}
			args.push("--", pattern, request.cwd);
			const result = await runTool(request.id, TOOL_PATHS.fd, args);
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
			// rg reports a refused search root as "exit 2" with the errno in prose,
			// which nothing downstream can classify. Ask the kernel directly first
			// -- on this side of the boundary, so it is the same answer rg got --
			// and let a refusal travel as the errno it is.
			accessSync(request.path, constants.R_OK);
			// Stop rg at the match limit rather than buffering everything it would
			// ever print; `--json` emits one event per line, so matches can be
			// counted as they arrive.
			let matches = 0;
			const limit = request.limit > 0 ? request.limit : Infinity;
			const result = await runTool(request.id, TOOL_PATHS.rg, request.args, (line) =>
				line.includes('"type":"match"') ? ++matches >= limit : false,
			);
			if (result.code === "ENOENT")
				throw Object.assign(new Error(`rg is not available (looked for ${TOOL_PATHS.rg})`), { code: "ENOENT" });
			// Same reasoning as glob: rg exits 1 for "no matches", and anything
			// higher is a failure that must not be reported as an empty search.
			if (result.exitCode !== null && result.exitCode > 1) {
				throw Object.assign(new Error(`rg failed (exit ${result.exitCode}): ${result.stderr.trim().slice(0, 200)}`), {
					code: "EIO",
				});
			}
			return {
				stdout: result.stdout,
				stderr: result.stderr,
				exitCode: result.exitCode,
				limitReached: Boolean(result.stopped && !result.capped),
				capped: Boolean(result.capped),
			};
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

/**
 * Operations whose success on bwrap may be the mask talking, not the real
 * file: a denied directory is an empty tmpfs, a denied *file* is a read-only
 * bind of /dev/null, so reads come back empty and access checks pass.
 */
const MASKABLE = new Set(["exists", "readdir", "stat", "glob", "grep", "readFile", "head", "access"]);

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
			(result) =>
				writeFrame({
					id: request.id,
					ok: true,
					result,
					// For the operations a masking tmpfs can answer "successfully" --
					// an empty listing of a denied directory -- the client needs to
					// know where the answer came from to say what it really means.
					...(MASKABLE.has(request.op) && typeof (request.path ?? request.cwd) === "string"
						? { resolvedPath: resolveForReport(request.path ?? request.cwd) }
						: {}),
				}),
			(error) =>
				writeFrame({
					id: request.id,
					ok: false,
					code: error?.code,
					syscall: error?.syscall,
					message: String(error?.message ?? error),
					...(typeof (request.path ?? request.cwd) === "string"
						? { resolvedPath: resolveForReport(request.path ?? request.cwd) }
						: {}),
				}),
		);
	}
});

// Exiting when stdin closes is what makes the helper die with its parent even
// where the backend cannot address it by pid -- on Linux it is PID 1 inside a
// nested namespace and invisible to the host.
process.stdin.on("end", () => process.exit(0));

writeFrame({ ready: true, pid: process.pid, protocol: PROTOCOL_VERSION });
