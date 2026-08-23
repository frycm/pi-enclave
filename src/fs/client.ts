/**
 * The pi-process half of the filesystem helper.
 *
 * Owns one long-lived helper per compiled profile, multiplexes concurrent
 * requests over its stdio, and turns kernel refusals into {@link SandboxDenied}
 * with a classified violation, so callers see the same thing whichever backend
 * refused and whichever errno it used.
 *
 * The helper is cheap to keep alive -- 40 ms to start, well under a tenth of a
 * millisecond per call on both platforms -- so it is started once and reused,
 * not spawned per operation.
 */
import type { ChildProcessWithoutNullStreams } from "node:child_process";
import { classifyErrno } from "../backend/errno.ts";
import type { CompiledProfile, FsClient, Violation } from "../backend/types.ts";
import { SandboxDenied } from "../backend/types.ts";
import { encodeFrame, FrameDecoder, type FsCall, type FsResponse } from "./protocol.ts";

/** How long a single operation may take before it is abandoned. */
const DEFAULT_CALL_TIMEOUT_MS = 30_000;
/** How long to wait for the helper's ready frame. */
const READY_TIMEOUT_MS = 15_000;
/**
 * Consecutive start failures before the client stops trying.
 *
 * A helper that cannot start will not start on the fourth attempt either, and
 * retrying forever turns one broken session into a spawn loop.
 */
const MAX_RESTARTS = 3;

/** Spawns a helper process under the compiled profile. */
export type HelperSpawner = () => ChildProcessWithoutNullStreams;

interface Pending {
	resolve: (response: FsResponse) => void;
	reject: (error: Error) => void;
	timer: NodeJS.Timeout;
}

export interface FsClientOptions {
	compiled: CompiledProfile;
	spawnHelper: HelperSpawner;
	callTimeoutMs?: number;
	/** Notified for every classified denial, for the audit log and status line. */
	onViolation?: (violation: Violation) => void;
}

export class HelperFsClient implements FsClient {
	private child: ChildProcessWithoutNullStreams | undefined;
	private ready: Promise<void> | undefined;
	private readonly pending = new Map<number, Pending>();
	private sequence = 0;
	private restarts = 0;
	private disposed = false;

	constructor(private readonly options: FsClientOptions) {}

	// -------------------------------------------------------------------------
	// Lifecycle
	// -------------------------------------------------------------------------

	private start(): Promise<void> {
		if (this.ready) return this.ready;

		this.ready = new Promise<void>((resolve, reject) => {
			if (this.restarts >= MAX_RESTARTS) {
				reject(new Error(`pi-enclave: the filesystem helper failed to start ${MAX_RESTARTS} times; giving up`));
				return;
			}
			this.restarts += 1;

			const child = this.options.spawnHelper();
			this.child = child;
			const decoder = new FrameDecoder();

			const timer = setTimeout(() => {
				reject(new Error("pi-enclave: the filesystem helper did not report ready"));
				child.kill("SIGKILL");
			}, READY_TIMEOUT_MS);

			child.stdout.on("data", (chunk: Buffer) => {
				let messages: unknown[];
				try {
					messages = decoder.push(chunk);
				} catch (error) {
					// A desynchronised stream cannot be trusted to answer the right
					// question, so tear it down rather than keep reading.
					clearTimeout(timer);
					this.failAll(error instanceof Error ? error : new Error(String(error)));
					child.kill("SIGKILL");
					return;
				}

				for (const message of messages) {
					if (isReady(message)) {
						clearTimeout(timer);
						// A successful start clears the budget: a crash after hours of work
						// deserves the same three attempts as one at startup.
						this.restarts = 0;
						resolve();
						continue;
					}
					this.settle(message as FsResponse);
				}
			});

			// The helper's stderr is diagnostic only; its answers all arrive on stdout.
			child.stderr.on("data", () => {});

			child.on("error", (error) => {
				clearTimeout(timer);
				this.failAll(error);
				reject(error);
			});

			child.on("close", (code) => {
				clearTimeout(timer);
				this.child = undefined;
				this.ready = undefined;
				if (!this.disposed) {
					this.failAll(new Error(`pi-enclave: the filesystem helper exited (code ${code})`));
				}
			});
		});

		return this.ready;
	}

	/** Reject everything in flight. Callers must never be left waiting on a dead helper. */
	private failAll(error: Error): void {
		for (const [, pending] of this.pending) {
			clearTimeout(pending.timer);
			pending.reject(error);
		}
		this.pending.clear();
	}

	private settle(response: FsResponse): void {
		const pending = this.pending.get(response.id);
		if (!pending) return;
		clearTimeout(pending.timer);
		this.pending.delete(response.id);
		pending.resolve(response);
	}

	async dispose(): Promise<void> {
		this.disposed = true;
		this.failAll(new Error("pi-enclave: the filesystem helper was shut down"));
		// Close stdin rather than signalling: on Linux the helper is PID 1 inside a
		// nested namespace and has no host pid we could address.
		this.child?.stdin.end();
		this.child = undefined;
		this.ready = undefined;
	}

	// -------------------------------------------------------------------------
	// Request plumbing
	// -------------------------------------------------------------------------

	private async call(request: FsCall): Promise<unknown> {
		if (this.disposed) throw new Error("pi-enclave: the filesystem helper was shut down");
		await this.start();

		const child = this.child;
		if (!child) throw new Error("pi-enclave: the filesystem helper is not running");

		const id = ++this.sequence;
		const timeoutMs = this.options.callTimeoutMs ?? DEFAULT_CALL_TIMEOUT_MS;

		const response = await new Promise<FsResponse>((resolve, reject) => {
			const timer = setTimeout(() => {
				this.pending.delete(id);
				reject(new Error(`pi-enclave: ${request.op} timed out after ${timeoutMs}ms`));
			}, timeoutMs);
			this.pending.set(id, { resolve, reject, timer });
			child.stdin.write(encodeFrame({ ...request, id }));
		});

		if (response.ok) return response.result;

		// The helper reports the errno; the profile decides what it means. On Linux
		// an ENOENT under a read-denied root is a denial and anywhere else is a
		// missing file, and only this side knows which.
		const path = "path" in request ? (request as { path: string }).path : "";
		const violation = classifyErrno({
			error: {
				...(response.code ? { code: response.code } : {}),
				...(response.syscall ? { syscall: response.syscall } : {}),
			},
			op: opName(request),
			path,
			profile: this.options.compiled.profile,
			backend: this.options.compiled.backend,
		});

		if (violation) {
			this.options.onViolation?.(violation);
			throw new SandboxDenied(violation);
		}
		throw Object.assign(new Error(response.message), response.code ? { code: response.code } : {});
	}

	// -------------------------------------------------------------------------
	// FsClient
	// -------------------------------------------------------------------------

	async readFile(path: string): Promise<Buffer> {
		return Buffer.from((await this.call({ op: "readFile", path })) as string, "base64");
	}

	async writeFile(path: string, content: string): Promise<void> {
		await this.call({ op: "writeFile", path, content });
	}

	async mkdir(path: string): Promise<void> {
		await this.call({ op: "mkdir", path });
	}

	async access(path: string, mode: "read" | "write"): Promise<void> {
		await this.call({ op: "access", path, mode });
	}

	async stat(path: string): Promise<{ isDirectory: () => boolean }> {
		const result = (await this.call({ op: "stat", path })) as { isDirectory: boolean };
		return { isDirectory: () => result.isDirectory };
	}

	async readdir(path: string): Promise<string[]> {
		return (await this.call({ op: "readdir", path })) as string[];
	}

	async exists(path: string): Promise<boolean> {
		return (await this.call({ op: "exists", path })) as boolean;
	}

	async glob(pattern: string, cwd: string, options: { ignore: string[]; limit: number }): Promise<string[]> {
		return (await this.call({ op: "glob", pattern, cwd, ignore: options.ignore, limit: options.limit })) as string[];
	}

	async grep(args: readonly string[]): Promise<{ stdout: string; exitCode: number | null }> {
		return (await this.call({ op: "grep", args: [...args] })) as { stdout: string; exitCode: number | null };
	}
}

function isReady(message: unknown): boolean {
	return typeof message === "object" && message !== null && (message as { ready?: boolean }).ready === true;
}

/** The logical operation name `classifyErrno` expects, which distinguishes read from write access. */
function opName(request: FsCall): string {
	if (request.op === "access") return `access:${request.mode}`;
	return request.op;
}
