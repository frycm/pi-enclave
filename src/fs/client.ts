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
import { isUnderAny } from "../backend/paths.ts";
import type { CompiledProfile, FsClient, Violation } from "../backend/types.ts";
import { SandboxDenied } from "../backend/types.ts";
import { encodeFrame, FrameDecoder, type FsCall, type FsResponse, PROTOCOL_VERSION } from "./protocol.ts";

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
	/**
	 * Runs before every call, before the helper is (re)started. The backend uses
	 * it to notice that the profile it wrapped the helper under no longer
	 * describes the filesystem -- a deny root that has since appeared -- and to
	 * retire the helper so the next start wraps it afresh.
	 */
	beforeCall?: () => Promise<void>;
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
						if (message.protocol !== PROTOCOL_VERSION) {
							// A helper speaking another version would answer with shapes
							// this side misreads, which is worse than not answering.
							const error = new Error(
								`pi-enclave: the filesystem helper speaks protocol ${message.protocol}, this client speaks ${PROTOCOL_VERSION}`,
							);
							this.failAll(error);
							reject(error);
							child.kill("SIGKILL");
							return;
						}
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

			// A write after the helper has gone surfaces as EPIPE on this stream. With
			// no listener that is an uncaught exception in the pi process -- precisely
			// in the window the restart logic exists for.
			child.stdin.on("error", (error) => {
				this.failAll(error);
			});

			child.on("error", (error) => {
				clearTimeout(timer);
				this.failAll(error);
				reject(error);
			});

			child.on("close", (code) => {
				clearTimeout(timer);
				// A retired helper closing late must not clobber its successor.
				if (this.child !== child) return;
				this.child = undefined;
				this.ready = undefined;
				const error = new Error(`pi-enclave: the filesystem helper exited (code ${code})`);
				if (!this.disposed) this.failAll(error);
				// A helper that dies before its ready frame must fail the start now,
				// not when the ready timeout gets round to it: with three restarts
				// per call that silence was minutes, not seconds.
				reject(error);
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

	/** Send a frame, turning a closed stream into a rejection rather than an event nobody handles. */
	private send(child: ChildProcessWithoutNullStreams, frame: Buffer): void {
		if (child.stdin.destroyed || child.stdin.writableEnded) {
			throw new Error("pi-enclave: the filesystem helper is no longer accepting requests");
		}
		child.stdin.write(frame);
	}

	/**
	 * Retire the running helper without disposing the client: the next call
	 * starts a fresh one. Used when the wrap it was started under is stale.
	 */
	retire(): void {
		const child = this.child;
		this.child = undefined;
		this.ready = undefined;
		this.failAll(new Error("pi-enclave: the filesystem helper was restarted under an updated sandbox"));
		child?.stdin.end();
	}

	private async call(request: FsCall, signal?: AbortSignal): Promise<unknown> {
		if (this.disposed) throw new Error("pi-enclave: the filesystem helper was shut down");
		await this.options.beforeCall?.();
		await this.start();

		const child = this.child;
		if (!child) throw new Error("pi-enclave: the filesystem helper is not running");

		const id = ++this.sequence;
		const timeoutMs = this.options.callTimeoutMs ?? DEFAULT_CALL_TIMEOUT_MS;

		// A search abandoned on this side keeps running on the other unless told
		// otherwise, so abort and timeout both send a cancel for it.
		const cancel = () => {
			try {
				this.send(child, encodeFrame({ op: "cancel", target: id, id: ++this.sequence }));
			} catch {
				// The helper is gone; there is nothing left to cancel.
			}
		};

		const response = await new Promise<FsResponse>((resolve, reject) => {
			const timer = setTimeout(() => {
				this.pending.delete(id);
				cancel();
				reject(new Error(`pi-enclave: ${request.op} timed out after ${timeoutMs}ms`));
			}, timeoutMs);
			const onAbort = () => {
				clearTimeout(timer);
				this.pending.delete(id);
				cancel();
				reject(new Error("Operation aborted"));
			};
			if (signal?.aborted) {
				onAbort();
				return;
			}
			signal?.addEventListener("abort", onAbort, { once: true });
			this.pending.set(id, {
				resolve: (r) => {
					signal?.removeEventListener("abort", onAbort);
					resolve(r);
				},
				reject: (e) => {
					signal?.removeEventListener("abort", onAbort);
					reject(e);
				},
				timer,
			});
			try {
				this.send(child, encodeFrame({ ...request, id }));
			} catch (error) {
				clearTimeout(timer);
				this.pending.delete(id);
				reject(error instanceof Error ? error : new Error(String(error)));
			}
		});

		if (response.ok) {
			this.refuseMaskedSuccess(request, response.resolvedPath);
			return response.result;
		}

		// The helper reports the errno; the profile decides what it means. On Linux
		// an ENOENT under a read-denied root is a denial and anywhere else is a
		// missing file, and only this side knows which.
		// Classify against the path the kernel judged, not the one the caller
		// spelled: a read through a workspace symlink into a denied directory
		// fails on the target. The helper resolved it inside the sandbox; it is
		// evidence for the verdict, and nothing here enforces on it.
		const requested = "path" in request ? request.path : "cwd" in request ? request.cwd : "";
		const path = response.resolvedPath ?? requested;
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

	/**
	 * On bwrap a read-denied directory is an empty tmpfs: `exists` answers true,
	 * `readdir` answers `[]`, `stat` says "directory", and `fd` finds nothing --
	 * each a success that would tell the agent `~/.ssh` is simply empty. The
	 * kernel has already refused; this only refuses to misdescribe it. A path
	 * comparison here never permits anything.
	 */
	private refuseMaskedSuccess(request: FsCall, resolvedPath: string | undefined): void {
		if (!["bwrap", "docker", "podman"].includes(this.options.compiled.backend)) return;
		// A write-access check passing under a deny root is not a masked read --
		// the deny list governs reads, and writes are decided by the roots.
		if (request.op === "access" && request.mode === "write") return;
		const path = resolvedPath ?? ("path" in request ? request.path : "cwd" in request ? request.cwd : undefined);
		if (!path || !isUnderAny(path, this.options.compiled.profile.readDeny)) return;
		const violation: Violation = {
			source: "errno",
			kind: "read",
			op: request.op,
			path,
			backend: this.options.compiled.backend,
			raw: "masked (deny-read tmpfs)",
		};
		this.options.onViolation?.(violation);
		throw new SandboxDenied(violation);
	}

	// -------------------------------------------------------------------------
	// FsClient
	// -------------------------------------------------------------------------

	async readFile(path: string): Promise<Buffer> {
		return Buffer.from((await this.call({ op: "readFile", path })) as string, "base64");
	}

	async head(path: string, bytes: number): Promise<Buffer> {
		return Buffer.from((await this.call({ op: "head", path, bytes })) as string, "base64");
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

	async grep(
		args: readonly string[],
		options: { limit?: number; signal?: AbortSignal; path?: string } = {},
	): Promise<{ stdout: string; exitCode: number | null; limitReached?: boolean; capped?: boolean }> {
		return (await this.call(
			{ op: "grep", args: [...args], limit: options.limit ?? 0, path: options.path ?? "" },
			options.signal,
		)) as {
			stdout: string;
			exitCode: number | null;
			limitReached?: boolean;
			capped?: boolean;
		};
	}
}

function isReady(message: unknown): message is { ready: true; protocol: number } {
	return typeof message === "object" && message !== null && (message as { ready?: boolean }).ready === true;
}

/** The logical operation name `classifyErrno` expects, which distinguishes read from write access. */
function opName(request: FsCall): string {
	if (request.op === "access") return `access:${request.mode}`;
	return request.op;
}
