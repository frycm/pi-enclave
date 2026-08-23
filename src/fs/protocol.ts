/**
 * The wire format between the pi process and the sandboxed filesystem helper.
 *
 * Length-prefixed rather than newline-delimited: file contents and search
 * results contain newlines, and a framing that can be confused by its own
 * payload is a framing that will eventually desynchronise mid-session and
 * return one file's bytes in answer to another file's request.
 *
 * Each frame is a 4-byte big-endian length followed by that many bytes of UTF-8
 * JSON. Binary payloads (file contents) travel base64-encoded inside the JSON.
 * That costs a third more bytes on reads, which is the right trade for a single
 * uniform frame type: the alternative is a second binary frame kind whose
 * desynchronisation failure mode is exactly what this format exists to avoid.
 */

export const HEADER_BYTES = 4;

/**
 * Refuse frames larger than this rather than allocating whatever a length
 * header claims. The helper is inside the sandbox and is not trusted to be
 * well-behaved -- a corrupted or hostile length must not become an allocation.
 */
export const MAX_FRAME_BYTES = 64 * 1024 * 1024;

// ---------------------------------------------------------------------------
// Messages
// ---------------------------------------------------------------------------

/**
 * A call without its correlation id.
 *
 * Defined separately from {@link FsRequest} because `Omit` over a union
 * collapses to the properties every member shares -- which would silently erase
 * `path`, `mode` and the rest from the type the client builds.
 */
export type FsCall =
	| { op: "readFile"; path: string }
	| { op: "writeFile"; path: string; content: string }
	| { op: "mkdir"; path: string }
	| { op: "access"; path: string; mode: "read" | "write" }
	| { op: "stat"; path: string }
	| { op: "readdir"; path: string }
	| { op: "exists"; path: string }
	| { op: "glob"; pattern: string; cwd: string; ignore: string[]; limit: number }
	| { op: "grep"; args: string[] }
	| { op: "ping" };

export type FsRequest = FsCall & { id: number };

/**
 * A failure carries the raw errno, never a verdict.
 *
 * The helper knows what the kernel said; only the pi process knows the compiled
 * profile, and on Linux an `ENOENT` is a denied read or a missing file depending
 * on it. Classifying in the helper would put that decision on the wrong side of
 * the boundary and duplicate the policy.
 */
export interface FsFailure {
	id: number;
	ok: false;
	code?: string;
	syscall?: string;
	message: string;
}

export interface FsSuccess {
	id: number;
	ok: true;
	/** Base64 for `readFile`; otherwise a JSON-representable result. */
	result?: unknown;
}

export type FsResponse = FsSuccess | FsFailure;

/** The helper's first frame, before any response. */
export interface FsReady {
	ready: true;
	pid: number;
	protocol: number;
}

/** Bumped whenever the message shapes change incompatibly. */
export const PROTOCOL_VERSION = 1;

// ---------------------------------------------------------------------------
// Framing
// ---------------------------------------------------------------------------

export function encodeFrame(message: unknown): Buffer {
	const payload = Buffer.from(JSON.stringify(message), "utf8");
	if (payload.length > MAX_FRAME_BYTES) {
		throw new Error(`pi-enclave: frame of ${payload.length} bytes exceeds the ${MAX_FRAME_BYTES}-byte limit`);
	}
	const header = Buffer.allocUnsafe(HEADER_BYTES);
	header.writeUInt32BE(payload.length, 0);
	return Buffer.concat([header, payload]);
}

/**
 * Incremental frame reader.
 *
 * stdio delivers arbitrary chunk boundaries, so a frame may arrive split across
 * many reads or several frames may arrive in one. Anything that assumed one
 * chunk equals one message would work in every test and fail on the first large
 * file.
 */
export class FrameDecoder {
	private buffer: Buffer = Buffer.alloc(0);

	/** Feed bytes; returns every complete message they finished. */
	push(chunk: Buffer): unknown[] {
		this.buffer = this.buffer.length === 0 ? chunk : Buffer.concat([this.buffer, chunk]);
		const messages: unknown[] = [];

		while (this.buffer.length >= HEADER_BYTES) {
			const length = this.buffer.readUInt32BE(0);
			if (length > MAX_FRAME_BYTES) {
				throw new Error(`pi-enclave: frame header claims ${length} bytes, above the ${MAX_FRAME_BYTES} limit`);
			}
			if (this.buffer.length < HEADER_BYTES + length) break;

			const payload = this.buffer.subarray(HEADER_BYTES, HEADER_BYTES + length);
			this.buffer = this.buffer.subarray(HEADER_BYTES + length);
			messages.push(JSON.parse(payload.toString("utf8")));
		}

		return messages;
	}

	/** Bytes held but not yet forming a complete frame. */
	get pending(): number {
		return this.buffer.length;
	}
}
