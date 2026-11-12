import { describe, expect, it, vi } from "vitest";
import { encodeFrame, FrameDecoder, HEADER_BYTES, MAX_FRAME_BYTES } from "../../src/fs/protocol.ts";

describe("frame encoding", () => {
	it("prefixes the payload with its big-endian length", () => {
		const frame = encodeFrame({ id: 1, op: "ping" });
		expect(frame.readUInt32BE(0)).toBe(frame.length - HEADER_BYTES);
	});

	it("refuses to encode an oversized frame rather than emitting a bad header", () => {
		const huge = { id: 1, op: "writeFile", content: "x".repeat(MAX_FRAME_BYTES + 10) };
		expect(() => encodeFrame(huge)).toThrow(/exceeds/);
	});
});

describe("FrameDecoder", () => {
	it("round-trips a message", () => {
		const decoder = new FrameDecoder();
		expect(decoder.push(encodeFrame({ id: 7, ok: true, result: "x" }))).toEqual([{ id: 7, ok: true, result: "x" }]);
	});

	it("reassembles a frame split across many chunks", () => {
		// stdio picks its own boundaries. Anything assuming one chunk is one
		// message works in tests and fails on the first large file.
		const frame = encodeFrame({ id: 1, ok: true, result: "y".repeat(5000) });
		const decoder = new FrameDecoder();
		const out: unknown[] = [];
		for (let i = 0; i < frame.length; i += 137) {
			out.push(...decoder.push(frame.subarray(i, Math.min(i + 137, frame.length))));
		}
		expect(out).toHaveLength(1);
		expect((out[0] as { result: string }).result).toHaveLength(5000);
	});

	it("returns every message when several arrive in one chunk", () => {
		const decoder = new FrameDecoder();
		const chunk = Buffer.concat([encodeFrame({ id: 1 }), encodeFrame({ id: 2 }), encodeFrame({ id: 3 })]);
		expect(decoder.push(chunk).map((m) => (m as { id: number }).id)).toEqual([1, 2, 3]);
	});

	it("holds a partial frame without emitting anything", () => {
		const decoder = new FrameDecoder();
		const frame = encodeFrame({ id: 1, result: "hello" });
		expect(decoder.push(frame.subarray(0, 6))).toEqual([]);
		expect(decoder.pending).toBe(6);
		expect(decoder.push(frame.subarray(6))).toHaveLength(1);
		expect(decoder.pending).toBe(0);
	});

	it("survives payloads containing newlines and braces", () => {
		// The reason this framing is length-prefixed rather than line-delimited:
		// file contents and search output contain both.
		const nasty = { id: 1, ok: true, result: 'line1\n{"id":999}\nline3\n' };
		const decoder = new FrameDecoder();
		expect(decoder.push(encodeFrame(nasty))).toEqual([nasty]);
	});

	it("rejects a header claiming more than the limit instead of allocating it", () => {
		// The helper runs inside the sandbox and is not trusted to be well-behaved.
		// A hostile or corrupted length must not become an allocation.
		const decoder = new FrameDecoder();
		const header = Buffer.allocUnsafe(HEADER_BYTES);
		header.writeUInt32BE(0xffffffff, 0);
		expect(() => decoder.push(header)).toThrow(/above the/);
	});

	it("preserves binary content through base64 round-trip", () => {
		const bytes = Buffer.from([0, 1, 2, 250, 251, 255, 10, 13]);
		const decoder = new FrameDecoder();
		const [message] = decoder.push(encodeFrame({ id: 1, ok: true, result: bytes.toString("base64") }));
		const back = Buffer.from((message as { result: string }).result, "base64");
		expect(back.equals(bytes)).toBe(true);
	});

	it("copies a frame split across many chunks once, not once per chunk", () => {
		// Joining on every chunk made a 31 MB frame cost seconds to decode.
		const frame = encodeFrame({ id: 1, ok: true, result: "z".repeat(1_000_000) });
		const decoder = new FrameDecoder();
		const concat = vi.spyOn(Buffer, "concat");
		const out: unknown[] = [];
		try {
			for (let i = 0; i < frame.length; i += 4096) out.push(...decoder.push(frame.subarray(i, i + 4096)));
			const copied = concat.mock.results.reduce((sum, r) => sum + (r.value as Buffer).length, 0);
			expect(copied).toBeLessThanOrEqual(frame.length);
		} finally {
			concat.mockRestore();
		}
		expect(out).toHaveLength(1);
		expect((out[0] as { result: string }).result).toHaveLength(1_000_000);
		expect(decoder.pending).toBe(0);
	});

	it("decodes frames fed one byte at a time, headers included", () => {
		const frames = Buffer.concat([
			encodeFrame({ id: 1, result: "a" }),
			encodeFrame({ id: 2, result: "" }),
			encodeFrame({ id: 3 }),
		]);
		const decoder = new FrameDecoder();
		const out: unknown[] = [];
		for (let i = 0; i < frames.length; i++) {
			out.push(...decoder.push(frames.subarray(i, i + 1)));
			if (i === 2) expect(decoder.pending).toBe(3);
		}
		expect(out).toEqual([{ id: 1, result: "a" }, { id: 2, result: "" }, { id: 3 }]);
		expect(decoder.pending).toBe(0);
	});

	it("keeps the bytes of the next frame that arrive with the end of this one", () => {
		const a = encodeFrame({ id: 1, result: "first" });
		const b = encodeFrame({ id: 2, result: "second" });
		const decoder = new FrameDecoder();
		expect(decoder.push(a.subarray(0, 5))).toEqual([]);
		expect(decoder.push(Buffer.concat([a.subarray(5), b.subarray(0, 2)]))).toEqual([{ id: 1, result: "first" }]);
		expect(decoder.pending).toBe(2);
		expect(decoder.push(b.subarray(2))).toEqual([{ id: 2, result: "second" }]);
	});
});
