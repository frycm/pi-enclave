/**
 * The sandboxed read must still know an image when it sees one.
 *
 * pi's read tool does not sniff the buffer when `detectImageMimeType` is
 * absent; it decodes the bytes as text. So the operations object supplies one
 * that fetches the magic bytes through the helper and judges them with pi's
 * own detector, loaded from the installed package so its rules cannot drift
 * from the built-in tool's.
 */
import { describe, expect, it } from "vitest";
import { createReadOperations } from "../../src/tools/file-ops.ts";
import { detectImageMimeType, IMAGE_SNIFF_BYTES } from "../../src/tools/image-mime.ts";

const PNG = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0, 13, 0x49, 0x48, 0x44, 0x52]);
const JPEG = Buffer.from([0xff, 0xd8, 0xff, 0xe0, 0, 0x10, 0x4a, 0x46]);

describe("detectImageMimeType", () => {
	it("uses pi's rules on the leading bytes", async () => {
		expect(await detectImageMimeType(PNG)).toBe("image/png");
		expect(await detectImageMimeType(JPEG)).toBe("image/jpeg");
		expect(await detectImageMimeType(Buffer.from("plain text"))).toBeNull();
	});

	it("asks the helper for the head, never for the whole file", async () => {
		const asked: Array<{ path: string; bytes: number }> = [];
		const ops = createReadOperations(
			() =>
				({
					head: async (path: string, bytes: number) => {
						asked.push({ path, bytes });
						return PNG;
					},
					readFile: async () => {
						throw new Error("readFile must not be used to sniff a type");
					},
				}) as never,
		);
		expect(await ops.detectImageMimeType("/w/pic.png")).toBe("image/png");
		expect(asked).toEqual([{ path: "/w/pic.png", bytes: IMAGE_SNIFF_BYTES }]);
	});
});
