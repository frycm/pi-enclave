/**
 * Image detection for the sandboxed `read`, without reopening the file.
 *
 * pi's read tool asks `operations.detectImageMimeType` before deciding whether
 * a file is an attachment or text. Leaving it undefined does not fall back to
 * sniffing the buffer -- on the pinned pi it sets `mimeType` to undefined and
 * decodes the bytes as UTF-8 -- so every image read through the helper came
 * back as garbage text while the inherited description still advertised
 * image support.
 *
 * The detector itself is pi's own, loaded from the installed package by file
 * URL: `detectSupportedImageMimeType(buffer)` exists but sits behind a
 * subpath the package's `exports` does not expose. Loading it by path keeps
 * the rules byte-identical to the built-in tool (animated PNGs and lossless
 * JPEGs are deliberately *not* images there) instead of a copy that drifts.
 * The drift test pins the module's hash so a pi bump that changes it fails
 * loudly rather than quietly.
 *
 * The bytes come from the helper, so the `open` still happens inside the
 * sandbox; this side only looks at them.
 */
import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

/** How many leading bytes pi's detector wants. Mirrors IMAGE_TYPE_SNIFF_BYTES. */
export const IMAGE_SNIFF_BYTES = 4100;

type Detector = (buffer: Uint8Array) => string | null;

let detector: Promise<Detector> | undefined;

/** The installed pi package root, found by walking up from this module. */
export function findPiRoot(from = dirname(fileURLToPath(import.meta.url))): string {
	let dir = from;
	for (;;) {
		const candidate = join(dir, "node_modules", "@earendil-works", "pi-coding-agent");
		if (existsSync(candidate)) return candidate;
		const parent = dirname(dir);
		if (parent === dir)
			throw new Error("pi-enclave: @earendil-works/pi-coding-agent is not installed above this module");
		dir = parent;
	}
}

async function loadDetector(): Promise<Detector> {
	const url = pathToFileURL(join(findPiRoot(), "dist", "utils", "mime.js")).href;
	const mod = (await import(url)) as { detectSupportedImageMimeType?: Detector };
	if (typeof mod.detectSupportedImageMimeType !== "function") {
		throw new Error("pi-enclave: pi's image detector is not where the pinned version keeps it");
	}
	return mod.detectSupportedImageMimeType;
}

/** Detect a supported image type from its leading bytes, using pi's own rules. */
export async function detectImageMimeType(head: Uint8Array): Promise<string | null> {
	detector ??= loadDetector();
	return (await detector)(head);
}
