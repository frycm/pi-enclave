/**
 * Drift check against the pi version pi-enclave is pinned to.
 *
 * `grep` is the one tool whose `execute` is replaced rather than redirected, so
 * two things are duplicated from pi and cannot be imported: the default match
 * limit, and the output shape the tests pin. Neither is exported, so nothing
 * fails when upstream changes them -- the sandboxed `grep` would simply start
 * disagreeing with the built-in one about what a truncated result looks like.
 *
 * So the artifact is hashed. A pi bump that touches `grep` fails here with what
 * to re-read, which is the whole of the "keep the copy in step" claim in the
 * plan: not that drift cannot happen, but that it cannot happen silently.
 */
import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { VERSION as PI_VERSION } from "@earendil-works/pi-coding-agent";
import { describe, expect, it } from "vitest";

/**
 * The installed pi package root.
 *
 * Resolved by walking up from this file rather than through the module
 * resolver: pi's `exports` hides `package.json` and declares only an `import`
 * condition, which neither `require.resolve` nor vitest's `import.meta.resolve`
 * can answer.
 */
function findPiRoot(): string {
	let dir = dirname(fileURLToPath(import.meta.url));
	for (;;) {
		const candidate = join(dir, "node_modules", "@earendil-works", "pi-coding-agent");
		if (existsSync(candidate)) return candidate;
		const parent = dirname(dir);
		if (parent === dir) throw new Error("pi-coding-agent is not installed anywhere above this test");
		dir = parent;
	}
}

const GREP_ARTIFACT = join(findPiRoot(), "dist", "core", "tools", "grep.js");
/** Loaded by file URL in src/tools/image-mime.ts because `exports` hides it. */
const MIME_ARTIFACT = join(findPiRoot(), "dist", "utils", "mime.js");

/** The pi build these hashes were taken from. Bump all together, never one. */
const PINNED_PI_VERSION = "0.84.2";
const PINNED_GREP_SHA256 = "c5289cbb5ea2a0f784387f80c91a10667104d651eb9af15903a87585044e75ed";
const PINNED_MIME_SHA256 = "e865d8bb69bc7462da3769a9add3f417f6f55ee3f8803cca4603123f8fbed438";

/** Duplicated in src/tools/grep.ts because pi does not export it. */
const DUPLICATED_DEFAULT_LIMIT = 100;

const source = readFileSync(GREP_ARTIFACT, "utf8");

describe("upstream grep drift", () => {
	it("is checked against the pinned pi version", () => {
		expect(
			PI_VERSION,
			"the installed pi is not the version this drift check was pinned to; re-read " +
				"pi's grep and update PINNED_PI_VERSION and PINNED_GREP_SHA256 together",
		).toBe(PINNED_PI_VERSION);
	});

	it("still reports the default match limit pi-enclave duplicates", () => {
		// Asserted on the value, not just the hash: this constant reaches users as
		// a different truncation notice, and a hash failure alone would not say so.
		const match = /const DEFAULT_LIMIT = (\d+);/.exec(source);
		expect(match?.[1], "pi's grep no longer declares DEFAULT_LIMIT the way this check reads it").toBeDefined();
		expect(
			Number(match?.[1]),
			"pi changed grep's default match limit; src/tools/grep.ts duplicates it and must follow",
		).toBe(DUPLICATED_DEFAULT_LIMIT);
	});

	it("still ships the image detector where the sandboxed read loads it from", () => {
		const digest = createHash("sha256").update(readFileSync(MIME_ARTIFACT)).digest("hex");
		expect(
			digest,
			"pi's dist/utils/mime.js changed. src/tools/image-mime.ts imports detectSupportedImageMimeType " +
				"from it by path; check the export and the sniff size, then update PINNED_MIME_SHA256.",
		).toBe(PINNED_MIME_SHA256);
		expect(/IMAGE_TYPE_SNIFF_BYTES = 4100/.test(readFileSync(MIME_ARTIFACT, "utf8"))).toBe(true);
	});

	it("has not changed since the sandboxed execute was written against it", () => {
		const digest = createHash("sha256").update(readFileSync(GREP_ARTIFACT)).digest("hex");
		expect(
			digest,
			"pi's grep changed. Re-read it against src/tools/grep.ts -- the output shape " +
				"(`path:line: text`, `path-line- text`, truncation notices) and the default " +
				"limit are duplicated there -- then update PINNED_GREP_SHA256.",
		).toBe(PINNED_GREP_SHA256);
	});
});
