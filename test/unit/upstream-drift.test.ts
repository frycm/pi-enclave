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
import { existsSync, readdirSync, readFileSync } from "node:fs";
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
const PINNED_PI_VERSION = "1.5.2";
const PINNED_GREP_SHA256 = "9f05f9b18d4edf7675395fdfaeba2050dff8e43b1e45922096c185a64a73118e";
const PINNED_MIME_SHA256 = "36bdb72fc40d809ab5f69e80ecd54651d4131661e92cf7dcec7b719f139badcf";

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

/**
 * GHSA-mrhx-c7xc-m3w5 (#38): sandbox-runtime depends on a Zod with an
 * oversized-collection validation advisory and no fixed 3.x release. It is
 * recorded as not reachable in docs/dependency-upgrade.md because nothing
 * pi-enclave calls validates with Zod: the schemas are only re-exported by the
 * package index, and parsed by the `srt` CLI's settings loader and the
 * `srt-proxy` decider client, neither of which pi-enclave starts.
 *
 * These checks make that conclusion fail loudly instead of going stale. An
 * SRT release that starts validating inside the manager, or a pi-enclave
 * change that imports a schema, reopens the question.
 */
describe("sandbox-runtime does not validate with Zod on pi-enclave's path (#38)", () => {
	const srtRoot = join(findPiRoot(), "..", "..", "@anthropic-ai", "sandbox-runtime");
	const ZOD_MODULES = ["sandbox-config.js", "config-loader.js", "decider-client.js"];

	/** Every module `entry` loads, by relative specifier, and every bare specifier it names. */
	function importClosure(entry: string): { files: Set<string>; packages: Set<string> } {
		const files = new Set<string>();
		const packages = new Set<string>();
		const pending = [entry];
		const specifier =
			/(?:import|export)\s[^'"]*?from\s*['"]([^'"]+)['"]|import\s*\(\s*['"]([^'"]+)['"]\s*\)|^\s*import\s*['"]([^'"]+)['"]|require\(\s*['"]([^'"]+)['"]\s*\)/gm;
		while (pending.length > 0) {
			const file = pending.pop() as string;
			if (files.has(file)) continue;
			files.add(file);
			for (const match of readFileSync(file, "utf8").matchAll(specifier)) {
				const name = (match[1] ?? match[2] ?? match[3] ?? match[4]) as string;
				if (name.startsWith(".")) pending.push(join(dirname(file), name));
				else packages.add(name);
			}
		}
		return { files, packages };
	}

	it("loads no Zod schema or parser from SandboxManager", () => {
		const { files, packages } = importClosure(join(srtRoot, "dist", "sandbox", "sandbox-manager.js"));
		// A sanity floor, so a resolver that silently found nothing cannot pass.
		expect(files.size).toBeGreaterThan(10);
		const reached = [...files].filter((file) => ZOD_MODULES.some((name) => file.endsWith(`/${name}`)));
		expect(
			reached,
			"sandbox-runtime's manager now loads a Zod-validating module. Re-check GHSA-mrhx-c7xc-m3w5 " +
				"reachability (docs/dependency-upgrade.md) before upgrading.",
		).toEqual([]);
		expect([...packages].filter((name) => name === "zod" || name.startsWith("zod/"))).toEqual([]);
	});

	it("is used by pi-enclave only through SandboxManager and getDefaultWritePaths", () => {
		const src = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "src");
		const names: string[] = [];
		for (const entry of readdirSync(src, { recursive: true, withFileTypes: true })) {
			if (!entry.isFile() || !/\.(ts|mjs|js)$/.test(entry.name)) continue;
			const text = readFileSync(join(entry.parentPath, entry.name), "utf8");
			for (const match of text.matchAll(/import\s+([^;]*?)\s+from\s*"@anthropic-ai\/sandbox-runtime[^"]*"/g)) {
				const clause = match[1] as string;
				const named = /^(?:type\s+)?\{([^}]*)\}$/.exec(clause.trim());
				// A namespace or default import could reach the schemas; list it as such.
				if (!named) names.push(`${entry.name}: ${clause.trim()}`);
				else names.push(...(named[1] as string).split(",").map((name) => name.replace(/^\s*type\s+/, "").trim()));
			}
		}
		expect(
			names.filter(Boolean).sort(),
			"pi-enclave imports more of sandbox-runtime than SandboxManager and getDefaultWritePaths; " +
				"check whether the new import validates with Zod (GHSA-mrhx-c7xc-m3w5, docs/dependency-upgrade.md)",
		).toEqual(["SandboxManager", "getDefaultWritePaths"]);
	});
});
