/** Compare the actual helper/formatter with the installed pi grep on real rg output. */
import { execFileSync, spawn } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { createGrepTool } from "@earendil-works/pi-coding-agent";
import { describe, expect, it } from "vitest";
import { HelperFsClient } from "../../src/fs/client.ts";
import { type GrepArgs, runSandboxedGrep } from "../../src/tools/grep.ts";

const HELPER = join(dirname(fileURLToPath(import.meta.url)), "../../src/fs/helper.mjs");
const RG = execFileSync("which", ["rg"], { encoding: "utf8" }).trim();
const cases: { name: string; files: Record<string, string | Buffer>; args: GrepArgs }[] = [
	{
		name: "overlapping context",
		files: { "a.txt": "one\nhit\nhit\nfour\nfive\n" },
		args: { pattern: "hit", context: 1 },
	},
	{ name: "exact match limit", files: { "a.txt": "hit\nend\n" }, args: { pattern: "hit", limit: 1, context: 1 } },
	{
		name: "extra match in trailing context",
		files: { "a.txt": "hit\nhit\nend\n" },
		args: { pattern: "hit", limit: 1, context: 2 },
	},
	{
		name: "additional match beyond context",
		files: { "a.txt": "hit\nend\nblank\nhit\n" },
		args: { pattern: "hit", limit: 1, context: 1 },
	},
	{
		name: "directory-relative glob",
		files: { "nested/src/a.ts": "hit\n", "nested/other.ts": "hit\n" },
		args: { pattern: "hit", path: "nested", glob: "./src/*.ts" },
	},
	{ name: "single-file paths", files: { "nested/a.txt": "hit\n" }, args: { pattern: "hit", path: "nested/a.txt" } },
	{
		name: "lone carriage returns",
		files: { "a.txt": "before\rinside\nhit\nafter\rinside\n" },
		args: { pattern: "hit", context: 1 },
	},
	{ name: "non-UTF-8 content", files: { "a.txt": Buffer.from([104, 105, 116, 255, 10]) }, args: { pattern: "hit" } },
	{ name: "long lines", files: { "a.txt": `hit${"x".repeat(2000)}\n` }, args: { pattern: "hit" } },
	{
		name: "byte truncation with context",
		files: { "a.txt": `${`${"x".repeat(500)}\n`.repeat(200)}hit\n` },
		args: { pattern: "hit", context: 200 },
	},
	{ name: "zero limit", files: { "a.txt": "hit\nhit\n" }, args: { pattern: "hit", limit: 0 } },
];

describe("pi 1.5 grep parity", () => {
	it.each(cases)("matches upstream for $name through a symlinked search root", async ({ files, args }) => {
		const base = mkdtempSync(join(tmpdir(), "enclave-grep-parity-"));
		const directory = join(base, "workspace");
		mkdirSync(directory);
		const root = join(base, "link");
		symlinkSync(directory, root);
		for (const [path, content] of Object.entries(files)) {
			mkdirSync(dirname(join(root, path)), { recursive: true });
			writeFileSync(join(root, path), content);
		}
		const profile = {
			mode: "workspace-write" as const,
			writableRoots: [root],
			readDeny: [],
			network: "off" as const,
			allowPty: false,
		};
		const fs = new HelperFsClient({
			compiled: { backend: "seatbelt", profile, describe: () => "unsandboxed parity fixture" },
			spawnHelper: () =>
				spawn(process.execPath, [HELPER], {
					env: { ...process.env, PI_ENCLAVE_RG: RG },
					stdio: ["pipe", "pipe", "pipe"],
				}),
		});
		try {
			const expected = await createGrepTool(root).execute("reference", args, undefined, undefined);
			const actual = await runSandboxedGrep({ fs, cwd: root }, args);
			expect(actual).toEqual(expected);
		} finally {
			await fs.dispose();
			rmSync(base, { recursive: true, force: true });
		}
	});
});
