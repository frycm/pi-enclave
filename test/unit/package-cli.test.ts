import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const root = dirname(dirname(dirname(fileURLToPath(import.meta.url))));

describe("packaged CLI entrypoint", () => {
	it("uses the package-relative wrapper", () => {
		const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8")) as {
			bin: { "pi-enclave": string };
		};
		expect(pkg.bin["pi-enclave"]).toBe("./bin/pi-enclave.mjs");
	});

	it("runs from a working directory outside the package", () => {
		const result = spawnSync(process.execPath, [join(root, "bin/pi-enclave.mjs"), "--help"], {
			cwd: tmpdir(),
			encoding: "utf8",
		});
		expect(result.status, result.stderr).toBe(0);
		expect(result.stdout).toContain("pi-enclave");
	});
});
