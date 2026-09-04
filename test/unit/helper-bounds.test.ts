/**
 * The helper's own bounds, exercised by running the real helper unsandboxed
 * with its search tools pointed at scripts that misbehave on purpose.
 *
 * Nothing here is about the boundary; it is about the helper staying alive
 * and answerable when a search produces far more than anyone wanted -- on
 * stdout, on stderr, or both.
 */
import { spawn } from "node:child_process";
import { chmodSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { HelperFsClient } from "../../src/fs/client.ts";

const HELPER = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "src", "fs", "helper.mjs");

/** A fake rg/fd that floods whichever stream it is told to, forever. */
const FLOOD = `#!/bin/sh
# $FLOOD_STREAM: out | err | both. Emits ~64 KiB lines until killed.
line=$(head -c 65536 /dev/zero | tr '\\0' 'x')
while :; do
  case "$FLOOD_STREAM" in
    out) echo "$line" ;;
    err) echo "$line" >&2 ;;
    both) echo "$line"; echo "$line" >&2 ;;
  esac
done
`;

describe("helper search bounds", () => {
	let dir: string;
	let flood: string;
	let serialized: string;

	beforeAll(() => {
		dir = mkdtempSync(join(tmpdir(), "enclave-flood-"));
		flood = join(dir, "flood.sh");
		writeFileSync(flood, FLOOD);
		chmodSync(flood, 0o755);
		serialized = join(dir, "serialized.sh");
		writeFileSync(
			serialized,
			`#!/bin/sh
if ! mkdir "$SEARCH_LOCK" 2>/dev/null; then
  echo "overlapping search" >&2
  exit 9
fi
trap 'rmdir "$SEARCH_LOCK"' EXIT
sleep 0.2
exit 1
`,
		);
		chmodSync(serialized, 0o755);
	});

	afterAll(() => {
		rmSync(dir, { recursive: true, force: true });
	});

	function client(stream: "out" | "err" | "both") {
		const profile = {
			mode: "workspace-write" as const,
			writableRoots: [dir],
			readDeny: [],
			network: "off" as const,
			allowPty: false,
		};
		return new HelperFsClient({
			compiled: { backend: "seatbelt", profile, describe: () => "unsandboxed test helper" },
			spawnHelper: () =>
				spawn(process.execPath, [HELPER], {
					env: { ...process.env, PI_ENCLAVE_RG: flood, PI_ENCLAVE_FD: flood, FLOOD_STREAM: stream },
					stdio: ["pipe", "pipe", "pipe"],
				}) as never,
			callTimeoutMs: 60_000,
		});
	}

	for (const stream of ["out", "err", "both"] as const) {
		it(`stops a grep that floods ${stream} and stays answerable`, async () => {
			const fs = client(stream);
			try {
				const started = Date.now();
				const result = await fs.grep(["--json", "x", dir], { limit: 0, path: dir });
				expect(result.capped, "the flood was not capped").toBe(true);
				expect(result.stdout.length).toBeLessThanOrEqual(17 * 1024 * 1024);
				expect(Date.now() - started).toBeLessThan(30_000);
				// The helper is still there for the next request.
				expect(await fs.exists(dir)).toBe(true);
			} finally {
				await fs.dispose();
			}
		}, 60_000);
	}

	it("stops rg at the match limit without waiting for the flood", async () => {
		const fs = client("out");
		try {
			// Every line is an x-flood, so no match events: the cap, not the limit,
			// ends it. With match events the limit ends it first -- covered by the
			// conformance grep rows, which use real rg.
			const result = await fs.grep(["--json", "x", dir], { limit: 3, path: dir });
			expect(result.capped || result.limitReached).toBe(true);
		} finally {
			await fs.dispose();
		}
	}, 60_000);

	it("serializes concurrent search requests to keep the aggregate memory bound", async () => {
		const profile = {
			mode: "workspace-write" as const,
			writableRoots: [dir],
			readDeny: [],
			network: "off" as const,
			allowPty: false,
		};
		const fs = new HelperFsClient({
			compiled: { backend: "seatbelt", profile, describe: () => "unsandboxed test helper" },
			spawnHelper: () =>
				spawn(process.execPath, [HELPER], {
					env: {
						...process.env,
						PI_ENCLAVE_RG: serialized,
						PI_ENCLAVE_FD: serialized,
						SEARCH_LOCK: join(dir, "search.lock"),
					},
					stdio: ["pipe", "pipe", "pipe"],
				}) as never,
			callTimeoutMs: 10_000,
		});
		try {
			await Promise.all([fs.grep(["--json", "x", dir], { path: dir }), fs.grep(["--json", "y", dir], { path: dir })]);
		} finally {
			await fs.dispose();
		}
	}, 15_000);
});
