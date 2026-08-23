/**
 * The world each conformance scenario runs against.
 *
 * Everything lives under temp directories, deliberately. A scenario that tried
 * to write `/etc/passwd` would "pass" on an unsandboxed backend purely because
 * the test user is not root -- which would make the suite unfalsifiable, since
 * the thing it is meant to detect (no sandbox at all) would look like success.
 * Every denied target here is somewhere the test process genuinely could reach
 * if nothing stopped it.
 */
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Profile } from "../../src/backend/types.ts";

/** Planted in the parent process so the env-leak scenario has something to find. */
export const SECRET_ENV = {
	ANTHROPIC_API_KEY: "sk-ant-CONFORMANCE-LEAK",
	AWS_SECRET_ACCESS_KEY: "aws-CONFORMANCE-LEAK",
	GITHUB_TOKEN: "ghp-CONFORMANCE-LEAK",
} as const;

/** Written into the read-denied directory. Must never appear in any output. */
export const SECRET_FILE_CONTENT = "PRIVATE-KEY-CONFORMANCE-LEAK";

/** Written outside the workspace. Scenarios check it is still intact afterwards. */
export const OUTSIDE_FILE_CONTENT = "OUTSIDE-ORIGINAL-CONTENT";

export interface Fixture {
	/** Writable root and the command working directory. */
	workspace: string;
	/** Read-denied: holds `.ssh/id_ed25519` and `.aws/credentials`. */
	deniedHome: string;
	/** Readable (reads are a deny-list) but not writable. */
	outside: string;
	/** A file in `outside`, used as a symlink target for the write-through test. */
	outsideFile: string;
	profile: Profile;
	cleanup(): void;
}

export function createFixture(): Fixture {
	const workspace = mkdtempSync(join(tmpdir(), "enclave-ws-"));
	const deniedHome = mkdtempSync(join(tmpdir(), "enclave-denied-"));
	const outside = mkdtempSync(join(tmpdir(), "enclave-outside-"));

	mkdirSync(join(deniedHome, ".ssh"));
	mkdirSync(join(deniedHome, ".aws"));
	writeFileSync(join(deniedHome, ".ssh", "id_ed25519"), `${SECRET_FILE_CONTENT}\n`);
	writeFileSync(join(deniedHome, ".aws", "credentials"), `${SECRET_FILE_CONTENT}\n`);

	const outsideFile = join(outside, "target.txt");
	writeFileSync(outsideFile, `${OUTSIDE_FILE_CONTENT}\n`);

	writeFileSync(join(workspace, "ok.txt"), "workspace content\n");

	// The symlink-race pair: both live inside the writable workspace but resolve
	// outside it. The kernel decides on the resolved path, which is the whole
	// point of routing file operations through the sandbox rather than checking
	// paths in the pi process.
	symlinkSync(join(deniedHome, ".ssh"), join(workspace, "link-to-denied"));
	symlinkSync(outsideFile, join(workspace, "link-to-outside"));

	const profile: Profile = {
		mode: "workspace-write",
		writableRoots: [workspace],
		readDeny: [deniedHome],
		network: "off",
		allowPty: true,
	};

	return {
		workspace,
		deniedHome,
		outside,
		outsideFile,
		profile,
		cleanup() {
			for (const dir of [workspace, deniedHome, outside]) {
				rmSync(dir, { recursive: true, force: true });
			}
		},
	};
}

/**
 * Can this host reach the internet at all?
 *
 * The network scenario's falsifiability control assumes an unsandboxed process
 * would succeed. On a host with no egress -- a restricted CI runner, an offline
 * laptop -- it would fail for reasons unrelated to the sandbox, and the control
 * would report "the suite is not falsifiable" when the truth is "this host
 * cannot run that control". Check the assumption rather than inherit it.
 */
export function hostHasNetwork(): boolean {
	const probe = spawnSync(
		"python3",
		["-c", "import socket;s=socket.socket();s.settimeout(4);s.connect(('1.1.1.1',80));print('OK')"],
		{ encoding: "utf8", timeout: 15_000 },
	);
	return probe.stdout?.includes("OK") ?? false;
}

/** Set the secret variables in this process, returning a restore function. */
export function plantSecrets(): () => void {
	const previous = new Map<string, string | undefined>();
	for (const [name, value] of Object.entries(SECRET_ENV)) {
		previous.set(name, process.env[name]);
		process.env[name] = value;
	}
	return () => {
		for (const [name, value] of previous) {
			if (value === undefined) delete process.env[name];
			else process.env[name] = value;
		}
	};
}
