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
import { mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { createServer, type Server } from "node:net";
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

/** Sent by the probe socket. Seeing it means the sandbox did not stop the connection. */
export const SOCKET_GREETING = "SOCKET-REACHED-CONFORMANCE";

export interface Fixture {
	/** Writable root and the command working directory. */
	workspace: string;
	/** Read-denied: holds `.ssh/id_ed25519` and `.aws/credentials`. */
	deniedHome: string;
	/** Read-denied in the profile, but absent until a scenario creates it. */
	lateDenied: string;
	/** Read-denied, and a file rather than a directory. */
	deniedFile: string;
	/** Read-denied, and a symlink to a directory holding a secret. */
	deniedLink: string;
	/** A second directory with a secret, for retargeting `deniedLink`. */
	linkTargetB: string;
	/** Readable (reads are a deny-list) but not writable. */
	outside: string;
	/** A file in `outside`, used as a symlink target for the write-through test. */
	outsideFile: string;
	/**
	 * A unix socket outside the workspace with something genuinely listening.
	 *
	 * It has to be real. Pointing the socket scenario at a path with no listener
	 * makes it pass everywhere -- including against a backend that enforces
	 * nothing, because connect() fails with ENOENT rather than a denial. The
	 * falsifiability control caught exactly that on a host without docker.sock.
	 */
	socketPath: string;
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

	// A live listener, so a successful connect() proves the boundary is absent
	// rather than proving the socket does not exist.
	const socketPath = join(outside, "probe.sock");
	const server: Server = createServer((connection) => {
		// The scenario connects and closes immediately -- a successful connect is
		// the whole verdict -- so this write usually lands on a closed socket. A
		// fixture that crashed the run on EPIPE would turn a passing security
		// test into an unexplained process exit.
		connection.on("error", () => {});
		connection.end(`${SOCKET_GREETING}\n`);
	});
	server.on("error", () => {});
	server.listen(socketPath);
	server.unref();

	writeFileSync(join(workspace, "ok.txt"), "workspace content\n");

	// The symlink-race pair: both live inside the writable workspace but resolve
	// outside it. The kernel decides on the resolved path, which is the whole
	// point of routing file operations through the sandbox rather than checking
	// paths in the pi process.
	symlinkSync(join(deniedHome, ".ssh"), join(workspace, "link-to-denied"));
	symlinkSync(outsideFile, join(workspace, "link-to-outside"));

	// A deny root that does not exist when the profile is compiled. bwrap can
	// only mask a directory that is there, so this is how the suite checks what
	// happens when a protected directory appears mid-session.
	const lateDenied = join(outside, "late-secrets");

	// A deny entry that is a *file*, not a directory. bwrap masks those with a
	// read-only /dev/null rather than a tmpfs, so reads "succeed" with no bytes.
	const deniedFile = join(outside, "netrc");
	writeFileSync(deniedFile, `${SECRET_FILE_CONTENT}\n`);

	// A deny entry that is a symlink, for the retarget case: SRT masks the link's
	// target at wrap time, so pointing it elsewhere afterwards must be noticed.
	const linkTargetA = join(outside, "creds-a");
	const linkTargetB = join(outside, "creds-b");
	mkdirSync(linkTargetA);
	mkdirSync(linkTargetB);
	writeFileSync(join(linkTargetA, "token"), `${SECRET_FILE_CONTENT}\n`);
	writeFileSync(join(linkTargetB, "token"), `${SECRET_FILE_CONTENT}\n`);
	const deniedLink = join(outside, "creds-link");
	symlinkSync(linkTargetA, deniedLink);

	// An ordinary tree for the find tool's pattern handling.
	mkdirSync(join(workspace, "src", "a"), { recursive: true });
	writeFileSync(join(workspace, "src", "a", "foo.spec.ts"), "");

	const profile: Profile = {
		mode: "workspace-write",
		writableRoots: [workspace],
		readDeny: [deniedHome, lateDenied, deniedFile, deniedLink],
		network: "off",
		allowPty: true,
	};

	return {
		workspace,
		deniedHome,
		lateDenied,
		deniedFile,
		deniedLink,
		linkTargetB,
		outside,
		outsideFile,
		socketPath,
		profile,
		cleanup() {
			server.close();
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

/**
 * What capabilities does an *unsandboxed* process hold on this host?
 *
 * Returns the hex `CapEff` mask, or `null` where the platform has no capability
 * model. C12's falsifiability control assumes an unsandboxed process has
 * capabilities to lose. That is true in a privileged container and as root; it
 * is false for an ordinary unprivileged Linux user -- a GitHub runner, a
 * developer laptop -- where `CapEff` is already zero and the noop backend passes
 * the row for a reason that has nothing to do with the sandbox.
 *
 * Same shape as {@link hostHasNetwork}: check the control's assumption instead
 * of reporting "the suite is unfalsifiable" when the host cannot run it.
 */
export function hostCapEff(): string | null {
	try {
		const match = /CapEff:\s*([0-9a-fA-F]+)/.exec(readFileSync("/proc/self/status", "utf8"));
		return match?.[1] ?? null;
	} catch {
		return null;
	}
}

/** True when this host's own processes hold capabilities, so C12 has something to prove. */
export function hostHoldsCapabilities(): boolean {
	const value = hostCapEff();
	return value !== null && /[1-9a-fA-F]/.test(value);
}

/** Are `rg` and `fd` on PATH, so the unsandboxed search control can actually search? */
export function hostHasSearchTools(): boolean {
	return ["rg", "fd"].every((bin) => spawnSync(bin, ["--version"], { stdio: "ignore" }).status === 0);
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
