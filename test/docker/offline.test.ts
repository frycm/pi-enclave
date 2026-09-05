/** Opt-in real Docker tests. Providing an image makes missing prerequisites fail, never skip. */
import { execFileSync } from "node:child_process";
import { once } from "node:events";
import {
	existsSync,
	mkdirSync,
	mkdtempSync,
	readFileSync,
	rmSync,
	statSync,
	symlinkSync,
	writeFileSync,
} from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { DockerBackend } from "../../src/backend/docker.ts";
import { shellQuote } from "../../src/backend/srt.ts";
import { type CompiledProfile, type Profile, SandboxDenied } from "../../src/backend/types.ts";
import { createReadOperations, createWriteOperations } from "../../src/tools/file-ops.ts";

const image = process.env.PI_ENCLAVE_DOCKER_IMAGE;
const binary = process.env.PI_ENCLAVE_DOCKER_BINARY ?? "/usr/bin/docker";

describe.skipIf(!image)("offline Docker boundary", () => {
	let backend: DockerBackend;
	let root: string;
	let workspace: string;
	let outside: string;
	let secret: string;
	let profile: Profile;
	let compiled: CompiledProfile;

	beforeEach(async () => {
		root = mkdtempSync(join(tmpdir(), "enclave-docker-live-"));
		workspace = join(root, "workspace");
		outside = join(root, "outside");
		mkdirSync(workspace);
		mkdirSync(outside);
		mkdirSync(join(workspace, ".git", "hooks"), { recursive: true });
		writeFileSync(join(workspace, ".git", "config"), "protected config");
		mkdirSync(join(workspace, "secrets"));
		secret = join(workspace, "secrets", "token");
		writeFileSync(secret, "DOCKER-CONFORMANCE-SECRET");
		writeFileSync(join(workspace, "private-file"), "DOCKER-CONFORMANCE-SECRET");
		writeFileSync(join(workspace, "ordinary.txt"), "ordinary content");
		writeFileSync(join(outside, "target.txt"), "outside original");
		symlinkSync(secret, join(workspace, "secret-link"));
		symlinkSync(join(outside, "target.txt"), join(workspace, "outside-link"));
		profile = {
			mode: "workspace-write",
			writableRoots: [workspace],
			readableRoots: [outside],
			readDeny: [join(workspace, "secrets"), join(workspace, "private-file")],
			writeDeny: [join(workspace, ".git", "hooks"), join(workspace, ".git", "config")],
			network: "off",
			allowPty: true,
		};
		backend = new DockerBackend({ image: image ?? "", binary });
		compiled = await backend.compile(profile);
	}, 60_000);

	afterEach(async () => {
		try {
			await backend?.dispose();
		} finally {
			if (root) rmSync(root, { recursive: true, force: true });
		}
	}, 60_000);

	async function sh(command: string, options: { signal?: AbortSignal; timeout?: number } = {}) {
		const chunks: Buffer[] = [];
		const result = await backend.run(compiled, {
			command,
			cwd: workspace,
			env: {
				...process.env,
				ANTHROPIC_API_KEY: "HOST-KEY-MUST-NOT-LEAK",
				IMAGE_ONLY_SECRET: "HOST-ENV-MUST-NOT-LEAK",
			} as Record<string, string>,
			commandId: "docker-conformance",
			onData: (data) => chunks.push(data),
			...options,
		});
		return { ...result, output: Buffer.concat(chunks).toString() };
	}

	it("allows workspace shell writes, explicit outside reads and correct UID ownership", async () => {
		const result = await sh(
			`printf ordinary > made.txt; cat ${shellQuote(join(outside, "target.txt"))}; printf ' uid='; id -u`,
		);
		expect(result.exitCode, result.output).toBe(0);
		expect(result.output).toContain("outside original");
		expect(result.output).toContain(`uid=${process.getuid?.()}`);
		expect(statSync(join(workspace, "made.txt")).uid).toBe(process.getuid?.());
	});

	it("refuses host writes, symlink writes, protected metadata and ancestor replacement", async () => {
		for (const command of [
			`echo wrong > ${shellQuote(join(outside, "target.txt"))}`,
			"echo wrong > outside-link",
			"echo wrong > .git/config",
			"echo wrong > .git/hooks/attack",
			"mv .git moved && mkdir -p .git/hooks && echo wrong > .git/hooks/attack",
		]) {
			const result = await sh(command);
			expect(result.exitCode, `${command}: ${result.output}`).not.toBe(0);
		}
		expect(readFileSync(join(outside, "target.txt"), "utf8")).toBe("outside original");
		expect(readFileSync(join(workspace, ".git", "config"), "utf8")).toBe("protected config");
		expect(existsSync(join(workspace, "moved"))).toBe(false);
	});

	it("denies secrets to shell reads, symlinks and recursive search", async () => {
		for (const command of ["cat secrets/token", "cat private-file", "cat secret-link"]) {
			const result = await sh(command);
			expect(result.exitCode).not.toBe(0);
			expect(result.output).not.toContain("DOCKER-CONFORMANCE-SECRET");
		}
		const result = await sh("rg --hidden --no-ignore --follow DOCKER-CONFORMANCE-SECRET .");
		expect(result.output).not.toContain("DOCKER-CONFORMANCE-SECRET");
	});

	it("denies TCP, DNS and a live Unix socket exposed inside the workspace", async () => {
		const socket = join(workspace, "host.sock");
		let connections = 0;
		const server = createServer((client) => {
			connections += 1;
			client.end();
		});
		server.listen(socket);
		await once(server, "listening");
		try {
			// Prove the listener is real and reachable without the boundary.
			const { createConnection } = await import("node:net");
			const client = createConnection(socket);
			await once(client, "connect");
			client.end();
			await delay(20);
			expect(connections).toBe(1);
			const result = await sh(
				`python3 -c ${shellQuote(`import socket
for family,target in [(socket.AF_INET,('1.1.1.1',80)),(socket.AF_UNIX,${JSON.stringify(socket)})]:
 try:
  s=socket.socket(family);s.settimeout(2);s.connect(target);print('LEAK')
 except OSError: print('DENIED')
try: socket.getaddrinfo('example.com',443);print('DNS_LEAK')
except OSError: print('DNS_DENIED')`)}`,
			);
			expect(result.exitCode, result.output).toBe(0);
			expect(result.output).not.toContain("LEAK");
			expect(result.output.match(/DENIED/g)).toHaveLength(3);
			expect(connections).toBe(1);
		} finally {
			server.close();
		}
	});

	it("starts shell and helper with env -i, ignoring host/image secrets and image entrypoint", async () => {
		const result = await sh("env; cat /proc/1/environ");
		expect(result.exitCode, result.output).toBe(0);
		for (const word of ["ANTHROPIC_API_KEY", "IMAGE_ONLY_SECRET", "MUST-NOT-LEAK"])
			expect(result.output).not.toContain(word);
		expect(result.output).toContain("PATH=/usr/local/bin:/usr/bin:/bin");
		const helperEnv = (await backend.fs(compiled).readFile("/proc/1/environ")).toString();
		for (const word of ["ANTHROPIC_API_KEY", "IMAGE_ONLY_SECRET", "MUST-NOT-LEAK"])
			expect(helperEnv).not.toContain(word);
	});

	it("keeps all capabilities empty and no-new-privileges set, including exec of su/sudo", async () => {
		const result = await sh("cat /proc/self/status; sudo -n id; su root -c id");
		for (const cap of ["CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"])
			expect(result.output).toMatch(new RegExp(`${cap}:\\s*0+(?:\\s|$)`));
		expect(result.output).toMatch(/NoNewPrivs:\s*1/);
		expect(result.output).not.toContain("uid=0");
	});

	it("supports the filesystem helper and pi read/write/search adapters under the same mounts", async () => {
		const fs = backend.fs(compiled);
		const read = createReadOperations(() => fs);
		const write = createWriteOperations(() => fs);
		await write.mkdir(join(workspace, "new"));
		await write.writeFile(join(workspace, "new", "file.txt"), "helper ordinary");
		expect((await read.readFile(join(workspace, "new", "file.txt"))).toString()).toBe("helper ordinary");
		expect((await fs.readFile(join(outside, "target.txt"))).toString()).toBe("outside original");
		for (const target of [secret, join(workspace, "private-file"), join(workspace, "secret-link")]) {
			await expect(fs.readFile(target)).rejects.toBeInstanceOf(SandboxDenied);
			await expect(fs.head(target, 32)).rejects.toBeInstanceOf(SandboxDenied);
			await expect(fs.access(target, "read")).rejects.toBeInstanceOf(SandboxDenied);
		}
		await expect(fs.readdir(join(workspace, "secrets"))).rejects.toBeInstanceOf(SandboxDenied);
		await expect(fs.writeFile(join(outside, "target.txt"), "wrong")).rejects.toBeInstanceOf(SandboxDenied);
		await expect(fs.readFile(join(workspace, "missing"))).rejects.toMatchObject({ code: "ENOENT" });
		const files = await fs.glob("*.txt", workspace, { ignore: [], limit: 100 });
		expect(files.some((path) => path.endsWith("ordinary.txt"))).toBe(true);
		const matches = await fs.grep(["--hidden", "--no-ignore", "ordinary", workspace], { path: workspace });
		expect(matches.stdout).toContain("ordinary content");
	});

	it.each(["timeout", "abort"])("reaps a setsid descendant before returning from %s", async (kind) => {
		const controller = new AbortController();
		const marker = join(workspace, "escaped");
		const command = `setsid /bin/bash -c ${shellQuote(`sleep 2; echo escaped > ${shellQuote(marker)}`)} >/dev/null 2>&1 & echo READY; sleep 30`;
		const output: Buffer[] = [];
		const result = await backend.run(compiled, {
			command,
			cwd: workspace,
			env: {},
			commandId: `cleanup-${kind}`,
			...(kind === "timeout" ? { timeout: 0.25 } : { signal: controller.signal }),
			onData: (data) => {
				output.push(data);
				if (kind === "abort" && data.toString().includes("READY")) controller.abort();
			},
		});
		expect(Buffer.concat(output).toString()).toContain("READY");
		expect(result.exitCode).toBeNull();
		await delay(2500);
		expect(existsSync(marker)).toBe(false);
		// This test process owns no other containers with this workspace mount.
		const remaining = execFileSync(binary, ["ps", "-aq", "--filter", `volume=${workspace}`], {
			encoding: "utf8",
		}).trim();
		expect(remaining).toBe("");
	});

	it("refuses unimplemented capabilities and invalid timeout before creating a container", async () => {
		for (const extra of [{ readCapability: secret }, { writeCapability: outside }, { timeout: Number.NaN }]) {
			await expect(
				backend.run(compiled, {
					command: "touch should-not-run",
					cwd: workspace,
					env: {},
					commandId: "refused",
					...extra,
				}),
			).rejects.toThrow();
		}
		expect(existsSync(join(workspace, "should-not-run"))).toBe(false);
	});
});
