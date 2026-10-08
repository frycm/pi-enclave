import { execFile, spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { once } from "node:events";
import {
	existsSync,
	mkdirSync,
	mkdtempSync,
	readFileSync,
	renameSync,
	rmSync,
	symlinkSync,
	writeFileSync,
} from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { checkSecureFile, ensureSecureDir } from "../../state/dir.ts";
import type { CompiledProfile, Profile } from "../types.ts";
import type { ContainerBackend } from "./backend.ts";

export const CONTAINER_CORPUS_VERSION = 1;
export interface QualificationRow {
	name: string;
	ms: number;
}
export interface ContainerQualification {
	schema: 1;
	corpus: number;
	identity: string;
	at: string;
	rows: QualificationRow[];
}

export async function requireContainerQualification(
	backend: ContainerBackend,
	qualifiedDir: string,
): Promise<ContainerQualification> {
	const identity = await backend.identity();
	ensureSecureDir(qualifiedDir);
	const path = join(qualifiedDir, `container-${identity}.json`);
	const problem = checkSecureFile(path);
	if (problem)
		throw new Error(
			`pi-enclave: ${backend.name} is unqualified: ${problem}. Run pi-enclave qualify-backend on this host.`,
		);
	const record = JSON.parse(readFileSync(path, "utf8")) as ContainerQualification;
	if (
		record.schema !== 1 ||
		record.corpus !== CONTAINER_CORPUS_VERSION ||
		record.identity !== identity ||
		!Array.isArray(record.rows) ||
		record.rows.length !== 14
	)
		throw new Error("pi-enclave: container qualification does not match the current contract");
	return record;
}

/** The same executable contract is used by local qualification and engine CI. No silent skips. */
export async function qualifyContainer(
	backend: ContainerBackend,
	qualifiedDir?: string,
): Promise<ContainerQualification> {
	const identity = await backend.identity();
	const root = mkdtempSync(join(tmpdir(), "enclave-container-eval-"));
	const workspace = join(root, "workspace");
	const outside = join(root, "outside");
	mkdirSync(workspace);
	mkdirSync(outside);
	mkdirSync(join(workspace, ".git", "hooks"), { recursive: true });
	writeFileSync(join(workspace, ".git", "config"), "protected");
	mkdirSync(join(workspace, "secrets"));
	const secret = join(workspace, "secrets", "key");
	writeFileSync(secret, "QUALIFICATION-SECRET");
	writeFileSync(join(workspace, "ordinary.txt"), "ordinary");
	const target = join(outside, "target");
	writeFileSync(target, "original");
	symlinkSync(target, join(workspace, "outside-link"));
	symlinkSync(secret, join(workspace, "secret-link"));
	const profile: Profile = {
		mode: "workspace-write",
		writableRoots: [workspace],
		readableRoots: [outside],
		readDeny: [join(workspace, "secrets")],
		writeDeny: [join(workspace, ".git", "config"), join(workspace, ".git", "hooks")],
		network: "off",
		allowPty: true,
	};
	let compiled: CompiledProfile;
	const rows: QualificationRow[] = [];
	const assert = (ok: unknown, message: string) => {
		if (!ok) throw new Error(`pi-enclave: container qualification failed: ${message}`);
	};
	const sh = async (
		command: string,
		extra: {
			compiled?: CompiledProfile;
			writeCapability?: string;
			readCapability?: string;
			timeout?: number;
			signal?: AbortSignal;
		} = {},
	) => {
		const chunks: Buffer[] = [];
		const result = await backend.run(extra.compiled ?? compiled, {
			...extra,
			command,
			cwd: workspace,
			env: {
				...process.env,
				ANTHROPIC_API_KEY: "QUALIFICATION-HOST-SECRET",
				IMAGE_ONLY_SECRET: "QUALIFICATION-HOST-SECRET",
			},
			commandId: randomBytes(12).toString("hex"),
			onData: (chunk) => chunks.push(chunk),
			timeout: extra.timeout ?? 10,
		});
		return { ...result, output: Buffer.concat(chunks).toString() };
	};
	const row = async (name: string, check: () => Promise<void>) => {
		const start = performance.now();
		await check();
		rows.push({ name, ms: performance.now() - start });
	};
	try {
		compiled = await backend.compile(profile);
		await row("workspace-and-uid", async () => {
			const result = await sh(
				"echo written > written.txt; id -u; grep CapEff /proc/self/status; test $(cat /sys/fs/cgroup/pids.max) = 256; test $(cat /sys/fs/cgroup/memory.max) = 536870912",
			);
			assert(
				result.exitCode === 0 &&
					readFileSync(join(workspace, "written.txt"), "utf8") === "written\n" &&
					/CapEff:\s+0+/.test(result.output) &&
					result.output.split("\n").includes(String(process.getuid?.())),
				"normal workspace writes, resource limits and zero capabilities",
			);
		});
		await row("outside-write-and-symlinks", async () => {
			assert((await sh(`echo bad > '${target}'`)).exitCode !== 0, "outside write permitted");
			assert(
				(await sh("echo bad > outside-link")).exitCode !== 0 && readFileSync(target, "utf8") === "original",
				"symlink write escaped",
			);
		});
		await row("nested-read-denials", async () => {
			assert(
				!(await sh("cat secrets/key secret-link 2>/dev/null; true")).output.includes("QUALIFICATION-SECRET"),
				"secret disclosed",
			);
		});
		await row("protected-metadata-and-rename", async () => {
			assert((await sh("echo bad > .git/config")).exitCode !== 0, "protected write permitted");
			assert((await sh("mv .git moved-git")).exitCode !== 0, "protected mount ancestor renamed");
		});
		await row("environment", async () => {
			const result = await sh("env");
			assert(
				result.exitCode === 0 &&
					!/QUALIFICATION-HOST-SECRET|IMAGE_ONLY_SECRET|DOCKER_HOST|CONTAINER_HOST/.test(result.output),
				"host or image environment supplemented the child environment",
			);
		});
		await row("tcp-dns-and-unix-socket", async () => {
			const socket = join(workspace, "live.sock");
			const server = createServer((connection) => {
				connection.on("error", () => {});
				connection.end("UNSANDBOXED-CONTROL");
			});
			server.listen(socket);
			await once(server, "listening");
			const tcp = createServer((connection) => {
				connection.on("error", () => {});
				connection.end("TCP-CONTROL");
			});
			tcp.listen(0, "127.0.0.1");
			await once(tcp, "listening");
			const address = tcp.address();
			if (!address || typeof address === "string") throw new Error("missing TCP control address");
			try {
				const { stdout } = await promisify(execFile)(process.execPath, [
					"-e",
					`require('net').connect(${JSON.stringify(socket)}).on('data',d=>process.stdout.write(d))`,
				]);
				assert(stdout.includes("UNSANDBOXED-CONTROL"), "socket positive control did not connect");
				const control = await promisify(execFile)(process.execPath, [
					"-e",
					`require('net').connect(${address.port},'127.0.0.1').on('data',d=>process.stdout.write(d))`,
				]);
				assert(control.stdout.includes("TCP-CONTROL"), "TCP positive control did not connect");
				const script = `const n=require('net');for(const [label,a] of [['unix',{path:${JSON.stringify(socket)}}],['tcp',{host:'127.0.0.1',port:${address.port}}]]){try{n.connect(a).on('error',e=>console.log(label+':'+e.code));}catch(e){console.log(label+':'+e.code)}}require('dns').lookup('example.com',e=>console.log('dns:'+e?.code));`;
				const result = await sh(`node -e '${script.replaceAll("'", "'\\''")}'`);
				assert(
					result.exitCode === 0 &&
						!result.output.includes("UNSANDBOXED-CONTROL") &&
						result.output.includes("unix:EPERM") &&
						result.output.includes("tcp:EPERM") &&
						/dns:(EAI_AGAIN|EPERM|EACCES)/.test(result.output),
					"socket/DNS denial absent",
				);
			} finally {
				server.close();
				tcp.close();
			}
		});
		await row("file-helper-and-search", async () => {
			const fs = backend.fs(compiled);
			assert(
				(await fs.readFile(join(workspace, "ordinary.txt"))).toString() === "ordinary",
				"helper ordinary read failed",
			);
			await fs.writeFile(join(workspace, "helper.txt"), "helper");
			assert(
				(await fs.glob("*.txt", workspace, { ignore: [], limit: 100 })).some((path) => path.endsWith("helper.txt")),
				"helper search failed",
			);
			let denied = false;
			try {
				await fs.readFile(secret);
			} catch {
				denied = true;
			}
			assert(denied, "helper disclosed masked read");
		});
		await row("write-grant-sibling-isolation", async () => {
			const [granted, sibling] = await Promise.all([
				sh(`echo granted > '${target}'`, { writeCapability: outside }),
				sh(`echo sibling > '${target}'`),
			]);
			assert(
				granted.exitCode === 0 && sibling.exitCode !== 0 && readFileSync(target, "utf8") === "granted\n",
				"write grant reached a sibling",
			);
		});
		await row("read-grant-and-helper-lease", async () => {
			const [granted, sibling] = await Promise.all([
				sh("cat secrets/key", { readCapability: join(workspace, "secrets") }),
				sh("cat secrets/key"),
			]);
			assert(
				granted.output.includes("QUALIFICATION-SECRET") && !sibling.output.includes("QUALIFICATION-SECRET"),
				"read grant reached a sibling",
			);
			const lease = await backend.fsWithReadCapability(
				compiled,
				join(workspace, "secrets"),
				randomBytes(32).toString("hex"),
				workspace,
			);
			try {
				assert((await lease.client.readFile(secret)).toString() === "QUALIFICATION-SECRET", "leased read failed");
			} finally {
				await lease.dispose();
			}
			let refused = false;
			try {
				await lease.client.readFile(secret);
			} catch {
				refused = true;
			}
			assert(refused, "revoked helper lease survived");
		});
		await row("timeout-descendant-cleanup", async () => {
			const result = await sh(
				"setsid sh -c 'echo started > detached-started; sleep 4; echo escaped > detached.txt' >/dev/null 2>&1 & sleep 30",
				{
					timeout: 2,
				},
			);
			assert(result.exitCode === null, "timeout did not cancel");
			assert(existsSync(join(workspace, "detached-started")), "timeout descendant positive control did not start");
			await new Promise((resolve) => setTimeout(resolve, 4300));
			let escaped = false;
			try {
				readFileSync(join(workspace, "detached.txt"));
				escaped = true;
			} catch {}
			assert(!escaped, "detached descendant survived timeout");
		});
		await row("abort", async () => {
			const abort = new AbortController();
			const timer = setTimeout(() => abort.abort(), 300);
			try {
				assert((await sh("sleep 30", { signal: abort.signal })).exitCode === null, "abort did not cancel");
			} finally {
				clearTimeout(timer);
			}
		});
		await row("parent-death-cleanup", async () => {
			const source = new URL("./backend.ts", import.meta.url).href;
			const childScript = `import {ContainerBackend} from ${JSON.stringify(source)};
const backend = new ContainerBackend(${JSON.stringify(backend.settings)}, ${JSON.stringify(join(root, "parent-control"))});
const compiled = await backend.compile(${JSON.stringify(profile)});
await backend.run(compiled, {command: "setsid sh -c 'echo started > crash-started; sleep 2; echo escaped > crash-escaped' >/dev/null 2>&1 & sleep 30", cwd:${JSON.stringify(workspace)},env:{},commandId:"parent-death"});`;
			const child = spawn(
				process.execPath,
				["--import", fileURLToPath(import.meta.resolve("tsx")), "--input-type=module", "-e", childScript],
				{ stdio: ["ignore", "pipe", "pipe"] },
			);
			let diagnostic = "";
			child.stderr.on("data", (chunk: Buffer) => {
				diagnostic += chunk.toString();
			});
			const closed = once(child, "close");
			try {
				const deadline = Date.now() + 15_000;
				while (!existsSync(join(workspace, "crash-started")) && child.exitCode === null && Date.now() < deadline)
					await new Promise((resolve) => setTimeout(resolve, 50));
				assert(
					existsSync(join(workspace, "crash-started")),
					`parent-death positive control did not start: ${diagnostic}`,
				);
				child.kill("SIGKILL");
				await closed;
				await new Promise((resolve) => setTimeout(resolve, 2400));
				assert(!existsSync(join(workspace, "crash-escaped")), "detached descendant survived parent death");
			} finally {
				if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL");
				await closed;
			}
		});
		await row("large-output-and-helper-cancellation", async () => {
			const result = await sh("node -e 'process.stdout.write(\"x\".repeat(2097152))'");
			assert(result.exitCode === 0 && result.output.length === 2097152, "large output was lost");
			const abort = new AbortController();
			abort.abort();
			let refused = false;
			try {
				await backend.fs(compiled).grep(["ordinary", workspace], { signal: abort.signal });
			} catch {
				refused = true;
			}
			assert(refused, "cancelled helper search ran");
		});
		await row("topology-change-refusal", async () => {
			renameSync(join(workspace, "secrets"), join(workspace, "old-secrets"));
			mkdirSync(join(workspace, "secrets"));
			let refused = false;
			try {
				await sh("true");
			} catch {
				refused = true;
			}
			assert(refused, "retargeted mount accepted");
		});
		const record: ContainerQualification = {
			schema: 1,
			corpus: CONTAINER_CORPUS_VERSION,
			identity,
			at: new Date().toISOString(),
			rows,
		};
		if (qualifiedDir) {
			ensureSecureDir(qualifiedDir);
			const path = join(qualifiedDir, `container-${identity}.json`);
			const temporary = `${path}.${randomBytes(8).toString("hex")}`;
			writeFileSync(temporary, JSON.stringify(record, null, 2), { mode: 0o600, flag: "wx" });
			renameSync(temporary, path);
		}
		return record;
	} finally {
		await backend.dispose();
		rmSync(root, { recursive: true, force: true });
	}
}
