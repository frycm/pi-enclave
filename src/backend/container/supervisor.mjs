/** Trusted host supervisor: stdin EOF survives a killed parent; cleanup owns create/start/remove. */
import { execFile, spawn } from "node:child_process";
import { once } from "node:events";
import { readFileSync, unlinkSync } from "node:fs";
import { Socket } from "node:net";
import { promisify } from "node:util";

const exec = promisify(execFile);
const plan = JSON.parse(readFileSync(process.argv[2], "utf8"));
unlinkSync(process.argv[2]);
let cancelled = false;
let creating = true;
let attachment;
let cleaning;
const cli = (args) =>
	exec(plan.binary, [...plan.prefix, ...args], { env: plan.engineEnv, timeout: 30_000, maxBuffer: 1024 * 1024 });

async function remove() {
	if (creating) return;
	if (cleaning) return cleaning;
	cleaning = (async () => {
		try {
			await cli(["rm", "--force", ...(plan.engine === "podman" ? ["--time", "0"] : []), plan.name]);
		} catch (error) {
			if (!/no such container|does not exist|not found/i.test(`${error.stderr ?? ""}`)) throw error;
		}
	})();
	return cleaning;
}
function cancel() {
	cancelled = true;
	void remove().catch((error) => {
		process.stderr.write(`pi-enclave: cleanup failed: ${error.message}\n`);
		process.exitCode = 125;
	});
}
process.on("SIGTERM", cancel);
process.on("SIGINT", cancel);
process.stdin.on("end", cancel);
process.stdin.on("error", cancel);
process.stdout.on("error", cancel);
process.stderr.on("error", cancel);
const lifetime = new Socket({ fd: 3, readable: true, writable: false });
lifetime.on("end", cancel);
lifetime.on("error", cancel);
lifetime.resume();

try {
	await cli(plan.create);
	creating = false;
	if (cancelled || process.stdin.readableEnded) {
		await remove();
		process.exitCode = 130;
	} else {
		attachment = spawn(plan.binary, [...plan.prefix, "start", "--attach", "--interactive", plan.name], {
			env: plan.engineEnv,
			stdio: ["pipe", "pipe", "pipe"],
		});
		attachment.stdin.on("error", cancel);
		attachment.stdout.pipe(process.stdout, { end: false });
		attachment.stderr.pipe(process.stderr, { end: false });
		process.stdin.pipe(attachment.stdin);
		const [code] = await once(attachment, "close");
		await remove();
		process.exitCode = cancelled ? 130 : (code ?? 125);
	}
} catch (error) {
	creating = false;
	process.stderr.write(`pi-enclave: container supervisor: ${error.stderr?.trim() || error.message}\n`);
	try {
		await remove();
	} catch (cleanupError) {
		process.stderr.write(`pi-enclave: cleanup failed: ${cleanupError.message}\n`);
	}
	process.exitCode = 125;
} finally {
	process.stdin.destroy();
	lifetime.destroy();
	attachment?.stdin.destroy();
}
