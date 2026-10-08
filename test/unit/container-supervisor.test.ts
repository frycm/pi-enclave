import { spawn } from "node:child_process";
import { once } from "node:events";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

async function supervise(denied: boolean) {
	const root = mkdtempSync(join(tmpdir(), "enclave-supervisor-"));
	const state = join(root, "state");
	const engine = join(root, "engine.mjs");
	writeFileSync(
		engine,
		`import {readFileSync,writeFileSync} from 'node:fs';
const state=${JSON.stringify(state)}; const args=process.argv.slice(2);
if(args[0]==='create'){writeFileSync(state,'0');console.log('id');}
if(args[0]==='start')console.log('attached');
if(args[0]==='rm'){console.error(${JSON.stringify(denied ? "permission denied" : "removal of container is already in progress")});process.exit(1);}
if(args[0]==='container'&&args[1]==='inspect'){
const count=Number(readFileSync(state,'utf8'))+1; writeFileSync(state,String(count));
if(count===1)console.log('[{"State":{"Status":"removing"}}]');
else {console.error('Error: No such object: fixture');process.exit(1);}
}`,
	);
	const plan = join(root, "plan.json");
	writeFileSync(
		plan,
		JSON.stringify({
			engine: "docker",
			name: "fixture",
			binary: process.execPath,
			prefix: [engine],
			engineEnv: {},
			create: ["create"],
		}),
		{ mode: 0o600 },
	);
	const child = spawn(
		process.execPath,
		[fileURLToPath(new URL("../../src/backend/container/supervisor.mjs", import.meta.url)), plan],
		{ stdio: ["pipe", "pipe", "pipe", "pipe"] },
	);
	let diagnostic = "";
	child.stdout.resume();
	child.stderr.on("data", (chunk: Buffer) => {
		diagnostic += chunk.toString();
	});
	try {
		const [code] = await once(child, "close");
		if (!existsSync(state)) throw new Error(`supervisor exited ${code} before create: ${diagnostic}`);
		return { code, diagnostic, inspections: Number(readFileSync(state, "utf8")) };
	} finally {
		if (child.exitCode === null) child.kill("SIGKILL");
		rmSync(root, { recursive: true, force: true });
	}
}

describe("container supervisor removal", () => {
	it("waits for confirmed absence when automatic removal is already in progress", async () => {
		const result = await supervise(false);
		expect(result).toEqual({ code: 0, diagnostic: "", inspections: 2 });
	});
	it("refuses a real removal failure instead of treating it as absence", async () => {
		const result = await supervise(true);
		expect(result.code).toBe(125);
		expect(result.diagnostic).toContain("permission denied");
		expect(result.inspections).toBe(0);
	});
});
