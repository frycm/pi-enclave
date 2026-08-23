/**
 * pi's file-tool operations, backed by the sandboxed helper.
 *
 * Each of pi's six file tools accepts an operations object; supplying one moves
 * the actual `open`, `readdir` and `stat` calls inside the sandbox, where the
 * kernel decides. The alternative -- pi's defaults -- performs them in the pi
 * process, which is both unsandboxed and a check-then-open race if any policy
 * were layered on top.
 *
 * `find` is the subtle one. pi only spawns `fd` itself when no custom `glob` is
 * supplied (`find.ts:225`), so providing one is what keeps that search inside
 * the boundary rather than merely filtering its results afterwards.
 */
import type { FsClient } from "../backend/types.ts";
import { SandboxDenied } from "../backend/types.ts";

/**
 * Resolves the helper for the profile currently in force.
 *
 * A getter rather than a client, for the same reason the shell operations take
 * one: tools are registered at load time, before any profile is compiled, and a
 * client captured then would either fail immediately or -- worse, once
 * recompilation exists -- keep a tool bound to a retired helper still enforcing
 * an older profile.
 */
export type FsClientRef = () => FsClient;

/**
 * Translate a denial into a message the agent can act on.
 *
 * `SandboxDenied` carries a classified violation, which matters most on Linux:
 * the raw errno for a denied read is `ENOENT`, so surfacing it unchanged would
 * tell the agent a credential store simply does not exist and invite it to
 * create one.
 */
function describe(error: unknown): never {
	if (error instanceof SandboxDenied) {
		const { kind, path } = error.violation;
		throw new Error(`sandbox denied ${kind} of ${path ?? "path"} (this is a policy boundary, not a missing file)`);
	}
	throw error;
}

const guard = async <T>(run: () => Promise<T>): Promise<T> => {
	try {
		return await run();
	} catch (error) {
		return describe(error);
	}
};

export function createReadOperations(fs: FsClientRef) {
	return {
		readFile: (path: string) => guard(() => fs().readFile(path)),
		access: (path: string) => guard(() => fs().access(path, "read")),
		// Image detection reads the file's magic bytes, which the helper has
		// already returned; leaving it undefined lets pi fall back to its own
		// detection on the buffer rather than opening the file a second time
		// outside the sandbox.
	};
}

export function createEditOperations(fs: FsClientRef) {
	return {
		readFile: (path: string) => guard(() => fs().readFile(path)),
		writeFile: (path: string, content: string) => guard(() => fs().writeFile(path, content)),
		access: (path: string) => guard(() => fs().access(path, "write")),
	};
}

export function createWriteOperations(fs: FsClientRef) {
	return {
		writeFile: (path: string, content: string) => guard(() => fs().writeFile(path, content)),
		mkdir: (path: string) => guard(() => fs().mkdir(path)),
	};
}

export function createLsOperations(fs: FsClientRef) {
	return {
		exists: (path: string) => guard(() => fs().exists(path)),
		stat: (path: string) => guard(() => fs().stat(path)),
		readdir: (path: string) => guard(() => fs().readdir(path)),
	};
}

export function createFindOperations(fs: FsClientRef) {
	return {
		exists: (path: string) => guard(() => fs().exists(path)),
		// Supplying glob is what stops pi spawning `fd` in its own process.
		glob: (pattern: string, cwd: string, options: { ignore: string[]; limit: number }) =>
			guard(() => fs().glob(pattern, cwd, options)),
	};
}
