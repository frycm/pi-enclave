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
import { detectImageMimeType, IMAGE_SNIFF_BYTES } from "./image-mime.ts";

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
 * Asked again, here, whether this operation may run.
 *
 * See the note on the shell operations: pi prepares a whole batch before
 * executing any of it, so the gate's decision can be overtaken by a breaker
 * trip. Throwing refuses the operation. Absent in Phase 1's tests and in the
 * benchmark, where there is no gate to have passed.
 */
export type ToolGuard = (tool: string, path: string) => void;

function guarded(guard: ToolGuard | undefined, tool: string, path: string): void {
	guard?.(tool, path);
}

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

const protect = async <T>(run: () => Promise<T>): Promise<T> => {
	try {
		return await run();
	} catch (error) {
		return describe(error);
	}
};

export function createReadOperations(fs: FsClientRef, guard?: ToolGuard) {
	return {
		readFile: (path: string) => {
			guarded(guard, "read", path);
			return protect(() => fs().readFile(path));
		},
		access: (path: string) => {
			guarded(guard, "read", path);
			return protect(() => fs().access(path, "read"));
		},
		// pi does not fall back to sniffing the buffer when this is absent: it
		// decodes the bytes as text. So the magic bytes are fetched through the
		// helper -- the open stays inside the sandbox -- and judged by pi's own
		// detector on this side.
		detectImageMimeType: (path: string) => {
			guarded(guard, "read", path);
			return protect(async () => detectImageMimeType(await fs().head(path, IMAGE_SNIFF_BYTES)));
		},
	};
}

export function createEditOperations(fs: FsClientRef, guard?: ToolGuard) {
	return {
		readFile: (path: string) => {
			guarded(guard, "edit", path);
			return protect(() => fs().readFile(path));
		},
		writeFile: (path: string, content: string) => {
			guarded(guard, "edit", path);
			return protect(() => fs().writeFile(path, content));
		},
		access: (path: string) => {
			guarded(guard, "edit", path);
			return protect(() => fs().access(path, "write"));
		},
	};
}

export function createWriteOperations(fs: FsClientRef, guard?: ToolGuard) {
	return {
		writeFile: (path: string, content: string) => {
			guarded(guard, "write", path);
			return protect(() => fs().writeFile(path, content));
		},
		// `mkdir` is guarded against the *file* path the action named: pi creates
		// the parent directory of a write target, so the directory itself never
		// appears in the tool input and would never be in the table.
		mkdir: (path: string) => protect(() => fs().mkdir(path)),
	};
}

export function createLsOperations(fs: FsClientRef, guard?: ToolGuard) {
	return {
		exists: (path: string) => protect(() => fs().exists(path)),
		stat: (path: string) => protect(() => fs().stat(path)),
		readdir: (path: string) => {
			guarded(guard, "ls", path);
			return protect(() => fs().readdir(path));
		},
	};
}

export function createFindOperations(fs: FsClientRef, guard?: ToolGuard) {
	return {
		exists: (path: string) => protect(() => fs().exists(path)),
		// Supplying glob is what stops pi spawning `fd` in its own process.
		glob: (pattern: string, cwd: string, options: { ignore: string[]; limit: number }) => {
			guarded(guard, "find", cwd);
			return protect(() => fs().glob(pattern, cwd, options));
		},
	};
}
