/**
 * Finding and reading the configuration files.
 *
 * Five sources, always visited in trust order, with two rules that matter more
 * than the plumbing:
 *
 * - **A missing file is not an error; an unreadable or malformed one is.** The
 *   zero-configuration case has to work, but a file that exists and cannot be
 *   parsed must never be treated as absent — that is how a syntax error becomes
 *   a silently wider sandbox.
 * - **Project files are read only when pi says the project is trusted.** pi
 *   already gates `.pi/extensions`, `.pi/skills` and the rest on the same
 *   answer, and a project the user has not trusted should not be tightening or
 *   loosening anything. An untrusted project's files are *reported* as ignored
 *   rather than passed over quietly, because a rule someone wrote and never saw
 *   applied is worse than one they know was skipped.
 */
import { lstatSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { getAgentDir } from "@earendil-works/pi-coding-agent";
import { SANDBOX_TMPDIR } from "../backend/types.ts";
import type { DefaultProfileOptions } from "./defaults.ts";
import { type FoldError, fold, formatFoldErrors } from "./merge.ts";
import { type Diagnostic, formatDiagnostics, parseDocument, parseEnvironment } from "./schema.ts";
import type { ConfigDocument, EffectiveProfile, Provenance, SourceId } from "./types.ts";
import { SOURCE_LABELS } from "./types.ts";

export interface LoadOptions {
	cwd: string;
	/** From `ctx.isProjectTrusted()`. Project files are skipped when false. */
	projectTrusted: boolean;
	env?: Record<string, string | undefined>;
	home?: string;
	tmp?: string;
	agentDir?: string;
	/** Injected by tests. Returns undefined for a missing file, throws otherwise. */
	readFile?: (path: string) => string | undefined;
	/** Injected by tests. Metadata only; undefined for a missing path. */
	statFile?: (path: string) => { size: number; regular: boolean } | undefined;
}

/**
 * A config file is tiny; anything larger is not one, and a repository-controlled
 * huge file must not be read into the privileged process to find that out.
 */
const MAX_CONFIG_BYTES = 1024 * 1024;

export interface LoadedSource {
	source: SourceId;
	path?: string;
	/** Set when the source exists but was deliberately not read. */
	ignored?: string;
}

export type LoadResult =
	| { ok: true; profile: EffectiveProfile; provenance: Provenance; sources: LoadedSource[] }
	| { ok: false; message: string; sources: LoadedSource[] };

/** Where each file lives. Exported so `/enclave status` can name them all. */
export function configPaths(options: Pick<LoadOptions, "cwd" | "agentDir">) {
	const agentDir = options.agentDir ?? getAgentDir();
	return {
		userGlobal: join(agentDir, "enclave.json"),
		projectLocal: join(options.cwd, ".pi", "enclave.local.json"),
		projectShared: join(options.cwd, ".pi", "enclave.json"),
	};
}

export function loadConfig(options: LoadOptions): LoadResult {
	const home = options.home ?? homedir();
	const tmp = options.tmp ?? SANDBOX_TMPDIR;
	const agentDir = options.agentDir ?? getAgentDir();
	const env = options.env ?? process.env;
	const defaults: DefaultProfileOptions = { cwd: options.cwd, home, tmp, agentDir, env };
	const paths = configPaths({ cwd: options.cwd, agentDir });
	const read = options.readFile ?? defaultReadFile;
	// Metadata only. In tests it is derived from the injected reader; in
	// production it is an `lstat`, so a repository-controlled FIFO, device, or
	// oversized file is never opened or read by the privileged process.
	const stat =
		options.statFile ??
		(options.readFile
			? (path: string) => {
					try {
						const content = options.readFile?.(path);
						return content === undefined ? undefined : { size: Buffer.byteLength(content), regular: true };
					} catch {
						return { size: 0, regular: false };
					}
				}
			: defaultStatFile);

	const sources: LoadedSource[] = [{ source: "builtin" }];
	const documents: ConfigDocument[] = [{ source: "builtin" }];
	const errors: string[] = [];

	const ingest = (source: SourceId, path: string) => {
		// Gate on metadata before reading: a non-regular file (FIFO/device/
		// symlink-to-one) or one larger than a config could ever be is refused
		// without ever being opened for content.
		const meta = stat(path);
		if (meta === undefined) return;
		if (!meta.regular) {
			errors.push(`pi-enclave: ${path} is not a regular file; refusing to read it.`);
			sources.push({ source, path, ignored: "not a regular file" });
			return;
		}
		if (meta.size > MAX_CONFIG_BYTES) {
			errors.push(`pi-enclave: ${path} is ${meta.size} bytes, larger than a config file can be; refusing to read it.`);
			sources.push({ source, path, ignored: "too large" });
			return;
		}

		let text: string | undefined;
		try {
			text = read(path);
		} catch (error) {
			errors.push(`pi-enclave: cannot read ${path}: ${(error as Error).message}`);
			sources.push({ source, path, ignored: "unreadable" });
			return;
		}
		if (text === undefined) return;
		sources.push({ source, path });

		let raw: unknown;
		try {
			raw = JSON.parse(text);
		} catch (error) {
			errors.push(`pi-enclave: ${path} is not valid JSON: ${(error as Error).message}`);
			return;
		}
		const parsed = parseDocument(raw, source, path, defaults);
		if (!parsed.ok) {
			errors.push(formatDiagnostics(source, path, parsed.errors));
			return;
		}
		documents.push(parsed.document);
	};

	ingest("user_global", paths.userGlobal);

	const environment = parseEnvironment(env);
	if (!environment.ok) {
		errors.push(formatDiagnostics("env", undefined, environment.errors));
	} else if (hasContent(environment.document)) {
		sources.push({ source: "env" });
		documents.push(environment.document);
	}

	for (const [source, path] of [
		["project_local", paths.projectLocal],
		["project_shared", paths.projectShared],
	] as const) {
		if (!options.projectTrusted) {
			// Metadata only -- an untrusted project's file is never read here, so a
			// FIFO or huge file cannot block the check. Only report it if present.
			if (stat(path) !== undefined) sources.push({ source, path, ignored: "project is not trusted" });
			continue;
		}
		ingest(source, path);
	}

	if (errors.length > 0) return { ok: false, message: errors.join("\n\n"), sources };

	const folded = fold(documents, defaults);
	if (!folded.ok) return { ok: false, message: formatFoldErrors(folded.errors), sources };

	return { ok: true, profile: folded.profile, provenance: folded.provenance, sources };
}

function hasContent(document: ConfigDocument): boolean {
	return document.patch !== undefined || document.profile !== undefined || document.auto !== undefined;
}

function defaultReadFile(path: string): string | undefined {
	try {
		return readFileSync(path, "utf8");
	} catch (error) {
		if ((error as NodeJS.ErrnoException).code === "ENOENT") return undefined;
		throw error;
	}
}

/** `lstat`-based metadata: never follows a symlink into a device or FIFO. */
function defaultStatFile(path: string): { size: number; regular: boolean } | undefined {
	try {
		const stats = lstatSync(path);
		return { size: stats.size, regular: stats.isFile() };
	} catch (error) {
		if ((error as NodeJS.ErrnoException).code === "ENOENT") return undefined;
		// An unreadable stat is reported as present-but-not-regular, so the
		// caller refuses rather than assuming it is fine.
		return { size: 0, regular: false };
	}
}

/** One line per source, for `/enclave status`. */
export function renderSources(sources: readonly LoadedSource[]): string {
	return sources
		.map((entry) => {
			const where = entry.path ?? SOURCE_LABELS[entry.source];
			return entry.ignored ? `  ignored  ${where} (${entry.ignored})` : `  applied  ${where}`;
		})
		.join("\n");
}

export type { Diagnostic, FoldError };
