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
import { readFileSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";
import { getAgentDir } from "@earendil-works/pi-coding-agent";
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
}

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
	const tmp = options.tmp ?? tmpdir();
	const agentDir = options.agentDir ?? getAgentDir();
	const env = options.env ?? process.env;
	const defaults: DefaultProfileOptions = { cwd: options.cwd, home, tmp, agentDir };
	const paths = configPaths({ cwd: options.cwd, agentDir });
	const read = options.readFile ?? defaultReadFile;

	const sources: LoadedSource[] = [{ source: "builtin" }];
	const documents: ConfigDocument[] = [{ source: "builtin" }];
	const errors: string[] = [];

	const ingest = (source: SourceId, path: string) => {
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
			// Only report it if it is actually there; otherwise every untrusted
			// project would list two files that do not exist.
			if (exists(read, path)) sources.push({ source, path, ignored: "project is not trusted" });
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

function exists(read: (path: string) => string | undefined, path: string): boolean {
	try {
		return read(path) !== undefined;
	} catch {
		return true;
	}
}

function defaultReadFile(path: string): string | undefined {
	try {
		return readFileSync(path, "utf8");
	} catch (error) {
		if ((error as NodeJS.ErrnoException).code === "ENOENT") return undefined;
		throw error;
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
