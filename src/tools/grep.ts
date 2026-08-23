/**
 * `grep`, with the search running inside the sandbox.
 *
 * pi's grep is the one file tool its operations object cannot redirect. The
 * interface abstracts the filesystem walk, but the tool
 * [spawns `rg` itself](https://github.com/earendil-works/pi/blob/c49906ec77788625aacbdc53ebca6fbe65bd20f5/packages/coding-agent/src/core/tools/grep.ts#L175-L226)
 * from the pi process -- so a `grep` over a credential directory would read it
 * with the user's full privileges no matter what profile is in force.
 *
 * Rather than copy pi's four hundred lines, this keeps pi's tool object whole --
 * schema, description, renderers, prompt snippet -- and replaces only `execute`.
 * Less to keep in step on a baseline bump, and the parts users see stay
 * byte-identical to the built-in tool.
 *
 * The observable contract is what the tests pin: `path:line: text` for a match,
 * `path-line- text` for a context line, and pi's own truncation notices.
 */
import { relative } from "node:path";
import { DEFAULT_MAX_BYTES, formatSize, truncateHead, truncateLine } from "@earendil-works/pi-coding-agent";
import type { FsClient } from "../backend/types.ts";
import { SandboxDenied } from "../backend/types.ts";

/**
 * Mirrors pi's private `DEFAULT_LIMIT` (grep.ts:44). Duplicated because it is
 * not exported; `test/unit/upstream-drift.test.ts` fails when pi's value or its
 * grep artifact changes, so the copy cannot drift silently.
 */
const DEFAULT_LIMIT = 100;

export interface GrepArgs {
	pattern: string;
	path?: string;
	glob?: string;
	ignoreCase?: boolean;
	literal?: boolean;
	context?: number;
	limit?: number;
}

export interface GrepOutcome {
	content: [{ type: "text"; text: string }];
	details?: { truncation?: unknown; matchLimitReached?: number; linesTruncated?: boolean };
	isError?: boolean;
}

interface RipgrepMatch {
	filePath: string;
	lineNumber: number;
}

/** Parse ripgrep's `--json` stream, stopping at the match limit. */
export function parseRipgrepJson(stdout: string, limit: number): { matches: RipgrepMatch[]; limitReached: boolean } {
	const matches: RipgrepMatch[] = [];
	for (const line of stdout.split("\n")) {
		if (!line.trim()) continue;
		if (matches.length >= limit) return { matches, limitReached: true };
		let event: { type?: string; data?: { path?: { text?: string }; line_number?: number } };
		try {
			event = JSON.parse(line);
		} catch {
			continue;
		}
		if (event.type !== "match") continue;
		const filePath = event.data?.path?.text;
		const lineNumber = event.data?.line_number;
		if (filePath && typeof lineNumber === "number") matches.push({ filePath, lineNumber });
	}
	return { matches, limitReached: matches.length >= limit };
}

export interface SandboxedGrepOptions {
	fs: FsClient;
	cwd: string;
	signal?: AbortSignal;
}

/**
 * Run a search entirely inside the sandbox and format it the way pi does.
 *
 * Context lines are read back through the helper too. Reading them in the pi
 * process would reopen the exact hole this module exists to close: `rg` would be
 * confined while the surrounding lines it reported were fetched with full
 * privileges.
 */
export async function runSandboxedGrep(options: SandboxedGrepOptions, args: GrepArgs): Promise<GrepOutcome> {
	const { fs, cwd, signal } = options;
	const searchPath = args.path ?? cwd;
	const limit = args.limit && args.limit > 0 ? args.limit : DEFAULT_LIMIT;
	const context = args.context && args.context > 0 ? args.context : 0;

	const rgArgs = ["--json", "--line-number", "--color=never", "--hidden"];
	if (args.ignoreCase) rgArgs.push("--ignore-case");
	if (args.literal) rgArgs.push("--fixed-strings");
	if (args.glob) rgArgs.push("--glob", args.glob);
	rgArgs.push("--", args.pattern, searchPath);

	let stdout: string;
	let capped = false;
	try {
		// The limit travels with the request so rg is stopped at the limit inside
		// the sandbox, rather than buffering everything it would ever print.
		({ stdout, capped = false } = await fs.grep(rgArgs, {
			limit,
			path: searchPath,
			...(signal ? { signal } : {}),
		}));
	} catch (error) {
		if (error instanceof SandboxDenied) {
			return {
				content: [{ type: "text", text: `sandbox denied search of ${error.violation.path ?? searchPath}` }],
				isError: true,
			};
		}
		throw error;
	}

	const { matches, limitReached } = parseRipgrepJson(stdout, limit);
	if (matches.length === 0) return { content: [{ type: "text", text: "No matches found" }] };

	// One read per file rather than per match: a pattern hitting forty lines of
	// one file would otherwise cost forty round trips through the helper.
	const fileCache = new Map<string, string[]>();
	const linesFor = async (path: string): Promise<string[]> => {
		const cached = fileCache.get(path);
		if (cached) return cached;
		let lines: string[] = [];
		try {
			lines = (await fs.readFile(path)).toString("utf8").split("\n");
		} catch {
			// A file rg could see but the helper cannot read is reported inline
			// rather than failing the whole search.
		}
		fileCache.set(path, lines);
		return lines;
	};

	let linesTruncated = false;
	const output: string[] = [];

	for (const match of matches) {
		const shown = relative(cwd, match.filePath) || match.filePath;
		const lines = await linesFor(match.filePath);
		if (lines.length === 0) {
			output.push(`${shown}:${match.lineNumber}: (unable to read file)`);
			continue;
		}
		const start = context > 0 ? Math.max(1, match.lineNumber - context) : match.lineNumber;
		const end = context > 0 ? Math.min(lines.length, match.lineNumber + context) : match.lineNumber;
		for (let current = start; current <= end; current++) {
			const raw = (lines[current - 1] ?? "").replace(/\r/g, "");
			const { text, wasTruncated } = truncateLine(raw);
			if (wasTruncated) linesTruncated = true;
			output.push(current === match.lineNumber ? `${shown}:${current}: ${text}` : `${shown}-${current}- ${text}`);
		}
	}

	const truncation = truncateHead(output.join("\n"), { maxBytes: DEFAULT_MAX_BYTES });
	let text = truncation.content;
	const notices: string[] = [];
	const details: GrepOutcome["details"] = {};

	if (limitReached) {
		notices.push(`${limit} match limit reached`);
		details.matchLimitReached = limit;
	}
	if (truncation.truncated) {
		notices.push(`${formatSize(DEFAULT_MAX_BYTES)} limit reached`);
		details.truncation = truncation;
	}
	if (capped) notices.push("search output limit reached inside the sandbox; refine the pattern or path");
	if (linesTruncated) details.linesTruncated = true;
	if (notices.length > 0) text += `\n\n[${notices.join(". ")}]`;

	return {
		content: [{ type: "text", text }],
		...(Object.keys(details).length > 0 ? { details } : {}),
	};
}
