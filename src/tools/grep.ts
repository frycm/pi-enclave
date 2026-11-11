/**
 * pi's grep executor, with rg running inside the sandboxed filesystem helper.
 * The schema and rendering stay upstream; this mirrors the pinned pi 1.5.2
 * JSON/context protocol without spawning rg or opening matched files in pi.
 */
import { basename, relative, resolve } from "node:path";
import { DEFAULT_MAX_BYTES, formatSize, truncateHead, truncateLine } from "@earendil-works/pi-coding-agent";
import type { FsClient } from "../backend/types.ts";
import { SandboxDenied } from "../backend/types.ts";

/** Private upstream constant, pinned with its artifact in upstream-drift.test.ts. */
const DEFAULT_LIMIT = 100;
/** Bound caller-controlled metadata even before output formatting. */
const MAX_MATCH_LIMIT = 10_000;
const GREP_MAX_LINE_LENGTH = 500;

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

interface RipgrepLine {
	filePath: string;
	lineNumber: number;
	lineText: string;
	isMatch: boolean;
}

/** Decode ripgrep's JSON wire values, including non-UTF-8 paths and contents. */
function decodeRgText(value: { text?: string; bytes?: string } | undefined): string {
	if (typeof value?.text === "string") return value.text;
	if (typeof value?.bytes === "string") return Buffer.from(value.bytes, "base64").toString("utf8");
	return "";
}

/** Select matches and their context; only an additional match proves truncation. */
export function parseRipgrepJson(stdout: string, limit: number, context = 0) {
	const matches: RipgrepLine[] = [];
	let matchCount = 0;
	let limitReached = false;
	let lastFile: string | undefined;
	let trailingEnd = 0;
	for (const line of stdout.split("\n")) {
		let event: {
			type?: string;
			data?: {
				path?: { text?: string; bytes?: string };
				line_number?: number;
				lines?: { text?: string; bytes?: string };
			};
		};
		try {
			event = JSON.parse(line);
		} catch {
			continue;
		}
		if (event.type !== "match" && event.type !== "context") continue;
		const filePath = decodeRgText(event.data?.path);
		const lineNumber = event.data?.line_number;
		if (!filePath || typeof lineNumber !== "number") continue;
		let isMatch = event.type === "match";
		if (matchCount >= limit) {
			const inWindow = filePath === lastFile && lineNumber <= trailingEnd;
			if (isMatch) limitReached = true;
			if (!inWindow) {
				if (limitReached) break;
				continue;
			}
			isMatch = false;
		} else if (isMatch) {
			matchCount++;
			lastFile = filePath;
			trailingEnd = lineNumber + context;
		}
		matches.push({ filePath, lineNumber, lineText: decodeRgText(event.data?.lines), isMatch });
	}
	return { matches, matchCount, limitReached };
}

export interface SandboxedGrepOptions {
	fs: FsClient;
	cwd: string;
	signal?: AbortSignal;
}

/** Bound the entire parent-side parsing/formatting lifetime, not only the child. */
export class GrepExecutionQueue {
	private tail: Promise<void> = Promise.resolve();

	async run<T>(task: () => Promise<T>, signal?: AbortSignal): Promise<T> {
		const predecessor = this.tail;
		let release!: () => void;
		this.tail = new Promise<void>((resolve) => {
			release = resolve;
		});
		await predecessor;
		try {
			if (signal?.aborted) throw new Error("Operation aborted");
			return await task();
		} finally {
			release();
		}
	}
}

/** Search and obtain context entirely inside L2, then format the bounded result. */
export async function runSandboxedGrep(options: SandboxedGrepOptions, args: GrepArgs): Promise<GrepOutcome> {
	const { fs, cwd, signal } = options;
	const searchPath = resolve(cwd, args.path ?? ".");
	const requestedLimit =
		args.limit !== undefined && Number.isFinite(args.limit) ? Math.max(1, Math.floor(args.limit)) : DEFAULT_LIMIT;
	const limit = Math.min(requestedLimit, MAX_MATCH_LIMIT);
	const context = args.context && args.context > 0 ? Math.min(Math.floor(args.context), Number.MAX_SAFE_INTEGER) : 0;
	const rgArgs = ["--no-config", "--json", "--line-number", "--color=never", "--hidden"];
	if (args.ignoreCase) rgArgs.push("--ignore-case");
	if (args.literal) rgArgs.push("--fixed-strings");
	if (args.glob) rgArgs.push("--glob", args.glob.replace(/^(!?)(?:\.\/)+/, "$1"));
	if (context > 0) rgArgs.push("--context", String(context));
	rgArgs.push("--", args.pattern, searchPath);

	let stdout: string;
	let directory: boolean;
	let capped = false;
	try {
		directory = (await fs.stat(searchPath)).isDirectory();
		({ stdout, capped = false } = await fs.grep(rgArgs, {
			limit,
			context,
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

	const { matches, matchCount, limitReached } = parseRipgrepJson(stdout, limit, context);
	if (matchCount === 0) return { content: [{ type: "text", text: "No matches found" }] };
	let linesTruncated = false;
	const output: string[] = [];
	let outputBytes = 0;
	for (const match of matches) {
		const path = relative(searchPath, resolve(searchPath, match.filePath));
		const shown = directory && path && !path.startsWith("..") ? path.replace(/\\/g, "/") : basename(match.filePath);
		const { text, wasTruncated } = truncateLine(match.lineText.replace(/\r?\n?$/, ""));
		if (wasTruncated) linesTruncated = true;
		const line = match.isMatch ? `${shown}:${match.lineNumber}: ${text}` : `${shown}-${match.lineNumber}- ${text}`;
		if (outputBytes - 1 <= DEFAULT_MAX_BYTES) output.push(line);
		outputBytes += Buffer.byteLength(line, "utf8") + 1;
	}
	const truncation = truncateHead(output.join("\n"), { maxLines: Number.MAX_SAFE_INTEGER });
	truncation.totalLines = matches.length;
	truncation.totalBytes = outputBytes - 1;
	let text = truncation.content;
	const notices: string[] = [];
	const details: GrepOutcome["details"] = {};
	if (limitReached) {
		notices.push(`${limit} matches limit reached. Use limit=${limit * 2} for more, or refine pattern`);
		details.matchLimitReached = limit;
	}
	if (truncation.truncated) {
		notices.push(`${formatSize(DEFAULT_MAX_BYTES)} limit reached`);
		details.truncation = truncation;
	}
	if (capped) notices.push("search output limit reached inside the sandbox; refine the pattern or path");
	if (linesTruncated) {
		notices.push(`Some lines truncated to ${GREP_MAX_LINE_LENGTH} chars. Use read tool to see full lines`);
		details.linesTruncated = true;
	}
	if (notices.length > 0) text += `\n\n[${notices.join(". ")}]`;
	return { content: [{ type: "text", text }], ...(Object.keys(details).length > 0 ? { details } : {}) };
}
