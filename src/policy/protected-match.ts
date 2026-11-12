/**
 * `rules.protectedPaths` at L1: which paths an action writes that a pattern
 * protects (#72).
 *
 * Comparing each written operand with the patterns is enough for a pattern
 * whose every route has to name it: `**\/AGENTS.md` is reached only by a path
 * ending in `AGENTS.md`, `**\/.husky/**` and `infra/**` only through a path
 * that names `.husky` or `infra`. A pattern with more than one segment whose
 * first segment is not protected itself (`**\/.github/workflows/**`,
 * `**\/.vscode/tasks.json`, a user-global `deploy/prod/*.yml`) has an ordinary
 * ancestor, and a command can change the protected file through it without
 * naming it:
 *
 * - by moving or removing the ancestor (`mv .github gh2`, `rm -rf deploy`);
 * - by moving or copying a tree into place (`mv gh2 .github`,
 *   `cp -r s/workflows .github/`);
 * - by giving it a second name (`cp -al .github gh-backup`), which a later
 *   write then changes without naming the protected path at all.
 *
 * For those patterns a directory operand of `rm`, `mv`, `cp` and `ln` is
 * looked into, a copy or move is checked for what it would create, and a
 * write to a file with more than one hard link asks. All of these are asks,
 * whichever list the pattern is in: the operand holds a protected path, and a
 * person decides. A write that names a protected path is matched as before.
 */
import { lstatSync, statSync } from "node:fs";
import { basename, join, relative } from "node:path";
import { PROTECTED_WALK_LIMIT, protectedPathMatcher } from "../gate/protected-writes.ts";
import { PersistenceScanError, scanRoots } from "../persistence/scan.ts";
import type { CanonicalAction } from "./canonical.ts";
import type { RuleMatch } from "./match.ts";
import { globToRegExp, matchesPathPattern, normalizeInputPath, resolveForPolicy } from "./paths.ts";
import type { SimpleCommand } from "./shell.ts";

export interface ProtectedMatchOptions {
	/** Where the patterns are anchored. */
	cwd: string;
	home: string;
	/** Both lists: which patterns have an ordinary ancestor depends on all of them. */
	rules: { deny: readonly string[]; ask: readonly string[] };
	maxEntries?: number;
}

/**
 * The patterns with an ordinary ancestor: more than one segment, and a first
 * segment no protected pattern covers by itself. Each comes with its literal
 * leading segments, as globs, for {@link couldHold}.
 */
export function ancestorPatterns(
	rules: ProtectedMatchOptions["rules"],
	cwd: string,
): { pattern: string; segments: RegExp[] }[] {
	const all = [...rules.deny, ...rules.ask];
	const out: { pattern: string; segments: RegExp[] }[] = [];
	for (const pattern of all) {
		const segments = pattern.replace(/^(?:\*\*\/)+/, "").split("/");
		if (segments.length < 2) continue;
		const first = segments[0] as string;
		if (first === "**") continue;
		// Covered: the first segment is protected by itself, so every route to
		// the pattern names a protected path.
		if (!/[*?[]/.test(first) && matchesPathPattern(all, join(cwd, first), cwd) !== undefined) continue;
		const leading: RegExp[] = [];
		for (const segment of segments) {
			if (segment === "**") break;
			leading.push(globToRegExp(segment));
		}
		out.push({ pattern, segments: leading });
	}
	return out;
}

/** Could `path` be, or be an ancestor of, a location an ancestor pattern names? */
function couldHold(path: string, patterns: { pattern: string; segments: RegExp[] }[]): string | undefined {
	const names = path.split("/").filter((name) => name !== "");
	for (const { pattern, segments } of patterns) {
		// The last k names of the path are the pattern's first k segments.
		for (let k = 1; k <= Math.min(segments.length, names.length); k++) {
			const tail = names.slice(names.length - k);
			if (tail.every((name, i) => segments[i]?.test(name))) return pattern;
		}
	}
	return undefined;
}

class Found extends Error {
	constructor(readonly match: RuleMatch) {
		super("found");
	}
}

/** Commands whose operands this module reads by role. */
type Role = {
	sources: string[];
	destination?: string;
	removes: boolean;
	links: boolean;
	/** `-T`: the destination is the new name, never a directory to go into. */
	noTargetDirectory?: true;
	/** `-t`: the destination is a directory to go into. */
	intoDirectory?: true;
};

/** Option letters of `cp`, `mv` and `ln` that take a separate value. */
const VALUE_OPTIONS: Record<string, string> = { cp: "St", mv: "St", ln: "St" };

/** Sources and destination of a `cp`, `mv`, `ln`, `rm` or `rmdir`, or undefined for anything else. */
function roles(command: SimpleCommand): Role | undefined {
	const name = command.name.slice(command.name.lastIndexOf("/") + 1);
	if (!["cp", "mv", "ln", "rm", "rmdir"].includes(name)) return undefined;
	const operands: string[] = [];
	let target: string | undefined;
	let links = name === "ln";
	let symbolic = false;
	let noTargetDirectory = false;
	let endOfOptions = false;
	for (let i = 0; i < command.args.length; i++) {
		const arg = command.args[i] as string;
		if (endOfOptions || arg === "-" || !arg.startsWith("-")) {
			operands.push(arg);
			continue;
		}
		if (arg === "--") {
			endOfOptions = true;
			continue;
		}
		if (arg.startsWith("--")) {
			const [flag, value] = arg.split("=", 2) as [string, string | undefined];
			if (flag === "--target-directory") target = value ?? command.args[++i];
			else if (flag === "--link") links = true;
			else if (flag === "--no-target-directory") noTargetDirectory = true;
			else if (flag === "--symbolic" || flag === "--symbolic-link") symbolic = true;
			else if (value === undefined && (flag === "--suffix" || flag === "--backup")) {
				// `--suffix X` takes a value; `--backup` takes one only with `=`.
				if (flag === "--suffix") i++;
			}
			continue;
		}
		// Clustered short options: `-al`, `-t dir`, `-tdir`.
		const letters = arg.slice(1);
		for (let j = 0; j < letters.length; j++) {
			const letter = letters[j] as string;
			if (letter === "l" && name === "cp") links = true;
			if (letter === "s") symbolic = true;
			if (letter === "T") noTargetDirectory = true;
			if ((VALUE_OPTIONS[name] ?? "").includes(letter)) {
				const value = letters.slice(j + 1) || command.args[++i];
				if (letter === "t") target = value;
				break;
			}
		}
	}
	if (name === "rm" || name === "rmdir") return { sources: operands, removes: true, links: false };
	if (name === "ln" && symbolic) links = false;
	const removes = name === "mv";
	if (target !== undefined) return { sources: operands, destination: target, removes, links, intoDirectory: true };
	if (operands.length < 2) return { sources: operands, removes, links };
	return {
		sources: operands.slice(0, -1),
		destination: operands.at(-1) as string,
		removes,
		links,
		...(noTargetDirectory ? { noTargetDirectory: true as const } : {}),
	};
}

/**
 * Every protected match of one list for an action.
 *
 * `deny` returns the direct matches only. `ask` adds what a directory
 * operand, a copy or move into place, or a second hard link reaches.
 */
export function protectedMatches(
	action: CanonicalAction,
	patterns: readonly string[],
	list: "deny" | "ask",
	options: ProtectedMatchOptions,
): RuleMatch[] {
	const matches: RuleMatch[] = [];
	// Only writes are escalated. A read of `infra/main.tf` is not the thing the
	// rule is about, and escalating it would make the list unusable in any
	// repository where the agent has to look at what it may not change.
	for (const path of action.paths) {
		if (!path.writes) continue;
		const pattern = matchesPathPattern(patterns, path.resolved, options.cwd);
		if (pattern) matches.push({ list: "ask", pattern, target: path.resolved });
	}
	if (list !== "ask") return matches;
	try {
		derivedMatches(action, options);
	} catch (error) {
		if (error instanceof Found) matches.push(error.match);
		else throw error;
	}
	return matches;
}

/** Throws {@link Found} with the first match a directory operand, a copy or a hard link reaches. */
function derivedMatches(action: CanonicalAction, options: ProtectedMatchOptions): void {
	const found = (pattern: string, target: string): never => {
		throw new Found({ list: "ask", pattern, target });
	};
	const resolve = (raw: string) => resolveForPolicy(normalizeInputPath(raw, options.home), options.cwd).resolved;

	// A write to a file with another name may change a protected file through
	// that name; finding the other names would mean walking every root.
	const hardLinked = (path: string) => {
		try {
			const stats = statSync(path);
			if (stats.isFile() && stats.nlink > 1) found(`(a file with ${stats.nlink} hard links)`, path);
		} catch (error) {
			if (error instanceof Found) throw error;
		}
	};
	if (!action.shell) {
		for (const path of action.paths) if (path.writes) hardLinked(path.resolved);
		return;
	}

	const ancestors = ancestorPatterns(options.rules, options.cwd);
	const matcher = protectedPathMatcher(
		ancestors.map((entry) => entry.pattern),
		options.cwd,
	);
	const limit = options.maxEntries ?? PROTECTED_WALK_LIMIT;
	const isDir = (path: string) => {
		try {
			return lstatSync(path).isDirectory();
		} catch {
			return false;
		}
	};
	const exists = (path: string) => {
		try {
			lstatSync(path);
			return true;
		} catch {
			return false;
		}
	};
	const firstMatch = (pattern: string, path: string) =>
		matchesPathPattern(
			ancestors.map((entry) => entry.pattern),
			path,
			options.cwd,
		) ?? pattern;
	/** Walk below a directory, calling `visit` with each entry's path; past the bound, ask. */
	const walk = (dir: string, visit: (path: string) => void) => {
		try {
			scanRoots([dir], {
				match: (_name, _kind, path) => {
					visit(path);
					return false;
				},
				maxEntries: limit,
			});
		} catch (error) {
			if (error instanceof PersistenceScanError) {
				found(`(more than ${limit} entries to check)`, dir);
			}
			throw error;
		}
	};
	// Earlier commands in the same line may create or change what a later one
	// moves, so a line of several commands is judged by where it moves to.
	const severalCommands = action.shell.commands.length > 1;

	for (const command of action.shell.commands) {
		for (const redirect of command.redirects) if (redirect.writes) hardLinked(resolve(redirect.target));
		const name = command.name.slice(command.name.lastIndexOf("/") + 1);
		if (name === "tee" || name === "truncate") {
			for (const arg of command.args) if (!arg.startsWith("-")) hardLinked(resolve(arg));
		}
		if (name === "dd") {
			for (const arg of command.args) {
				const of = /^of=(.+)$/.exec(arg);
				if (of?.[1]) hardLinked(resolve(of[1]));
			}
		}
		const role = roles(command);
		if (!role || ancestors.length === 0) {
			// The hard-link check of a copy's destination needs no patterns.
			if (role?.destination !== undefined && name === "cp") cpDestination(role);
			continue;
		}
		const sources = role.sources.map(resolve);
		// Moving, removing or linking a tree takes what it holds with it.
		if (role.removes || role.links) {
			for (const source of sources) {
				if (!isDir(source)) continue;
				walk(source, (path) => {
					if (matcher(path)) found(firstMatch("", path), path);
				});
			}
		}
		if (role.destination === undefined || name === "rm" || name === "rmdir") continue;
		const destination = resolve(role.destination);
		for (const source of sources) {
			// What the copy or move would create: `dest/name/rel` when it goes
			// inside an existing directory, `dest/rel` when it takes that name.
			// When an earlier command may create the directory, both.
			const inside = role.intoDirectory || (!role.noTargetDirectory && (severalCommands || isDir(destination)));
			const replaces = !role.intoDirectory && (role.noTargetDirectory || severalCommands || !isDir(destination));
			const created = (rel: string) => [
				...(replaces ? [join(destination, rel)] : []),
				...(inside ? [join(destination, basename(source), rel)] : []),
			];
			for (const path of created("")) {
				if (matcher(path)) found(firstMatch("", path), path);
				if (severalCommands || !exists(source)) {
					const pattern = couldHold(relative(options.cwd, path) || ".", ancestors);
					if (pattern) found(pattern, path);
				}
			}
			if (isDir(source)) {
				walk(source, (path) => {
					for (const target of created(relative(source, path))) {
						if (matcher(target)) found(firstMatch("", target), target);
					}
				});
			}
		}
		if (name === "cp") cpDestination(role);
	}

	function cpDestination(role: Role) {
		if (role.destination === undefined) return;
		const destination = resolve(role.destination);
		// `cp` overwrites an existing file in place, inode and all.
		hardLinked(destination);
		for (const source of role.sources) hardLinked(join(destination, basename(resolve(source))));
	}
}
