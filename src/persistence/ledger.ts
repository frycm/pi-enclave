/**
 * Tripwire hits that nobody has acknowledged yet, kept across sessions.
 *
 * A hit is shown once and then becomes the baseline, and the next session's
 * profile write-protects whatever was planted without comment. In an
 * unattended session nobody sees that one notice. So every hit is also
 * written here, in the state directory outside every writable root, and
 * repeated at each `session_start` until the user runs
 * `/enclave tripwire ack`.
 */
import { createHash } from "node:crypto";
import { readFileSync, renameSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { ensureSecureDir } from "../state/dir.ts";
import type { SurfaceKind } from "./agent.ts";
import type { TripwireChange, TripwireHit } from "./tripwire.ts";

export interface LedgerEntry {
	path: string;
	change: TripwireChange;
	kind: SurfaceKind;
	/** When it was first seen, ISO 8601. */
	at: string;
	/** Whether only the agent's turn can have made it. */
	agent: boolean;
	detail?: string;
}

/**
 * Room for project-file entries. Git, pi configuration and unverifiable
 * entries are never dropped: they are the reason the ledger exists, and an
 * agent that edits hundreds of `.envrc` files must not be able to push a
 * planted `.pi` out of it. Project-file entries make room, oldest first, and
 * are counted when they do.
 */
const MAX_ENTRIES = 500;

export interface LedgerState {
	entries: LedgerEntry[];
	/** Project-file entries dropped to stay within {@link MAX_ENTRIES}. */
	droppedProject: number;
}

const isKept = (entry: LedgerEntry) => entry.kind !== "project" || entry.change === "unverifiable";

function isEntry(value: unknown): value is LedgerEntry {
	if (typeof value !== "object" || value === null) return false;
	const entry = value as Record<string, unknown>;
	return typeof entry.path === "string" && typeof entry.change === "string" && typeof entry.at === "string";
}

export class TripwireLedger {
	constructor(private readonly file: string) {}

	/** One file per workspace, named by a hash of its path. */
	static forWorkspace(stateRoot: string, workspace: string): TripwireLedger {
		const name = createHash("sha256").update(workspace).digest("hex").slice(0, 16);
		return new TripwireLedger(join(stateRoot, "tripwire", `${name}.json`));
	}

	/** The unacknowledged hits, oldest first. */
	read(): LedgerEntry[] {
		return this.state().entries;
	}

	/**
	 * The hits and how many project-file entries were dropped. A ledger that
	 * cannot be parsed is itself reported, rather than read as empty.
	 */
	state(): LedgerState {
		let text: string;
		try {
			text = readFileSync(this.file, "utf8");
		} catch (error) {
			if ((error as NodeJS.ErrnoException).code === "ENOENT") return { entries: [], droppedProject: 0 };
			throw error;
		}
		try {
			const parsed = JSON.parse(text) as { entries?: unknown; droppedProject?: unknown };
			if (Array.isArray(parsed.entries) && parsed.entries.every(isEntry)) {
				const dropped = typeof parsed.droppedProject === "number" ? parsed.droppedProject : 0;
				return { entries: parsed.entries, droppedProject: dropped };
			}
		} catch {
			// Reported below.
		}
		return {
			entries: [
				{
					path: this.file,
					change: "unverifiable",
					kind: "git",
					at: new Date(0).toISOString(),
					agent: false,
					detail: "the tripwire ledger is unreadable; earlier hits may be lost",
				},
			],
			droppedProject: 0,
		};
	}

	/** Adds hits, keeping the first sighting of each path and change. */
	add(hits: readonly TripwireHit[], agent: boolean, at = new Date()): void {
		if (hits.length === 0) return;
		const state = this.state();
		const entries = state.entries.filter((entry) => entry.path !== this.file);
		const known = new Set(entries.map((entry) => `${entry.change}\0${entry.path}`));
		for (const hit of hits) {
			const key = `${hit.change}\0${hit.path}`;
			if (known.has(key)) continue;
			known.add(key);
			entries.push({
				path: hit.path,
				change: hit.change,
				kind: hit.kind ?? "git",
				at: at.toISOString(),
				agent,
				...(hit.detail ? { detail: hit.detail } : {}),
			});
		}
		const room = Math.max(0, MAX_ENTRIES - entries.filter(isKept).length);
		const project = entries.filter((entry) => !isKept(entry));
		const dropped = new Set(project.slice(0, Math.max(0, project.length - room)));
		this.write({
			entries: entries.filter((entry) => !dropped.has(entry)),
			droppedProject: state.droppedProject + dropped.size,
		});
	}

	/** Forgets every hit; returns how many there were. */
	clear(): number {
		const { entries, droppedProject } = this.state();
		const count = entries.length + droppedProject;
		if (count > 0) this.write({ entries: [], droppedProject: 0 });
		return count;
	}

	private write(state: LedgerState): void {
		const dir = join(this.file, "..");
		ensureSecureDir(dir);
		const temp = `${this.file}.${process.pid}.tmp`;
		writeFileSync(temp, `${JSON.stringify(state, null, "\t")}\n`, { mode: 0o600 });
		renameSync(temp, this.file);
	}
}

const ORDER = ["unverifiable", "agent", "git", "project"] as const;
const LABELS: Record<(typeof ORDER)[number], string> = {
	unverifiable: "could not be checked",
	agent: "pi configuration",
	git: "Git configuration or hooks",
	project: "project files",
};
const group = (entry: LedgerEntry): (typeof ORDER)[number] =>
	entry.change === "unverifiable" ? "unverifiable" : entry.kind;

/**
 * The reminder shown at session start, or `undefined` when there is none:
 * counts per kind, then the entries most worth reading first, unverifiable,
 * pi configuration and Git before project files.
 */
export function formatPendingHits(state: LedgerState, limit = 10): string | undefined {
	const { entries, droppedProject } = state;
	if (entries.length === 0 && droppedProject === 0) return undefined;
	const counts = ORDER.map((name) => {
		const count = entries.filter((entry) => group(entry) === name).length + (name === "project" ? droppedProject : 0);
		return count > 0 ? `${count} ${LABELS[name]}` : undefined;
	}).filter((part): part is string => part !== undefined);
	const ordered = ORDER.flatMap((name) => entries.filter((entry) => group(entry) === name));
	const lines = ordered
		.slice(0, limit)
		.map(
			(entry) =>
				`  ${entry.at}  ${entry.change}: ${entry.path}${entry.agent ? " (agent's turn)" : ""}` +
				`${entry.detail ? ` (${entry.detail})` : ""}`,
		);
	if (ordered.length > limit) lines.push(`  ... and ${ordered.length - limit} more`);
	if (droppedProject > 0) lines.push(`  ... and ${droppedProject} older project-file change(s) no longer listed`);
	const total = entries.length + droppedProject;
	return [
		`pi-enclave: ${total} change(s) to files loaded outside the sandbox have not been acknowledged ` +
			`(${counts.join(", ")}):`,
		...lines,
		"Review them, then run /enclave tripwire ack. /enclave tripwire lists them all.",
	].join("\n");
}
