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
import { classifySurfacePath, type SurfaceKind } from "./agent.ts";
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

/** Enough to name every path of a real incident without growing without end. */
const MAX_ENTRIES = 500;

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

	/**
	 * The unacknowledged hits, oldest first. A ledger that cannot be parsed is
	 * itself reported, rather than read as empty.
	 */
	read(): LedgerEntry[] {
		let text: string;
		try {
			text = readFileSync(this.file, "utf8");
		} catch (error) {
			if ((error as NodeJS.ErrnoException).code === "ENOENT") return [];
			throw error;
		}
		try {
			const parsed = JSON.parse(text) as { entries?: unknown };
			if (Array.isArray(parsed.entries) && parsed.entries.every(isEntry)) return parsed.entries;
		} catch {
			// Reported below.
		}
		return [
			{
				path: this.file,
				change: "unverifiable",
				kind: "git",
				at: new Date(0).toISOString(),
				agent: false,
				detail: "the tripwire ledger is unreadable; earlier hits may be lost",
			},
		];
	}

	/** Adds hits, keeping the first sighting of each path and change. */
	add(hits: readonly TripwireHit[], agent: boolean, at = new Date()): void {
		if (hits.length === 0) return;
		const entries = this.read().filter((entry) => entry.path !== this.file);
		const known = new Set(entries.map((entry) => `${entry.change}\0${entry.path}`));
		for (const hit of hits) {
			const key = `${hit.change}\0${hit.path}`;
			if (known.has(key)) continue;
			known.add(key);
			entries.push({
				path: hit.path,
				change: hit.change,
				kind: classifySurfacePath(hit.path),
				at: at.toISOString(),
				agent,
				...(hit.detail ? { detail: hit.detail } : {}),
			});
		}
		this.write(entries.slice(-MAX_ENTRIES));
	}

	/** Forgets every hit; returns how many there were. */
	clear(): number {
		const count = this.read().length;
		if (count > 0) this.write([]);
		return count;
	}

	private write(entries: readonly LedgerEntry[]): void {
		const dir = join(this.file, "..");
		ensureSecureDir(dir);
		const temp = `${this.file}.${process.pid}.tmp`;
		writeFileSync(temp, `${JSON.stringify({ entries }, null, "\t")}\n`, { mode: 0o600 });
		renameSync(temp, this.file);
	}
}

/** The reminder shown at session start, or `undefined` when there is none. */
export function formatPendingHits(entries: readonly LedgerEntry[], limit = 10): string | undefined {
	if (entries.length === 0) return undefined;
	const lines = entries
		.slice(-limit)
		.map(
			(entry) =>
				`  ${entry.at}  ${entry.change}: ${entry.path}${entry.agent ? " (agent's turn)" : ""}` +
				`${entry.detail ? ` (${entry.detail})` : ""}`,
		);
	if (entries.length > limit) lines.unshift(`  ... ${entries.length - limit} earlier`);
	return [
		`pi-enclave: ${entries.length} change(s) to files loaded outside the sandbox have not been acknowledged:`,
		...lines,
		"Review them, then run /enclave tripwire ack. /enclave tripwire lists them all.",
	].join("\n");
}
