/**
 * Audit retention.
 *
 * Two bounds, whichever comes first: an age and a total size. Run once at
 * session start rather than continuously, because the only thing worse for a
 * hash chain than deleting a file is deleting part of one -- rotation *within*
 * a session would break `prevHash` at the seam, and a chain with an expected
 * break in it is a chain nobody can verify.
 *
 * Deleting whole session files is honest about what it costs: the history is
 * gone, and it is gone in units a person can reason about ("sessions older than
 * 30 days") rather than in truncated fragments.
 */
import { readdirSync, statSync, unlinkSync } from "node:fs";
import { join } from "node:path";

export interface RetentionOptions {
	dir: string;
	retentionDays: number;
	retentionMb: number;
	/** The session currently being written, which is never a candidate. */
	keepSessionId?: string;
	now?: () => number;
}

export interface RetentionResult {
	deleted: string[];
	keptBytes: number;
}

export function applyRetention(options: RetentionOptions): RetentionResult {
	const now = options.now?.() ?? Date.now();
	const cutoff = now - options.retentionDays * 24 * 60 * 60 * 1000;
	const budget = options.retentionMb * 1024 * 1024;

	let files: { name: string; path: string; mtime: number; size: number }[];
	try {
		files = readdirSync(options.dir)
			.filter((name) => name.endsWith(".jsonl"))
			.map((name) => {
				const path = join(options.dir, name);
				const stats = statSync(path);
				return { name, path, mtime: stats.mtimeMs, size: stats.size };
			});
	} catch {
		// No directory yet, or an unreadable one. Retention is housekeeping, not
		// a control, so it does not refuse a session.
		return { deleted: [], keptBytes: 0 };
	}

	const current = options.keepSessionId ? `${options.keepSessionId}.jsonl` : undefined;
	const deleted: string[] = [];

	const remove = (file: { name: string; path: string }) => {
		if (file.name === current) return false;
		try {
			unlinkSync(file.path);
			deleted.push(file.name);
			return true;
		} catch {
			return false;
		}
	};

	const survivors = files.filter((file) => (file.mtime < cutoff ? !remove(file) : true));

	// Oldest first, until the total fits.
	survivors.sort((a, b) => a.mtime - b.mtime);
	let total = survivors.reduce((sum, file) => sum + file.size, 0);
	for (const file of survivors) {
		if (total <= budget) break;
		if (remove(file)) total -= file.size;
	}

	return { deleted, keptBytes: total };
}
