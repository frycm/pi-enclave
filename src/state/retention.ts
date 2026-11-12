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
 *
 * Two refinements for unattended servers (#37):
 *
 * - The size budget never deletes a session that holds a breaker, violation
 *   or approval record. Those are the sessions an incident review needs, and
 *   the oldest-first order would otherwise pick them. Only age removes them,
 *   which is a period the user chose; the budget can be exceeded meanwhile.
 * - A deleted log's head anchor is kept and marked retired, so `audit verify`
 *   can tell a log retention removed from one that disappeared. The marker is
 *   removed after another retention period.
 */
import { readdirSync, readFileSync, statSync, unlinkSync } from "node:fs";
import { join } from "node:path";
import { anchorPathFor, readAnchor, writeAnchor } from "./audit.ts";

/** Record kinds that make a session worth keeping past the size budget. */
const INCIDENT_KINDS = ["breaker", "violation", "approval"];
/** `audit` records that are evidence of tampering, rather than the cap being reached. */
const INCIDENT_AUDIT_EVENTS = ["tail-missing", "tail-differs"];

function holdsIncident(path: string): boolean {
	try {
		const text = readFileSync(path, "utf8");
		// The record's own `kind` is serialized as-is; the same text inside a
		// string field would be escaped (\"kind\"), so this does not match it.
		if (INCIDENT_KINDS.some((kind) => text.includes(`"kind":"${kind}"`))) return true;
		return (
			text.includes(`"kind":"audit"`) && INCIDENT_AUDIT_EVENTS.some((event) => text.includes(`"event":"${event}"`))
		);
	} catch {
		return false;
	}
}

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
	/** Sessions kept past the size budget because they hold an incident. */
	keptForIncidents: string[];
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
		return { deleted: [], keptBytes: 0, keptForIncidents: [] };
	}

	const current = options.keepSessionId ? `${options.keepSessionId}.jsonl` : undefined;
	const deleted: string[] = [];

	const remove = (file: { name: string; path: string }, reason: string) => {
		if (file.name === current) return false;
		try {
			unlinkSync(file.path);
			deleted.push(file.name);
		} catch {
			return false;
		}
		const anchorPath = anchorPathFor(file.path);
		const anchor = readAnchor(anchorPath);
		if (anchor && !anchor.retired) {
			try {
				writeAnchor(anchorPath, { ...anchor, retired: { ts: new Date(now).toISOString(), reason } });
			} catch {
				// Housekeeping; verify then reports the log as missing, which is the
				// safe direction.
			}
		}
		return true;
	};

	const survivors = files.filter((file) => (file.mtime < cutoff ? !remove(file, "retention (age)") : true));

	// Oldest first, until the total fits.
	survivors.sort((a, b) => a.mtime - b.mtime);
	let total = survivors.reduce((sum, file) => sum + file.size, 0);
	const keptForIncidents: string[] = [];
	for (const file of survivors) {
		if (total <= budget) break;
		if (file.name === current) continue;
		if (holdsIncident(file.path)) {
			keptForIncidents.push(file.name);
			continue;
		}
		if (remove(file, "retention (size)")) total -= file.size;
	}

	// Retired anchors outlive their log by one retention period, then go.
	try {
		for (const name of readdirSync(options.dir)) {
			if (!name.endsWith(".head")) continue;
			const path = join(options.dir, name);
			const retired = readAnchor(path)?.retired;
			if (retired && Date.parse(retired.ts) < cutoff) unlinkSync(path);
		}
	} catch {
		// Housekeeping only.
	}

	return { deleted, keptBytes: total, keptForIncidents };
}
