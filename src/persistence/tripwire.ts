/**
 * A post-turn check for persistence paths the kernel profile could not cover.
 *
 * The profile is compiled once per session from the paths that exist then. A
 * nested repository, or a submodule directory, that the agent creates later
 * has a writable `config` and `hooks` for the rest of the session, and bwrap
 * cannot deny a name that does not exist yet. So the trusted parent records a
 * fingerprint of the persistence surface when the session starts and compares
 * it after every turn: a path that appeared or changed is reported as a
 * violation, which the user sees and the breaker counts.
 *
 * It detects, it does not prevent. What it buys is that the user learns about
 * the change in the turn it happened, before their next `git status`, and the
 * next session's profile protects the new path at L2.
 */

import { isUnverifiableValue, type SurfaceKind, surfaceValueKind } from "./agent.ts";

export type TripwireChange = "created" | "modified" | "unverifiable";

export interface TripwireHit {
	path: string;
	change: TripwireChange;
	detail?: string;
	/**
	 * Which surface the path is on, when the surface says. Absent for a
	 * surface that does not tag its values, and for a surface that could not
	 * be read at all.
	 */
	kind?: SurfaceKind;
}

/** Path -> fingerprint. Absent paths are absent from the map. */
export type PersistenceSurface = () => Map<string, string>;

export class PersistenceTripwire {
	private baseline: Map<string, string>;

	/** Takes the first fingerprint now; a surface that cannot be read throws. */
	constructor(
		private readonly surface: PersistenceSurface,
		/** Reported as the path of an `unverifiable` hit. */
		private readonly label: string,
	) {
		this.baseline = surface();
	}

	/**
	 * Compare the surface with the last fingerprint, then make the current one
	 * the new baseline, so each change is reported once.
	 *
	 * Removed paths are not reported: deleting a hook or a configuration file
	 * is not a way to run code later. A surface that cannot be read is reported
	 * as `unverifiable` rather than passed, since making the walk fail is the
	 * obvious way to hide from it; the old baseline is kept.
	 */
	check(): TripwireHit[] {
		let current: Map<string, string>;
		try {
			current = this.surface();
		} catch (error) {
			return [{ path: this.label, change: "unverifiable", detail: (error as Error).message }];
		}
		const hits: TripwireHit[] = [];
		for (const [path, value] of current) {
			const kind = surfaceValueKind(value);
			const tag = kind ? { kind } : {};
			// Too large to fingerprint: it cannot be compared, so it is reported
			// at every check rather than passed as unchanged.
			if (isUnverifiableValue(value)) {
				hits.push({ path, change: "unverifiable", detail: "too many entries to fingerprint", ...tag });
				continue;
			}
			const before = this.baseline.get(path);
			if (before === undefined) hits.push({ path, change: "created", ...tag });
			else if (before !== value) hits.push({ path, change: "modified", ...tag });
		}
		this.baseline = current;
		return hits.sort((a, b) => a.path.localeCompare(b.path));
	}

	/** Accept the current state without reporting it, after a change the user made. */
	rebaseline(): void {
		try {
			this.baseline = this.surface();
		} catch {
			// Kept: the next check reports the surface as unverifiable.
		}
	}
}

const LEADS: Record<SurfaceKind, (when: string) => string> = {
	git: (when) =>
		`Git configuration or hooks changed ${when}. Git run in this workspace outside the sandbox ` +
		"would read them. Inspect before running git, for example with " +
		"`git -c core.fsmonitor=false -c core.hooksPath=/dev/null --no-pager status --ignore-submodules=all`:",
	agent: (when) =>
		`pi configuration (.pi, .agents) changed ${when}. pi loads it outside the sandbox the next time it ` +
		"starts in this tree. Review or remove it before then:",
	project: (when) =>
		`Files that agents, your shell or your editor load changed ${when} (instructions, .envrc, hook ` +
		"managers, editor tasks). Treat them as untrusted until you have read them:",
};

/** One section per kind of surface, one line per hit, for the notification. */
export function formatTripwireHits(hits: readonly TripwireHit[], when: string): string {
	const sections: string[] = [];
	const unverifiable = hits.filter((hit) => hit.change === "unverifiable");
	if (unverifiable.length > 0) {
		sections.push(
			[
				`pi-enclave: the files loaded outside the sandbox could not be checked ${when}. ` +
					"Treat the workspace as untrusted until they can be:",
				...unverifiable.map((hit) => `  unverifiable: ${hit.path}${hit.detail ? ` (${hit.detail})` : ""}`),
			].join("\n"),
		);
	}
	for (const kind of ["git", "agent", "project"] as const) {
		const ofKind = hits.filter((hit) => hit.change !== "unverifiable" && (hit.kind ?? "git") === kind);
		if (ofKind.length === 0) continue;
		const lines = ofKind
			.slice(0, 10)
			.map((hit) => `  ${hit.change}: ${hit.path}${hit.detail ? ` (${hit.detail})` : ""}`);
		if (ofKind.length > 10) lines.push(`  ... and ${ofKind.length - 10} more`);
		sections.push([`pi-enclave: ${LEADS[kind](when)}`, ...lines].join("\n"));
	}
	return sections.join("\n");
}
