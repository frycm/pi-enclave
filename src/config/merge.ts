/**
 * The monotonic fold.
 *
 * One rule instead of a list of exceptions: **configuration sources are ordered
 * by trust, and a less-trusted source may only produce a profile that is at
 * most as permissive as the one it received.** Everything the configuration
 * table in the README says a project file "may not" do is a consequence of that
 * rule plus the partial orders below, not a separate check.
 *
 * Three things are worth knowing before reading further.
 *
 * **The order is per field, and each one is a claim about permission, not about
 * set size.** `readDeny` grows to narrow; `writableRoots` may only gain paths
 * already inside a root it had. Writing them as one generic "subset" rule was
 * the first version and it was wrong in both directions.
 *
 * **Each step is checked against the profile it received, not a fixed ceiling.**
 * The user's own file is the most trusted source and is not itself measured
 * against anything. Every source below it must be at most as permissive as the
 * profile produced by the source immediately above it -- which is what the
 * "the one it received" wording means, and is strictly stronger than checking
 * against the user-global result alone: it also stops a less-trusted source
 * (project-shared) from undoing a more-trusted one's (project-local) narrowing.
 * Transitivity still guarantees everything ends up ⊑ the user-global profile.
 *
 * **Nothing is clamped.** A violation rejects the whole file and names the
 * field. A clamped value is one the user believes they set.
 */
import { canonical, isUnder, normalizePath } from "../backend/paths.ts";
import type { DefaultProfileOptions } from "./defaults.ts";
import { defaultProfile, enclaveStateDir } from "./defaults.ts";
import type {
	AttendedMode,
	CapabilityMode,
	ConfigDocument,
	EffectiveProfile,
	HostExecMode,
	ProfilePatch,
	Provenance,
	ReviewTrigger,
	SourceId,
	ToolGrant,
} from "./types.ts";
import { recordProvenance, SOURCE_LABELS } from "./types.ts";

export interface OrderViolation {
	/** Dotted field path, e.g. `sandbox.writableRoots`. */
	field: string;
	message: string;
}

export interface FoldError extends OrderViolation {
	source: SourceId;
	path?: string;
}

export type FoldResult =
	| { ok: true; profile: EffectiveProfile; provenance: Provenance }
	| { ok: false; errors: FoldError[] };

// ---------------------------------------------------------------------------
// Ranked scalars
// ---------------------------------------------------------------------------

const CAPABILITY_RANK: Record<CapabilityMode, number> = { none: 0, reviewed: 1 };
const HOST_EXEC_RANK: Record<HostExecMode, number> = { never: 0, human: 1 };
/** More review is narrower, so the ranks run the other way and the comparison flips. */
const TRIGGER_RANK: Record<ReviewTrigger, number> = { boundary: 0, mutating: 1, all: 2 };
/** `off` denies every escalation, so it is the narrowest attendance. */
const ATTENDED_RANK: Record<AttendedMode, number> = { off: 0, rpc: 1, tui: 2 };

/**
 * How permissive a tool grant is.
 *
 * `reviewed` sends every call to a decision, so it is narrowest; a plain grant
 * runs the tool under the ordinary path; `readOnly` is a promise that lets
 * Phase 3's trigger skip review entirely, which is the widest of the three. The
 * README's "readOnly may become reviewed, never the reverse" is this ordering.
 */
function grantRank(grant: ToolGrant): number {
	if (grant.reviewed) return 0;
	if (grant.readOnly) return 2;
	return 1;
}

// ---------------------------------------------------------------------------
// The partial order
// ---------------------------------------------------------------------------

/**
 * Is `a` at most as permissive as `b`? Returns every field where it is not.
 *
 * Pure and total: it never throws and never consults the filesystem except
 * through `canonical`, which falls back to the path as written.
 */
export function narrowerOrEqual(a: EffectiveProfile, b: EffectiveProfile): OrderViolation[] {
	const violations: OrderViolation[] = [];
	const fail = (field: string, message: string) => violations.push({ field, message });
	const contained = containment();

	if (a.auto && !b.auto) fail("auto", "auto mode cannot be turned back on");

	if (a.sandbox.mode !== b.sandbox.mode) {
		fail("sandbox.mode", `cannot change the sandbox mode from "${b.sandbox.mode}" to "${a.sandbox.mode}"`);
	}

	// Writable roots: every root must be contained in one the wider profile
	// already had. This is exactly "added roots must be inside the workspace"
	// when the workspace is a root, and it also rejects a root that merely looks
	// local through a symlink, because containment is checked canonically too.
	for (const root of a.sandbox.writableRoots) {
		if (!contained(root, b.sandbox.writableRoots)) {
			fail("sandbox.writableRoots", `"${root}" is not inside any writable root of the more trusted profile`);
		}
	}

	// Read denials: the narrower profile must deny at least as much. Containment
	// again rather than set membership -- denying `~/.aws` also denies
	// `~/.aws/credentials`, and a rewrite that replaces the child with the parent
	// is a tightening, not a violation.
	for (const denied of b.sandbox.readDeny) {
		if (!contained(denied, a.sandbox.readDeny)) {
			fail("sandbox.readDeny", `"${denied}" is no longer denied for reading`);
		}
	}

	if (a.sandbox.network.mode !== b.sandbox.network.mode) {
		fail("sandbox.network.mode", `cannot change the network mode from "${b.sandbox.network.mode}"`);
	}
	subsetOf("sandbox.network.allowHosts", a.sandbox.network.allowHosts, b.sandbox.network.allowHosts, fail);

	if (CAPABILITY_RANK[a.sandbox.capabilities] > CAPABILITY_RANK[b.sandbox.capabilities]) {
		fail("sandbox.capabilities", `cannot widen from "${b.sandbox.capabilities}" to "${a.sandbox.capabilities}"`);
	}
	if (HOST_EXEC_RANK[a.sandbox.hostExec] > HOST_EXEC_RANK[b.sandbox.hostExec]) {
		fail("sandbox.hostExec", `cannot widen from "${b.sandbox.hostExec}" to "${a.sandbox.hostExec}"`);
	}
	if (a.sandbox.allowPty && !b.sandbox.allowPty) fail("sandbox.allowPty", "cannot enable PTY allocation");

	subsetOf("sandbox.env.passthrough", a.sandbox.env.passthrough, b.sandbox.env.passthrough, fail);
	supersetOf("sandbox.env.envDeny", a.sandbox.env.envDeny, b.sandbox.env.envDeny, fail);

	supersetOf("rules.deny", a.rules.deny, b.rules.deny, fail);
	supersetOf("rules.ask", a.rules.ask, b.rules.ask, fail);
	supersetOf("rules.protectedPaths.deny", a.rules.protectedPaths.deny, b.rules.protectedPaths.deny, fail);
	supersetOf("rules.protectedPaths.ask", a.rules.protectedPaths.ask, b.rules.protectedPaths.ask, fail);
	subsetOf("rules.skipReview", a.rules.skipReview, b.rules.skipReview, fail);

	if (TRIGGER_RANK[a.review.trigger] < TRIGGER_RANK[b.review.trigger]) {
		fail("review.trigger", `cannot lower the review trigger from "${b.review.trigger}" to "${a.review.trigger}"`);
	}
	// The four prose lists have no partial order a merge can check, so the only
	// sound relation is equality. Presence in a project file is refused earlier,
	// by the schema; this catches any other way one could change.
	for (const list of ["environment", "hard_deny", "soft_deny", "allow"] as const) {
		if (!sameList(a.review[list], b.review[list])) {
			fail(`review.${list}`, "prose rulebook entries are immutable below user-global");
		}
	}

	for (const [name, grant] of Object.entries(a.tools.allow)) {
		const wider = b.tools.allow[name];
		if (!wider) {
			fail("tools.allow", `"${name}" is not allowed by the more trusted profile`);
			continue;
		}
		if (grantRank(grant) > grantRank(wider)) {
			fail(`tools.allow.${name}`, `cannot widen the grant for "${name}"`);
		}
		if (wider.source !== undefined && grant.source !== wider.source) {
			fail(`tools.allow.${name}.source`, `the grant is pinned to "${wider.source}" and cannot be repointed`);
		}
	}

	if (a.reviewer.model !== b.reviewer.model || a.reviewer.fallback !== b.reviewer.fallback) {
		fail("reviewer", "the reviewer is immutable below user-global");
	}
	if (a.reviewer.timeoutMs > b.reviewer.timeoutMs) {
		fail("reviewer.timeoutMs", "cannot lengthen the reviewer timeout");
	}

	if (a.breaker.consecutive > b.breaker.consecutive) fail("breaker.consecutive", "cannot raise the consecutive limit");
	if (a.breaker.window[0] > b.breaker.window[0]) fail("breaker.window", "cannot raise the windowed adverse limit");
	if (a.breaker.window[1] < b.breaker.window[1]) fail("breaker.window", "cannot shrink the observation window");

	if (ATTENDED_RANK[a.attended.mode] > ATTENDED_RANK[b.attended.mode]) {
		fail("attended.mode", `cannot widen attendance from "${b.attended.mode}" to "${a.attended.mode}"`);
	}
	if (a.attended.confirmTimeoutMs > b.attended.confirmTimeoutMs) {
		fail("attended.confirmTimeoutMs", "cannot lengthen the confirmation timeout");
	}

	if (a.audit.retentionDays < b.audit.retentionDays) fail("audit.retentionDays", "cannot shorten audit retention");
	if (a.audit.retentionMb < b.audit.retentionMb) fail("audit.retentionMb", "cannot shrink the audit budget");

	return violations;
}

/**
 * Containment against a list of roots, canonicalizing only when it has to.
 *
 * Two passes and a cache, both for the same reason: `canonical` resolves
 * symlinks through the filesystem, and on macOS `/home` is an autofs mount
 * point where a single failed probe costs milliseconds. The naive version
 * canonicalized every root for every entry -- quadratic in the list length and
 * a measured 1.8 s for one comparison of two default profiles, which made the
 * property test unrunnable. The literal pass answers the overwhelmingly common
 * case (a list compared against itself) without touching the disk at all, and
 * the cache makes the fallback linear.
 *
 * The cache lives for one comparison only. A longer-lived one would answer from
 * a filesystem that has since changed, and this comparison decides what a
 * profile is permitted to contain.
 */
function containment(): (path: string, roots: readonly string[]) => boolean {
	const cache = new Map<string, string>();
	const canon = (path: string): string => {
		let resolved = cache.get(path);
		if (resolved === undefined) {
			resolved = canonical(path);
			cache.set(path, resolved);
		}
		return resolved;
	};
	return (path, roots) => {
		if (roots.some((root) => isUnder(path, root))) return true;
		const resolved = canon(path);
		return roots.some((root) => isUnder(resolved, canon(root)));
	};
}

function subsetOf(field: string, a: readonly string[], b: readonly string[], fail: (f: string, m: string) => void) {
	const wider = new Set(b);
	for (const entry of a) if (!wider.has(entry)) fail(field, `"${entry}" was added; this list may only shrink`);
}

function supersetOf(field: string, a: readonly string[], b: readonly string[], fail: (f: string, m: string) => void) {
	const narrower = new Set(a);
	for (const entry of b) if (!narrower.has(entry)) fail(field, `"${entry}" was removed; this list may only grow`);
}

function sameList(a: readonly string[], b: readonly string[]): boolean {
	return a.length === b.length && a.every((entry, index) => entry === b[index]);
}

// ---------------------------------------------------------------------------
// Applying a patch
// ---------------------------------------------------------------------------

/**
 * Per-list merge strategy, and why each one is what it is.
 *
 * `union` for the lists whose order is "superset": a lower source contributes
 * *additional* denials, and replacing would silently drop the ones above it.
 * `replace` for the lists whose order is "subset": there, contributing means
 * naming the whole set, and the order check then rejects anything new.
 *
 * `sandbox.writableRoots` is the interesting one: it is union *and* its order
 * is containment, which together are exactly the README's "a project may add
 * writable roots inside the repo". Replacement would have forced a project to
 * restate the user's roots to add one of its own.
 */
type ListStrategy = "union" | "replace";

function mergeList(strategy: ListStrategy, current: string[], incoming: string[] | undefined): string[] {
	if (incoming === undefined) return current;
	if (strategy === "replace") return [...new Set(incoming)];
	return [...new Set([...current, ...incoming])];
}

export interface ApplyOptions extends DefaultProfileOptions {
	source: SourceId;
	provenance?: Provenance;
}

/**
 * Apply one patch to a profile, returning a new profile. Never mutates.
 *
 * Path-valued entries are expanded here rather than in the schema, because the
 * expansion depends on the workspace and home the fold was given, and a schema
 * that resolved paths would not be testable against literals.
 */
export function applyPatch(base: EffectiveProfile, patch: ProfilePatch, options: ApplyOptions): EffectiveProfile {
	const { source, provenance } = options;
	const next: EffectiveProfile = structuredClone(base);
	const expand = (value: string) => expandPath(value, options);
	const track = (listPath: string, entries: readonly string[]) => {
		if (provenance) recordProvenance(provenance, listPath, entries, source);
	};

	const sandbox = patch.sandbox;
	if (sandbox) {
		if (sandbox.mode !== undefined) next.sandbox.mode = sandbox.mode;
		if (sandbox.writableRoots) {
			const expanded = sandbox.writableRoots.map(expand);
			track("sandbox.writableRoots", expanded);
			next.sandbox.writableRoots = mergeList("union", next.sandbox.writableRoots, expanded);
		}
		if (sandbox.readDeny) {
			const expanded = sandbox.readDeny.map(expand);
			track("sandbox.readDeny", expanded);
			next.sandbox.readDeny = mergeList("union", next.sandbox.readDeny, expanded);
		}
		if (sandbox.network) {
			if (sandbox.network.mode !== undefined) next.sandbox.network.mode = sandbox.network.mode;
			if (sandbox.network.allowHosts) {
				track("sandbox.network.allowHosts", sandbox.network.allowHosts);
				next.sandbox.network.allowHosts = mergeList(
					"union",
					next.sandbox.network.allowHosts,
					sandbox.network.allowHosts,
				);
			}
		}
		if (sandbox.capabilities !== undefined) next.sandbox.capabilities = sandbox.capabilities;
		if (sandbox.hostExec !== undefined) next.sandbox.hostExec = sandbox.hostExec;
		if (sandbox.allowPty !== undefined) next.sandbox.allowPty = sandbox.allowPty;
		if (sandbox.env) {
			if (sandbox.env.passthrough) {
				track("sandbox.env.passthrough", sandbox.env.passthrough);
				next.sandbox.env.passthrough = mergeList("replace", next.sandbox.env.passthrough, sandbox.env.passthrough);
			}
			if (sandbox.env.envDeny) {
				track("sandbox.env.envDeny", sandbox.env.envDeny);
				next.sandbox.env.envDeny = mergeList("union", next.sandbox.env.envDeny, sandbox.env.envDeny);
			}
		}
	}

	const rules = patch.rules;
	if (rules) {
		if (rules.deny) {
			track("rules.deny", rules.deny);
			next.rules.deny = mergeList("union", next.rules.deny, rules.deny);
		}
		if (rules.ask) {
			track("rules.ask", rules.ask);
			next.rules.ask = mergeList("union", next.rules.ask, rules.ask);
		}
		if (rules.skipReview) {
			track("rules.skipReview", rules.skipReview);
			next.rules.skipReview = mergeList("replace", next.rules.skipReview, rules.skipReview);
		}
		if (rules.protectedPaths) {
			const protectedPaths = rules.protectedPaths;
			if (protectedPaths.deny) {
				track("rules.protectedPaths.deny", protectedPaths.deny);
				next.rules.protectedPaths.deny = mergeList("union", next.rules.protectedPaths.deny, protectedPaths.deny);
			}
			if (protectedPaths.ask) {
				track("rules.protectedPaths.ask", protectedPaths.ask);
				next.rules.protectedPaths.ask = mergeList("union", next.rules.protectedPaths.ask, protectedPaths.ask);
			}
		}
	}

	const review = patch.review;
	if (review) {
		if (review.trigger !== undefined) next.review.trigger = review.trigger;
		for (const list of ["environment", "hard_deny", "soft_deny", "allow"] as const) {
			const entries = review[list];
			if (!entries) continue;
			track(`review.${list}`, entries);
			next.review[list] = mergeList("replace", next.review[list], entries);
		}
	}

	if (patch.tools?.allow) {
		next.tools.allow = structuredClone(patch.tools.allow);
		track("tools.allow", Object.keys(patch.tools.allow));
	}
	if (patch.reviewer) next.reviewer = { ...next.reviewer, ...patch.reviewer };
	if (patch.breaker) {
		if (patch.breaker.consecutive !== undefined) next.breaker.consecutive = patch.breaker.consecutive;
		if (patch.breaker.window) next.breaker.window = [...patch.breaker.window];
	}
	if (patch.attended) next.attended = { ...next.attended, ...patch.attended };
	if (patch.audit) next.audit = { ...next.audit, ...patch.audit };

	return next;
}

/**
 * Expand `~`, `$WORKSPACE`, `$TMPDIR` and relative paths.
 *
 * A relative path resolves against the workspace, which is what a project file
 * means by `build/` and the only reading that is safe: resolving against the
 * process cwd would let a config file loaded from elsewhere name a path the
 * author did not intend.
 */
export function expandPath(value: string, options: DefaultProfileOptions): string {
	const home = options.home ?? process.env.HOME ?? "";
	const tmp = options.tmp ?? "/tmp";
	let out = value;
	if (out === "~") out = home;
	else if (out.startsWith("~/")) out = `${home}/${out.slice(2)}`;
	// The braced form is concatenated rather than written out: spelled literally
	// it reads to the linter as a template placeholder someone forgot to
	// interpolate, and that warning is worth keeping switched on everywhere else.
	const braced = (name: string) => `$${"{"}${name}}`;
	for (const [name, value] of [
		["WORKSPACE", options.cwd],
		["TMPDIR", tmp],
	] as const) {
		out = out.replaceAll(braced(name), value).replaceAll(`$${name}`, value);
	}
	if (!out.startsWith("/")) out = `${options.cwd}/${out}`;
	return normalizePath(out);
}

// ---------------------------------------------------------------------------
// The fold
// ---------------------------------------------------------------------------

/**
 * Fold the documents, in trust order, into one effective profile.
 *
 * `documents` must already be validated by `schema.ts`; this function assumes
 * shapes and enforces *relations*. The two jobs are separate because a shape
 * error is the user's typo and a relation error is a trust decision, and they
 * deserve different messages.
 */
export function fold(documents: readonly ConfigDocument[], options: DefaultProfileOptions): FoldResult {
	const errors: FoldError[] = [];
	const provenance: Provenance = new Map();

	const builtin = defaultProfile(options);
	recordBuiltinProvenance(provenance, builtin);

	let current = builtin;
	/** Profiles the user-global file defined, available for later selection. */
	let defined: Record<string, ProfilePatch> = {};
	let seenUserGlobal = false;

	for (const document of documents) {
		const { source } = document;
		const fail = (field: string, message: string) => {
			const error: FoldError = { source, field, message };
			if (document.path !== undefined) error.path = document.path;
			errors.push(error);
		};

		// The profile this source was handed, before any of its own mutations.
		// The order is checked against *this*, not only against the user-global
		// ceiling: the promise is "at most as permissive as the one it received",
		// and checking against the ceiling alone let a less-trusted source undo a
		// more-trusted one's narrowing (project-shared reverting project-local, or
		// a project re-selecting a profile to revert PI_ENCLAVE_ATTENDED=off) as
		// long as the result stayed under the ceiling. Checking against `received`
		// is strictly stronger and still implies `⊑ ceiling` by transitivity.
		const received = current;

		if (document.auto === false) current = { ...current, auto: false };

		// Definitions are registered before any selection is resolved, including
		// a selection in the very same file: `{ profile: "dev", profiles: { dev }}`
		// is the ordinary shape of a user-global file, and reading them the other
		// way round made it fail to find a profile sitting three lines below.
		if (source === "user_global") {
			defined = document.profiles ?? {};
		} else if (document.profiles) {
			fail("profiles", `${SOURCE_LABELS[source]} may not define profiles`);
		}

		// A profile *selection* replaces the profile rather than patching it, so
		// it is rebuilt from the built-in base and the named definition. A
		// less-trusted source may select, never define; the order check below
		// then decides whether the profile it picked is one it is allowed to have.
		const selection =
			document.profile ??
			// A user-global file with definitions but no selection uses the first
			// one, which is what a single-profile file means.
			(source === "user_global" && document.profiles ? Object.keys(document.profiles)[0] : undefined);

		if (selection !== undefined) {
			const definition = defined[selection];
			if (!definition) {
				fail("profile", `no profile named "${selection}" is defined in the user-global file`);
			} else {
				const selected = applyPatch(builtin, definition, { ...options, source: "user_global", provenance });
				selected.name = selection;
				selected.auto = current.auto;
				current = selected;
			}
		}

		if (document.patch) {
			current = applyPatch(current, document.patch, { ...options, source, provenance });
		}

		if (source === "user_global") {
			// The user's own file is the most trusted source: it sets the ceiling
			// and is not itself measured against anything. Checking it against the
			// built-in defaults would mean a user could never widen anything.
			seenUserGlobal = true;
		} else if (seenUserGlobal || source !== "builtin") {
			for (const violation of narrowerOrEqual(current, received)) {
				fail(violation.field, violation.message);
			}
		}
	}

	// An invariant no source may reach, checked once at the end rather than as
	// an order: pi-enclave's own state directory holds the pending approval
	// records and the attendance secret, and a writable root that contains it
	// would let the agent forge the evidence of its own approval.
	const stateDir = enclaveStateDir(options.agentDir);
	for (const root of current.sandbox.writableRoots) {
		if (isUnder(stateDir, root) || isUnder(canonical(stateDir), canonical(root))) {
			errors.push({
				source: "builtin",
				field: "sandbox.writableRoots",
				message:
					`"${root}" contains pi-enclave's state directory (${stateDir}), so the sandboxed agent could write ` +
					`its own approval records and read the attendance secret.\n` +
					`    Fix it by moving pi's agent directory outside the workspace (unset PI_CODING_AGENT_DIR, or point ` +
					`it somewhere the agent cannot write), or by narrowing sandbox.writableRoots so it does not contain that path.`,
			});
		}
	}

	if (errors.length > 0) return { ok: false, errors };
	return { ok: true, profile: current, provenance };
}

function recordBuiltinProvenance(provenance: Provenance, profile: EffectiveProfile) {
	recordProvenance(provenance, "sandbox.writableRoots", profile.sandbox.writableRoots, "builtin");
	recordProvenance(provenance, "sandbox.readDeny", profile.sandbox.readDeny, "builtin");
	recordProvenance(provenance, "sandbox.network.allowHosts", profile.sandbox.network.allowHosts, "builtin");
	recordProvenance(provenance, "sandbox.env.passthrough", profile.sandbox.env.passthrough, "builtin");
	recordProvenance(provenance, "sandbox.env.envDeny", profile.sandbox.env.envDeny, "builtin");
	recordProvenance(provenance, "rules.deny", profile.rules.deny, "builtin");
	recordProvenance(provenance, "rules.ask", profile.rules.ask, "builtin");
	recordProvenance(provenance, "rules.skipReview", profile.rules.skipReview, "builtin");
	recordProvenance(provenance, "rules.protectedPaths.deny", profile.rules.protectedPaths.deny, "builtin");
	recordProvenance(provenance, "rules.protectedPaths.ask", profile.rules.protectedPaths.ask, "builtin");
	recordProvenance(provenance, "tools.allow", Object.keys(profile.tools.allow), "builtin");
}

/** Render fold errors for stderr and `/enclave status`. */
export function formatFoldErrors(errors: readonly FoldError[]): string {
	const lines = ["pi-enclave: configuration was rejected; auto mode will not start."];
	for (const error of errors) {
		const where = error.path ?? SOURCE_LABELS[error.source];
		lines.push(`  ${where}: ${error.field} — ${error.message}`);
	}
	lines.push("  A less-trusted source may only narrow what a more trusted one produced.");
	return lines.join("\n");
}
