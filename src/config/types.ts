/**
 * The shape of an effective pi-enclave configuration.
 *
 * Two things live here and nothing else: the *complete* settings a session runs
 * under (`EffectiveProfile`), and the identity of the source each list entry
 * came from (`Provenance`). Both are plain data. The validation lives in
 * `schema.ts`, the ordering in `merge.ts`, and the discovery in `sources.ts`,
 * because those three answer different questions and mixing them is how a
 * configuration layer becomes impossible to audit.
 *
 * Every field is required in an `EffectiveProfile`. A partially-specified
 * profile is a `ProfilePatch`, which is what a file contributes; the fold turns
 * patches into an effective profile and never the other way round. That
 * distinction is what lets "a project may only tighten" be a type-level fact as
 * well as a runtime check.
 */

// ---------------------------------------------------------------------------
// Sources
// ---------------------------------------------------------------------------

/**
 * Where a setting came from, ordered by trust: earlier is more trusted.
 *
 * The fold visits them in exactly this order, and the order is the whole of the
 * monotonic rule -- there is no per-source exception table, only "a later
 * source may not widen what an earlier one produced".
 */
export const SOURCE_ORDER = ["builtin", "user_global", "env", "project_local", "project_shared"] as const;

export type SourceId = (typeof SOURCE_ORDER)[number];

/** True for sources a repository can write. */
export function isProjectSource(source: SourceId): boolean {
	return source === "project_local" || source === "project_shared";
}

/** Human-readable name for diagnostics. */
export const SOURCE_LABELS: Record<SourceId, string> = {
	builtin: "built-in defaults",
	user_global: "~/.pi/agent/enclave.json",
	env: "PI_ENCLAVE_* environment",
	project_local: ".pi/enclave.local.json",
	project_shared: ".pi/enclave.json",
};

// ---------------------------------------------------------------------------
// Settings
// ---------------------------------------------------------------------------

export type ReviewTrigger = "boundary" | "mutating" | "all";
export type CapabilityMode = "none" | "reviewed";
export type HostExecMode = "never" | "human";
export type AttendedMode = "tui" | "rpc" | "off";
export type NetworkMode = "off";

export interface EnvSettings {
	/** Extra host variables copied into the child, by exact name. User-global only. */
	passthrough: string[];
	/** Credential name patterns stripped last, whatever else asked for them. */
	envDeny: string[];
}

export interface NetworkSettings {
	mode: NetworkMode;
	allowHosts: string[];
}

export interface SandboxSettings {
	mode: "workspace-write";
	/** Absolute paths that may be written. Everything else is read-only. */
	writableRoots: string[];
	/** Absolute paths that may not be read, even though reads are otherwise open. */
	readDeny: string[];
	/** User-global read-deny entries that a reviewed action may lift once. */
	grantableReadDeny: string[];
	network: NetworkSettings;
	/** May the agent request a one-shot capability (which goes to L3, or to L4 without one)? */
	capabilities: CapabilityMode;
	/** May a *human* approve an unsandboxed run? Never a model. */
	hostExec: HostExecMode;
	allowPty: boolean;
	env: EnvSettings;
}

export interface ProtectedPaths {
	deny: string[];
	ask: string[];
}

export interface RulesSettings {
	/** Never runs; nothing below can override. */
	deny: string[];
	/** Always a human decision; the reviewer cannot auto-approve it. */
	ask: string[];
	/** An allow verdict that skips L3. User-global only. */
	skipReview: string[];
	protectedPaths: ProtectedPaths;
}

/**
 * The prose rulebook rendered into the isolated reviewer's prompt. Nothing
 * below user-global can supply it, so a repository cannot rewrite the policy
 * that judges its own actions.
 */
export interface ReviewSettings {
	trigger: ReviewTrigger;
	environment: string[];
	hard_deny: string[];
	soft_deny: string[];
	allow: string[];
}

/**
 * A grant for one tool pi-enclave does not execute itself.
 *
 * `source` pins the grant to the extension that registered the tool, by the
 * `sourceInfo.path` pi reports. Without it, any extension registering a tool of
 * the same name inherits the grant -- and since load order decides which
 * registration wins, that is a grant to whoever loads first.
 * `reviewed` always leaves the final permit to L4 because this tool runs outside
 * the sandbox; a named reviewer may veto or recommend, but cannot authorize it.
 */
export interface ToolGrant {
	readOnly?: boolean;
	reviewed?: boolean;
	source?: string;
}

export interface ToolsSettings {
	allow: Record<string, ToolGrant>;
}

export interface ReviewerSettings {
	/** `"none"` is deterministic mode; otherwise an explicit `provider/model-id`. */
	model: string;
	timeoutMs: number;
	fallback: string;
}

export interface BreakerSettings {
	/** Adverse outcomes in a row within one turn before the breaker opens. */
	consecutive: number;
	/** `[maxAdverse, windowSize]` over recent batches. */
	window: [number, number];
}

export interface AttendedSettings {
	mode: AttendedMode;
	confirmTimeoutMs: number;
}

export interface AuditSettings {
	retentionDays: number;
	retentionMb: number;
}

/**
 * A complete configuration. Produced only by the fold, never written by hand.
 */
export interface EffectiveProfile {
	/** The selected profile's name, for the status line and the audit record. */
	name: string;
	/**
	 * Whether L1 and L4 are active. `PI_ENCLAVE_AUTO=off` clears it.
	 *
	 * It never clears the sandbox. L2 is the one layer the monotonic rule says
	 * nothing may remove, and an environment variable is the least trusted place
	 * a request to remove it could come from.
	 */
	auto: boolean;
	sandbox: SandboxSettings;
	rules: RulesSettings;
	review: ReviewSettings;
	tools: ToolsSettings;
	reviewer: ReviewerSettings;
	breaker: BreakerSettings;
	attended: AttendedSettings;
	audit: AuditSettings;
}

// ---------------------------------------------------------------------------
// Patches
// ---------------------------------------------------------------------------

/** A partially-specified contribution from one file. */
export interface ProfilePatch {
	sandbox?: Partial<Omit<SandboxSettings, "network" | "env">> & {
		network?: Partial<NetworkSettings>;
		env?: Partial<EnvSettings>;
	};
	rules?: Partial<Omit<RulesSettings, "protectedPaths">> & { protectedPaths?: Partial<ProtectedPaths> };
	review?: Partial<ReviewSettings>;
	tools?: Partial<ToolsSettings>;
	reviewer?: Partial<ReviewerSettings>;
	breaker?: Partial<BreakerSettings>;
	attended?: Partial<AttendedSettings>;
	audit?: Partial<AuditSettings>;
}

/** One file's contribution: which profile it selects, and what it defines or patches. */
export interface ConfigDocument {
	source: SourceId;
	/** The file this came from, for diagnostics. Absent for `builtin` and `env`. */
	path?: string;
	/** Profile selection. */
	profile?: string;
	/** Full profile definitions. Only a user-global file may define profiles. */
	profiles?: Record<string, ProfilePatch>;
	/** A patch applied to the selected profile. How project files contribute. */
	patch?: ProfilePatch;
	/** Cleared by `PI_ENCLAVE_AUTO=off`. */
	auto?: boolean;
}

// ---------------------------------------------------------------------------
// Provenance
// ---------------------------------------------------------------------------

/**
 * Which source contributed each entry of each list.
 *
 * Keyed by a dotted list path (`"rules.deny"`) then by the entry itself. An
 * entry contributed by two sources records the *most trusted* one, because that
 * is the source a reader has to change to remove it.
 */
export type Provenance = Map<string, Map<string, SourceId>>;

export function recordProvenance(
	provenance: Provenance,
	listPath: string,
	entries: Iterable<string>,
	source: SourceId,
) {
	let list = provenance.get(listPath);
	if (!list) {
		list = new Map();
		provenance.set(listPath, list);
	}
	for (const entry of entries) if (!list.has(entry)) list.set(entry, source);
}

export function provenanceOf(provenance: Provenance, listPath: string, entry: string): SourceId | undefined {
	return provenance.get(listPath)?.get(entry);
}
