/**
 * Configuration validation.
 *
 * Hand-written, with no schema library, on purpose: this function *is* a trust
 * boundary, and a boundary whose rules live in a declarative dialect somewhere
 * else is one nobody reads. Every rule below is a line of code a reviewer can
 * follow to the value it rejects.
 *
 * Three properties it must have, and which the tests assert directly:
 *
 * - **Unknown keys are errors.** A misspelled `readDeny` that is silently
 *   ignored produces a sandbox the user believes is narrower than it is. There
 *   is no forward compatibility to preserve here; a newer pi-enclave reading an
 *   older file is the direction that has to work, not the reverse.
 * - **A file is accepted whole or rejected whole.** Nothing is clamped. A
 *   half-applied configuration is harder to reason about than none, and a
 *   clamped value is one a user believes they set.
 * - **Every diagnostic names the key.** `sandbox.writableRoots[1]`, not "invalid
 *   configuration".
 */
import type { DefaultProfileOptions } from "./defaults.ts";
import { defaultListFor } from "./defaults.ts";
import { isReviewerModelSetting } from "./reviewer-model.ts";
import type {
	AttendedMode,
	CapabilityMode,
	ConfigDocument,
	HostExecMode,
	ProfilePatch,
	ReviewTrigger,
	SourceId,
	ToolGrant,
} from "./types.ts";
import { isProjectSource, SOURCE_LABELS } from "./types.ts";

export interface Diagnostic {
	/** Dotted path to the offending key, e.g. `profiles.dev.rules.skipReview`. */
	key: string;
	message: string;
}

export type ParseResult = { ok: true; document: ConfigDocument } | { ok: false; errors: Diagnostic[] };

/**
 * Keys a project file may not contain **at all**, with the reason.
 *
 * Presence, not value, is the test. The four prose lists have no partial order
 * a merge could check -- "append only" is a syntactic superset, not a semantic
 * tightening -- so the only sound rule is that a repository never contributes
 * one. `skipReview` is an allow verdict, and `reviewer` decides who judges.
 */
const PROJECT_FORBIDDEN: Record<string, string> = {
	"sandbox.grantableReadDeny": "grantableReadDeny authorizes one-shot read widening and is therefore user-global only.",
	"rules.skipReview": "skipReview is an allow verdict: it bypasses review entirely. User-global only.",
	"review.environment": "prose rulebook entries are user-global only; a repository must not reach the reviewer prompt.",
	"review.hard_deny": "prose rulebook entries are user-global only; a repository must not reach the reviewer prompt.",
	"review.soft_deny": "prose rulebook entries are user-global only; a repository must not reach the reviewer prompt.",
	"review.allow": "prose rulebook entries are user-global only; a repository must not reach the reviewer prompt.",
	reviewer: "the reviewer is immutable below user-global.",
	breaker: "breaker thresholds are immutable below user-global.",
	audit: "audit retention is immutable below user-global.",
	"sandbox.env": "the child environment is user-global only: a project cannot add a variable.",
	profiles: "only a user-global file may define profiles; a project file may select one.",
};

const PROFILE_KEYS = ["sandbox", "rules", "review", "tools", "reviewer", "breaker", "attended", "audit"] as const;
const DOCUMENT_KEYS = ["profile", "profiles", ...PROFILE_KEYS] as const;

const SANDBOX_KEYS = [
	"mode",
	"writableRoots",
	"readDeny",
	"grantableReadDeny",
	"network",
	"capabilities",
	"hostExec",
	"allowPty",
	"env",
] as const;
const RULES_KEYS = ["deny", "ask", "skipReview", "protectedPaths"] as const;
const REVIEW_KEYS = ["trigger", "environment", "hard_deny", "soft_deny", "allow"] as const;

/**
 * Parse one configuration file.
 *
 * `raw` is the parsed JSON, not the text: reading and JSON syntax belong to
 * `sources.ts`, so this function is pure and testable against literals.
 */
export function parseDocument(
	raw: unknown,
	source: SourceId,
	path: string | undefined,
	options: DefaultProfileOptions,
): ParseResult {
	const errors: Diagnostic[] = [];
	const ctx = new ParseContext(errors, source, options);

	const root = ctx.object("", raw);
	if (!root) return { ok: false, errors };

	ctx.rejectUnknown("", root, DOCUMENT_KEYS);
	ctx.rejectForbidden("", root);

	const document: ConfigDocument = { source };
	if (path !== undefined) document.path = path;

	if ("profile" in root) {
		const name = ctx.string("profile", root.profile);
		if (name !== undefined) document.profile = name;
	}

	if ("profiles" in root) {
		const profiles = ctx.object("profiles", root.profiles);
		if (profiles) {
			const parsed: Record<string, ProfilePatch> = {};
			for (const [name, body] of Object.entries(profiles)) {
				const patch = ctx.profile(`profiles.${name}`, body);
				if (patch) parsed[name] = patch;
			}
			document.profiles = parsed;
		}
	}

	// Top-level profile keys are a patch on the selected profile. This is how a
	// project file contributes, and a user-global file may use it too rather
	// than naming a profile it then has to select.
	const hasInlineBody = PROFILE_KEYS.some((key) => key in root);
	if (hasInlineBody) {
		const patch = ctx.profile("", root);
		if (patch) document.patch = patch;
	}

	return errors.length > 0 ? { ok: false, errors } : { ok: true, document };
}

/**
 * Read the three environment variables into a document.
 *
 * Exactly three exist, and any other `PI_ENCLAVE_*` is an error rather than a
 * warning: whoever controls the process environment of an ops runner would
 * otherwise get to probe for variables that do something. Test and benchmark
 * harnesses may read their own variables directly; they are not production
 * configuration.
 */
export function parseEnvironment(env: Record<string, string | undefined>): ParseResult {
	const errors: Diagnostic[] = [];
	const document: ConfigDocument = { source: "env" };

	const known = new Set(["PI_ENCLAVE_ATTENDED", "PI_ENCLAVE_PROFILE", "PI_ENCLAVE_AUTO"]);
	for (const name of Object.keys(env)) {
		if (name.startsWith("PI_ENCLAVE_") && !known.has(name)) {
			errors.push({
				key: name,
				message: `unknown environment variable; the only ones that exist are ${[...known].join(", ")}`,
			});
		}
	}

	const attended = env.PI_ENCLAVE_ATTENDED;
	if (attended !== undefined) {
		if (attended !== "off") {
			errors.push({
				key: "PI_ENCLAVE_ATTENDED",
				message: `only "off" is accepted; attendance can be turned off, never on`,
			});
		} else {
			document.patch = { attended: { mode: "off" } };
		}
	}

	const auto = env.PI_ENCLAVE_AUTO;
	if (auto !== undefined) {
		if (auto !== "off") {
			errors.push({ key: "PI_ENCLAVE_AUTO", message: `only "off" is accepted; there is no "on"` });
		} else {
			document.auto = false;
		}
	}

	const profile = env.PI_ENCLAVE_PROFILE;
	if (profile !== undefined) {
		if (profile.trim() === "") {
			errors.push({ key: "PI_ENCLAVE_PROFILE", message: "must name a profile defined in the user-global file" });
		} else {
			document.profile = profile;
		}
	}

	return errors.length > 0 ? { ok: false, errors } : { ok: true, document };
}

// ---------------------------------------------------------------------------
// The parser
// ---------------------------------------------------------------------------

type Obj = Record<string, unknown>;

class ParseContext {
	constructor(
		private readonly errors: Diagnostic[],
		private readonly source: SourceId,
		private readonly options: DefaultProfileOptions,
	) {}

	private error(key: string, message: string) {
		this.errors.push({ key: key || "<root>", message });
	}

	object(key: string, value: unknown): Obj | undefined {
		if (typeof value !== "object" || value === null || Array.isArray(value)) {
			this.error(key, `expected an object, got ${describe(value)}`);
			return undefined;
		}
		return value as Obj;
	}

	string(key: string, value: unknown): string | undefined {
		if (typeof value !== "string") {
			this.error(key, `expected a string, got ${describe(value)}`);
			return undefined;
		}
		return value;
	}

	boolean(key: string, value: unknown): boolean | undefined {
		if (typeof value !== "boolean") {
			this.error(key, `expected true or false, got ${describe(value)}`);
			return undefined;
		}
		return value;
	}

	integer(key: string, value: unknown, min: number, max: number): number | undefined {
		if (typeof value !== "number" || !Number.isInteger(value)) {
			this.error(key, `expected a whole number, got ${describe(value)}`);
			return undefined;
		}
		if (value < min || value > max) {
			this.error(key, `must be between ${min} and ${max}, got ${value}`);
			return undefined;
		}
		return value;
	}

	enum<T extends string>(key: string, value: unknown, allowed: readonly T[]): T | undefined {
		if (typeof value !== "string" || !allowed.includes(value as T)) {
			this.error(key, `must be one of ${allowed.map((v) => `"${v}"`).join(", ")}, got ${describe(value)}`);
			return undefined;
		}
		return value as T;
	}

	/**
	 * A list of strings with `"$defaults"` spliced in place.
	 *
	 * A malformed entry rejects the list rather than being dropped. automode
	 * keeps the defaults and carries on, which is the conservative choice for a
	 * classifier hint; here a dropped entry is a rule the user believes is in
	 * force, so silence is the wrong direction.
	 */
	list(key: string, value: unknown, listPath: string): string[] | undefined {
		if (!Array.isArray(value)) {
			this.error(key, `expected an array of strings, got ${describe(value)}`);
			return undefined;
		}
		const out: string[] = [];
		let bad = false;
		value.forEach((entry, index) => {
			if (typeof entry !== "string") {
				this.error(`${key}[${index}]`, `expected a string, got ${describe(entry)}`);
				bad = true;
				return;
			}
			if (entry === "$defaults") {
				out.push(...defaultListFor(listPath, this.options));
				return;
			}
			if (entry.trim() === "") {
				this.error(`${key}[${index}]`, "empty entry");
				bad = true;
				return;
			}
			out.push(entry);
		});
		if (bad) return undefined;
		// Order is preserved and duplicates collapse to their first occurrence,
		// so `["$defaults", …]` and a hand-repeated default read the same.
		return [...new Set(out)];
	}

	rejectUnknown(prefix: string, value: Obj, allowed: readonly string[]) {
		for (const key of Object.keys(value)) {
			if (!allowed.includes(key)) {
				this.error(join(prefix, key), `unknown key; expected one of ${allowed.join(", ")}`);
			}
		}
	}

	/**
	 * Refuse a key a project file may not contain, whatever its value.
	 *
	 * Checked before the value is even looked at: a `soft_deny` that reads as
	 * tightening is still a repository-supplied string in a reviewer prompt.
	 */
	rejectForbidden(prefix: string, value: Obj) {
		if (!isProjectSource(this.source)) return;
		for (const [forbidden, reason] of Object.entries(PROJECT_FORBIDDEN)) {
			// Each object checks only the keys that live directly on it, so
			// `rules.skipReview` is caught when parsing `rules`, not at the root.
			const relative = relativeKey(prefix, forbidden);
			if (relative === undefined || relative.includes(".") || !(relative in value)) continue;
			this.error(join(prefix, relative), `${SOURCE_LABELS[this.source]} may not set this: ${reason}`);
		}
	}

	profile(prefix: string, raw: unknown): ProfilePatch | undefined {
		const body = this.object(prefix, raw);
		if (!body) return undefined;
		this.rejectUnknown(prefix, body, prefix === "" ? DOCUMENT_KEYS : PROFILE_KEYS);
		this.rejectForbidden(prefix, body);

		const patch: ProfilePatch = {};

		if ("sandbox" in body) {
			const sandbox = this.sandbox(join(prefix, "sandbox"), body.sandbox);
			if (sandbox) patch.sandbox = sandbox;
		}
		if ("rules" in body) {
			const rules = this.rules(join(prefix, "rules"), body.rules);
			if (rules) patch.rules = rules;
		}
		if ("review" in body) {
			const review = this.review(join(prefix, "review"), body.review);
			if (review) patch.review = review;
		}
		if ("tools" in body) {
			const tools = this.tools(join(prefix, "tools"), body.tools);
			if (tools) patch.tools = tools;
		}
		if ("reviewer" in body) {
			const reviewer = this.reviewer(join(prefix, "reviewer"), body.reviewer);
			if (reviewer) patch.reviewer = reviewer;
		}
		if ("breaker" in body) {
			const breaker = this.breaker(join(prefix, "breaker"), body.breaker);
			if (breaker) patch.breaker = breaker;
		}
		if ("attended" in body) {
			const attended = this.attended(join(prefix, "attended"), body.attended);
			if (attended) patch.attended = attended;
		}
		if ("audit" in body) {
			const audit = this.audit(join(prefix, "audit"), body.audit);
			if (audit) patch.audit = audit;
		}

		return patch;
	}

	private sandbox(prefix: string, raw: unknown): ProfilePatch["sandbox"] | undefined {
		const body = this.object(prefix, raw);
		if (!body) return undefined;
		this.rejectUnknown(prefix, body, SANDBOX_KEYS);
		this.rejectForbidden(prefix, body);

		const out: NonNullable<ProfilePatch["sandbox"]> = {};

		if ("mode" in body) {
			const mode = this.enum(join(prefix, "mode"), body.mode, ["workspace-write"] as const);
			if (mode) out.mode = mode;
		}
		if ("writableRoots" in body) {
			const roots = this.list(join(prefix, "writableRoots"), body.writableRoots, "sandbox.writableRoots");
			if (roots) out.writableRoots = roots;
		}
		if ("readDeny" in body) {
			const deny = this.list(join(prefix, "readDeny"), body.readDeny, "sandbox.readDeny");
			if (deny) out.readDeny = deny;
		}
		if ("grantableReadDeny" in body) {
			const deny = this.list(join(prefix, "grantableReadDeny"), body.grantableReadDeny, "sandbox.grantableReadDeny");
			if (deny) out.grantableReadDeny = deny;
		}
		if ("network" in body) {
			const network = this.object(join(prefix, "network"), body.network);
			if (network) {
				this.rejectUnknown(join(prefix, "network"), network, ["mode", "allowHosts"]);
				const parsed: NonNullable<NonNullable<ProfilePatch["sandbox"]>["network"]> = {};
				if ("mode" in network) {
					const mode = this.enum(join(prefix, "network.mode"), network.mode, ["off"] as const);
					if (mode) parsed.mode = mode;
				}
				if ("allowHosts" in network) {
					const hosts = this.list(join(prefix, "network.allowHosts"), network.allowHosts, "sandbox.network.allowHosts");
					if (hosts) {
						if (hosts.length > 0) {
							this.error(
								join(prefix, "network.allowHosts"),
								'the egress proxy is Phase 4; only an empty allowlist is accepted, and network.mode is "off"',
							);
						} else {
							parsed.allowHosts = hosts;
						}
					}
				}
				out.network = parsed;
			}
		}
		if ("capabilities" in body) {
			const capabilities = this.enum<CapabilityMode>(join(prefix, "capabilities"), body.capabilities, [
				"none",
				"reviewed",
			]);
			if (capabilities) out.capabilities = capabilities;
		}
		if ("hostExec" in body) {
			const hostExec = this.enum<HostExecMode>(join(prefix, "hostExec"), body.hostExec, ["never", "human"]);
			if (hostExec === "human") {
				this.error(
					join(prefix, "hostExec"),
					'"human" needs the L4 host-execution path, which is Phase 5; only "never" is accepted',
				);
			} else if (hostExec) {
				out.hostExec = hostExec;
			}
		}
		if ("allowPty" in body) {
			const allowPty = this.boolean(join(prefix, "allowPty"), body.allowPty);
			if (allowPty !== undefined) out.allowPty = allowPty;
		}
		if ("env" in body) {
			const env = this.object(join(prefix, "env"), body.env);
			if (env) {
				this.rejectUnknown(join(prefix, "env"), env, ["passthrough", "envDeny"]);
				const parsed: NonNullable<NonNullable<ProfilePatch["sandbox"]>["env"]> = {};
				if ("passthrough" in env) {
					const names = this.list(join(prefix, "env.passthrough"), env.passthrough, "sandbox.env.passthrough");
					if (names) parsed.passthrough = names;
				}
				if ("envDeny" in env) {
					const names = this.list(join(prefix, "env.envDeny"), env.envDeny, "sandbox.env.envDeny");
					if (names) parsed.envDeny = names;
				}
				out.env = parsed;
			}
		}

		return out;
	}

	private rules(prefix: string, raw: unknown): ProfilePatch["rules"] | undefined {
		const body = this.object(prefix, raw);
		if (!body) return undefined;
		this.rejectUnknown(prefix, body, RULES_KEYS);
		this.rejectForbidden(prefix, body);

		const out: NonNullable<ProfilePatch["rules"]> = {};
		for (const key of ["deny", "ask", "skipReview"] as const) {
			if (!(key in body)) continue;
			const list = this.list(join(prefix, key), body[key], `rules.${key}`);
			if (list) out[key] = list;
		}
		if ("protectedPaths" in body) {
			const protectedPaths = this.object(join(prefix, "protectedPaths"), body.protectedPaths);
			if (protectedPaths) {
				this.rejectUnknown(join(prefix, "protectedPaths"), protectedPaths, ["deny", "ask"]);
				const parsed: NonNullable<NonNullable<ProfilePatch["rules"]>["protectedPaths"]> = {};
				for (const key of ["deny", "ask"] as const) {
					if (!(key in protectedPaths)) continue;
					const list = this.list(
						join(prefix, `protectedPaths.${key}`),
						protectedPaths[key],
						`rules.protectedPaths.${key}`,
					);
					if (list) parsed[key] = list;
				}
				out.protectedPaths = parsed;
			}
		}
		return out;
	}

	private review(prefix: string, raw: unknown): ProfilePatch["review"] | undefined {
		const body = this.object(prefix, raw);
		if (!body) return undefined;
		this.rejectUnknown(prefix, body, REVIEW_KEYS);
		this.rejectForbidden(prefix, body);

		const out: NonNullable<ProfilePatch["review"]> = {};
		if ("trigger" in body) {
			const trigger = this.enum<ReviewTrigger>(join(prefix, "trigger"), body.trigger, ["boundary", "mutating", "all"]);
			if (trigger) out.trigger = trigger;
		}
		for (const key of ["environment", "hard_deny", "soft_deny", "allow"] as const) {
			if (!(key in body)) continue;
			const list = this.list(join(prefix, key), body[key], `review.${key}`);
			if (list) out[key] = list;
		}
		return out;
	}

	private tools(prefix: string, raw: unknown): ProfilePatch["tools"] | undefined {
		const body = this.object(prefix, raw);
		if (!body) return undefined;
		this.rejectUnknown(prefix, body, ["allow"]);
		if (!("allow" in body)) return {};

		const allow = this.object(join(prefix, "allow"), body.allow);
		if (!allow) return undefined;

		const parsed: Record<string, ToolGrant> = {};
		for (const [name, value] of Object.entries(allow)) {
			const key = join(prefix, `allow.${name}`);
			const grantBody = this.object(key, value);
			if (!grantBody) continue;
			this.rejectUnknown(key, grantBody, ["readOnly", "reviewed", "source"]);
			const grant: ToolGrant = {};
			if ("readOnly" in grantBody) {
				const readOnly = this.boolean(join(key, "readOnly"), grantBody.readOnly);
				if (readOnly !== undefined) grant.readOnly = readOnly;
			}
			if ("reviewed" in grantBody) {
				const reviewed = this.boolean(join(key, "reviewed"), grantBody.reviewed);
				if (reviewed !== undefined) grant.reviewed = reviewed;
			}
			if ("source" in grantBody) {
				const src = this.string(join(key, "source"), grantBody.source);
				if (src !== undefined) grant.source = src;
			}
			if (grant.readOnly && grant.reviewed) {
				this.error(key, "a tool cannot be both readOnly and reviewed; reviewed is the narrower of the two");
			}
			parsed[name] = grant;
		}
		return { allow: parsed };
	}

	private reviewer(prefix: string, raw: unknown): ProfilePatch["reviewer"] | undefined {
		const body = this.object(prefix, raw);
		if (!body) return undefined;
		this.rejectUnknown(prefix, body, ["model", "timeoutMs", "fallback"]);

		const out: NonNullable<ProfilePatch["reviewer"]> = {};
		if ("model" in body) {
			const model = this.string(join(prefix, "model"), body.model);
			if (model !== undefined) {
				if (!isReviewerModelSetting(model)) {
					this.error(join(prefix, "model"), 'must be "none" or an explicit "provider/model-id"');
				} else {
					out.model = model;
				}
			}
		}
		if ("timeoutMs" in body) {
			const timeout = this.integer(join(prefix, "timeoutMs"), body.timeoutMs, 1, 600_000);
			if (timeout !== undefined) out.timeoutMs = timeout;
		}
		if ("fallback" in body) {
			const fallback = this.string(join(prefix, "fallback"), body.fallback);
			if (fallback !== undefined) {
				if (!isReviewerModelSetting(fallback)) {
					this.error(join(prefix, "fallback"), 'must be "none" or an explicit "provider/model-id"');
				} else {
					out.fallback = fallback;
				}
			}
		}
		return out;
	}

	private breaker(prefix: string, raw: unknown): ProfilePatch["breaker"] | undefined {
		const body = this.object(prefix, raw);
		if (!body) return undefined;
		this.rejectUnknown(prefix, body, ["consecutive", "window"]);

		const out: NonNullable<ProfilePatch["breaker"]> = {};
		if ("consecutive" in body) {
			const consecutive = this.integer(join(prefix, "consecutive"), body.consecutive, 1, 1000);
			if (consecutive !== undefined) out.consecutive = consecutive;
		}
		if ("window" in body) {
			const window = body.window;
			if (!Array.isArray(window) || window.length !== 2) {
				this.error(join(prefix, "window"), "expected [maxAdverse, windowSize]");
			} else {
				const maxAdverse = this.integer(join(prefix, "window[0]"), window[0], 1, 10_000);
				const size = this.integer(join(prefix, "window[1]"), window[1], 1, 10_000);
				if (maxAdverse !== undefined && size !== undefined) {
					if (maxAdverse > size) {
						this.error(join(prefix, "window"), `maxAdverse (${maxAdverse}) cannot exceed the window size (${size})`);
					} else {
						out.window = [maxAdverse, size];
					}
				}
			}
		}
		return out;
	}

	private attended(prefix: string, raw: unknown): ProfilePatch["attended"] | undefined {
		const body = this.object(prefix, raw);
		if (!body) return undefined;
		this.rejectUnknown(prefix, body, ["mode", "confirmTimeoutMs"]);

		const out: NonNullable<ProfilePatch["attended"]> = {};
		if ("mode" in body) {
			const mode = this.enum<AttendedMode>(join(prefix, "mode"), body.mode, ["tui", "rpc", "off"]);
			if (mode) out.mode = mode;
		}
		if ("confirmTimeoutMs" in body) {
			// Zero is not allowed: a confirm that expires immediately is a deny
			// wearing a dialog, and it would show as "attended" in the status line.
			const timeout = this.integer(join(prefix, "confirmTimeoutMs"), body.confirmTimeoutMs, 1_000, 3_600_000);
			if (timeout !== undefined) out.confirmTimeoutMs = timeout;
		}
		return out;
	}

	private audit(prefix: string, raw: unknown): ProfilePatch["audit"] | undefined {
		const body = this.object(prefix, raw);
		if (!body) return undefined;
		this.rejectUnknown(prefix, body, ["retentionDays", "retentionMb"]);

		const out: NonNullable<ProfilePatch["audit"]> = {};
		if ("retentionDays" in body) {
			const days = this.integer(join(prefix, "retentionDays"), body.retentionDays, 1, 3650);
			if (days !== undefined) out.retentionDays = days;
		}
		if ("retentionMb" in body) {
			const mb = this.integer(join(prefix, "retentionMb"), body.retentionMb, 1, 100_000);
			if (mb !== undefined) out.retentionMb = mb;
		}
		return out;
	}
}

function join(prefix: string, key: string): string {
	return prefix === "" ? key : `${prefix}.${key}`;
}

/** `relativeKey("sandbox", "sandbox.env")` is `"env"`; an unrelated prefix gives undefined. */
function relativeKey(prefix: string, dotted: string): string | undefined {
	if (prefix === "") return dotted;
	return dotted.startsWith(`${prefix}.`) ? dotted.slice(prefix.length + 1) : undefined;
}

function describe(value: unknown): string {
	if (value === null) return "null";
	if (Array.isArray(value)) return "an array";
	return typeof value;
}

/** Render diagnostics for stderr and the status report. */
export function formatDiagnostics(source: SourceId, path: string | undefined, errors: readonly Diagnostic[]): string {
	const where = path ?? SOURCE_LABELS[source];
	const lines = [`pi-enclave: ${where} was rejected; auto mode will not start.`];
	for (const error of errors) lines.push(`  ${error.key}: ${error.message}`);
	lines.push("  Nothing was applied. A half-applied configuration is harder to reason about than none.");
	return lines.join("\n");
}
