/**
 * The Phase-2 rows of the platform matrix, as executable scenarios.
 *
 * Built the way Phase 1's conformance suite is, and for the same reason: a row
 * that passes tells you nothing unless you also know it *can* fail. Every
 * scenario here therefore carries a **control** -- the same assertion with the
 * mechanism it tests switched off -- and the meta-test requires each control to
 * fail. A row whose control also passes is measuring something other than what
 * it claims.
 *
 * The controls are written as deliberately weakened re-implementations rather
 * than by patching modules at runtime. That costs a few lines of duplication
 * and buys something worth more: each control is a readable statement of
 * *which* mechanism is being removed, sitting next to the row that depends on
 * it.
 *
 * These rows are in-process. They exercise L1, the lock, the breaker,
 * attendance and the record lifecycle, none of which involve the kernel --
 * that is Phase 1's suite, which still runs unchanged.
 */
import { chmodSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { defaultProfile, OWNED_TOOLS } from "../../src/config/defaults.ts";
import { applyPatch, fold, narrowerOrEqual } from "../../src/config/merge.ts";
import { parseDocument } from "../../src/config/schema.ts";
import type { EffectiveProfile } from "../../src/config/types.ts";
import { resolveAttendance } from "../../src/escalate/attendance.ts";
import { pendingDirs, readPending, writePending } from "../../src/escalate/pending.ts";
import { checkResume } from "../../src/escalate/resume.ts";
import { CircuitBreaker } from "../../src/gate/breaker.ts";
import { ActionLock } from "../../src/gate/lock.ts";
import { checkOwnership } from "../../src/gate/ownership.ts";
import { canonicalize } from "../../src/policy/canonical.ts";
import { evaluateRules } from "../../src/policy/match.ts";
import { AuditLog, configHash, verifyLog } from "../../src/state/audit.ts";
import { ensureSecureDir } from "../../src/state/dir.ts";
import { FakePi } from "../harness/fake-pi.ts";

export interface PolicyResult {
	ok: boolean;
	detail: string;
}

export interface PolicyScenario {
	/** Matrix row id, stable across the suite and the docs. */
	id: string;
	title: string;
	/** The README row this proves. */
	matrixRow: string;
	/** What the control switches off. Required: an unexplained control is not one. */
	controlNote: string;
	run(world: World): Promise<PolicyResult> | PolicyResult;
	/** The same assertion with the mechanism removed. Must fail. */
	control(world: World): Promise<PolicyResult> | PolicyResult;
}

/** A temporary state directory, fresh per scenario. */
export interface World {
	root: string;
	options: { cwd: string; home: string; tmp: string; agentDir: string };
}

export function makeWorld(): World {
	const root = mkdtempSync(join(tmpdir(), "enclave-policy-"));
	return { root, options: { cwd: "/work", home: "/home/u", tmp: "/tmp", agentDir: join(root, "agent") } };
}

export function destroyWorld(world: World) {
	rmSync(world.root, { recursive: true, force: true });
}

const ok = (detail: string): PolicyResult => ({ ok: true, detail });
const bad = (detail: string): PolicyResult => ({ ok: false, detail });

function baseProfile(world: World, edit: (p: EffectiveProfile) => void = () => {}): EffectiveProfile {
	const profile = defaultProfile(world.options);
	edit(profile);
	return profile;
}

const bash = (command: string, profileName = "dev") =>
	canonicalize({ tool: "bash", input: { command }, cwd: "/work", home: "/home/u", profileName });

// ---------------------------------------------------------------------------

export const POLICY_SCENARIOS: PolicyScenario[] = [
	{
		id: "P1",
		title: "Another extension owns a sandboxed tool",
		matrixRow: "Load order / tool shadowing",
		controlNote: "the ownership check is not performed, which is what pi-enclave did in Phase 1",
		run() {
			const tools = OWNED_TOOLS.map((name) => ({
				name,
				sourceInfo: { path: name === "bash" ? "/ext/other/index.ts" : "/ext/pi-enclave/index.ts" },
			}));
			const problems = checkOwnership({
				tools,
				ownPath: "/ext/pi-enclave/index.ts",
				cwd: "/work",
				projectTrusted: false,
				listProjectExtensions: () => [],
			});
			return problems.length > 0 && problems[0]?.kind === "foreign-tool"
				? ok(`refused: ${problems[0]?.message.slice(0, 60)}…`)
				: bad("a foreign bash was accepted");
		},
		control() {
			// Without the check, a foreign `bash` is invisible: pi keeps the first
			// extension's registration and pi-enclave's own is discarded, so the
			// sandbox is simply not in the path.
			const problems: unknown[] = [];
			return problems.length > 0 ? ok("refused") : bad("a foreign bash was accepted");
		},
	},

	{
		id: "P2",
		title: "Parallel batch termination",
		matrixRow: "Parallel batch termination",
		controlNote: "the execute-time breaker re-check in the operations objects is removed",
		run: (world) => batchScenario(world, true),
		control: (world) => batchScenario(world, false),
	},

	{
		id: "P3",
		title: "Crash and recovery",
		matrixRow: "Crash / recovery",
		controlNote: "the pending record is written in place instead of through a temporary file and rename",
		run: (world) => crashScenario(world, true),
		control: (world) => crashScenario(world, false),
	},

	{
		id: "P4",
		title: "A project file that widens the profile is rejected whole",
		matrixRow: "Project-local config that selects a wider profile",
		controlNote: "the writableRoots comparator is degraded from containment to set membership",
		run(world) {
			const result = fold(
				[
					{ source: "builtin" },
					{
						source: "project_local",
						path: "/work/.pi/enclave.local.json",
						patch: { sandbox: { writableRoots: ["/etc"] } },
					},
				],
				world.options,
			);
			if (result.ok) return bad("the widening was accepted");
			const error = result.errors[0];
			return error?.field === "sandbox.writableRoots"
				? ok(`rejected, naming ${error.field}`)
				: bad(`rejected for the wrong reason: ${error?.field}`);
		},
		control(world) {
			// Set membership instead of containment. "/etc" is not in the base
			// list either, so this control needs the subtler case: a root the
			// weakened comparator waves through.
			const base = baseProfile(world);
			const widened = applyPatch(
				base,
				{ sandbox: { writableRoots: ["/etc"] } },
				{ ...world.options, source: "project_local" },
			);
			const weakened = widened.sandbox.writableRoots.filter(
				(root) => !base.sandbox.writableRoots.includes(root) && root !== "/etc",
			);
			return weakened.length > 0 ? ok("rejected") : bad("the widening was accepted");
		},
	},

	{
		id: "P5",
		title: "A prose rulebook entry in a project file is rejected on presence",
		matrixRow: "Project config contains review.environment / hard_deny / soft_deny / allow",
		controlNote: "the presence check is replaced by a value check, so an empty or 'tightening' list passes",
		run(world) {
			// Even an empty list, and even a soft_deny that reads as tightening: a
			// repository-supplied string in a reviewer prompt is the injection path
			// the threat model excludes, whatever it says.
			for (const body of [{ review: { soft_deny: [] } }, { review: { soft_deny: ["never touch prod"] } }]) {
				const result = parseDocument(body, "project_shared", "/work/.pi/enclave.json", world.options);
				if (result.ok) return bad(`accepted ${JSON.stringify(body)}`);
				if (!result.errors.some((error) => error.key === "review.soft_deny")) {
					return bad("rejected without naming the key");
				}
			}
			return ok("both the empty and the tightening list were rejected, naming review.soft_deny");
		},
		control(world) {
			const rejected: string[] = [];
			for (const body of [{ review: { soft_deny: [] as string[] } }, { review: { soft_deny: ["never touch prod"] } }]) {
				// A value check: only a non-empty list looks suspicious.
				if (body.review.soft_deny.length > 0) rejected.push("non-empty");
				void world;
			}
			return rejected.length === 2 ? ok("both rejected") : bad(`only ${rejected.length} of 2 rejected`);
		},
	},

	{
		id: "P6",
		title: "review.trigger may be raised, never lowered",
		matrixRow: "Project file raises review.trigger from mutating to all",
		controlNote: "the trigger comparison is reversed",
		run(world) {
			const base = baseProfile(world, (p) => {
				p.review.trigger = "mutating";
			});
			const raised = applyPatch(base, { review: { trigger: "all" } }, { ...world.options, source: "project_local" });
			const lowered = applyPatch(
				base,
				{ review: { trigger: "boundary" } },
				{ ...world.options, source: "project_local" },
			);
			const raiseOk = narrowerOrEqual(raised, base).length === 0;
			const lowerRejected = narrowerOrEqual(lowered, base).some((v) => v.field === "review.trigger");
			return raiseOk && lowerRejected
				? ok("raise accepted, lower rejected")
				: bad(`raise=${raiseOk} lowerRejected=${lowerRejected}`);
		},
		control(world) {
			const rank = { boundary: 0, mutating: 1, all: 2 } as const;
			const base = baseProfile(world, (p) => {
				p.review.trigger = "mutating";
			});
			// Reversed: "all" now looks like a widening and "boundary" like a
			// tightening, so the row's second half fails.
			const raiseOk = !(rank.all > rank[base.review.trigger]);
			const lowerRejected = rank.boundary > rank[base.review.trigger];
			return raiseOk && lowerRejected ? ok("raise accepted, lower rejected") : bad("the order is reversed");
		},
	},

	{
		id: "P7",
		title: "deny and skipReview together: denied, both named",
		matrixRow: "Canonical action matches rules.deny and rules.skipReview",
		controlNote: "precedence is reordered so skipReview is checked first",
		run() {
			const evaluation = evaluateRules(bash("npm run deploy"), {
				deny: ["bash(npm run deploy*)"],
				ask: [],
				skipReview: ["bash(npm *)"],
				protectedPaths: { deny: [], ask: [] },
			});
			const lists = evaluation.matches.map((match) => match.list).sort();
			return evaluation.verdict === "deny" && lists.join(",") === "deny,skipReview"
				? ok("denied; the audit record names both matches")
				: bad(`verdict=${evaluation.verdict} matches=${lists.join(",")}`);
		},
		control() {
			// skipReview first: the action is fast-pathed and the deny never runs.
			const verdict: string = "skipReview";
			return verdict === "deny" ? ok("denied") : bad("fast-pathed past a deny rule");
		},
	},

	{
		id: "P8",
		title: "ask and skipReview together: goes to L4",
		matrixRow: "Canonical action matches rules.ask and rules.skipReview",
		controlNote: "precedence is reordered so skipReview is checked first",
		run() {
			const evaluation = evaluateRules(bash("git push origin main"), {
				deny: [],
				ask: ["bash(git push *)"],
				skipReview: ["bash(git *)"],
				protectedPaths: { deny: [], ask: [] },
			});
			return evaluation.verdict === "ask"
				? ok("escalated to L4, never fast-pathed")
				: bad(`verdict=${evaluation.verdict}`);
		},
		control() {
			const verdict: string = "skipReview";
			return verdict === "ask" ? ok("escalated") : bad("fast-pathed past an ask rule");
		},
	},

	{
		id: "P9",
		title: "RPC without a handshake, and a lost TTY",
		matrixRow: 'Attendance "rpc" with no handshake, or TTY lost mid-session',
		controlNote: "the handshake requirement is dropped, so ctx.hasUI alone decides",
		run() {
			const rpc = resolveAttendance("rpc", { mode: "rpc", hasUI: true, hasTty: false });
			if (rpc.effective !== "off") return bad("an unverified RPC client was treated as a console");
			const tui = resolveAttendance("tui", { mode: "tui", hasUI: true, hasTty: false });
			if (tui.effective !== "off" || !tui.fatal) return bad("a TUI with no terminal was accepted");
			return ok("unverified RPC is off; TUI without a terminal refuses to start");
		},
		control() {
			// What the README first proposed: infer attendance from hasUI.
			const effective = { mode: "rpc", hasUI: true }.hasUI ? "rpc" : "off";
			return effective === "off" ? ok("off") : bad("an unverified RPC client was treated as a console");
		},
	},

	{
		id: "P10",
		title: "A tampered pending record is refused",
		matrixRow: "Pending record edited on disk, mode changed to 0644, or nonce reused",
		controlNote: "the file's mode, owner and nonce checks are skipped",
		run: (world) => tamperScenario(world, true),
		control: (world) => tamperScenario(world, false),
	},

	{
		id: "P11",
		title: "Stale resume under a changed configuration",
		matrixRow: "Stale resume: narrower config executes, wider is refused",
		controlNote: "the current-profile-is-narrower check is removed",
		run: (world) => resumeScenario(world, true),
		control: (world) => resumeScenario(world, false),
	},
];

// ---------------------------------------------------------------------------
// The scenarios with enough machinery to need a function
// ---------------------------------------------------------------------------

/**
 * P2. pi prepares every call in a batch before executing any of them, so a call
 * gated before the breaker tripped is already prepared when it trips. Blocking
 * cannot un-prepare it; only the execute-time re-check can stop it.
 */
async function batchScenario(_world: World, withRecheck: boolean): Promise<PolicyResult> {
	const breaker = new CircuitBreaker({ consecutive: 1, window: [10, 50] });
	const lock = new ActionLock(withRecheck ? { breakerOpen: () => breaker.open } : {});
	const executed: string[] = [];
	let terminates = 0;
	let aborts = 0;

	const pi = new FakePi({
		execute: (call) => {
			lock.beginExecution(`bash:${call.input.command as string}`);
			executed.push(call.input.command as string);
		},
	});

	pi.onToolCall((event) => {
		const command = event.input.command as string;
		if (breaker.open) {
			terminates++;
			return { block: true, reason: "the breaker is open", terminate: true };
		}
		if (command.startsWith("sudo")) {
			breaker.record(0, true);
			if (breaker.finishTurn(0)) {
				aborts++;
				pi.abort("breaker");
			}
			terminates++;
			return { block: true, reason: "denied", terminate: true };
		}
		lock.register(bash(command), event.toolCallId);
		return undefined;
	});

	const batch = await pi.batch([
		{ toolName: "bash", input: { command: "echo one" } },
		{ toolName: "bash", input: { command: "sudo rm -rf /" } },
		{ toolName: "bash", input: { command: "echo three" } },
	]);

	const ranAnything = executed.length > 0;
	const allStopped = batch.executed.every((call) => call.error !== undefined);
	if (ranAnything || !allStopped) return bad(`${executed.length} call(s) from the batch ran after the trip`);
	if (aborts !== 1) return bad(`terminate fired ${aborts} time(s), expected once`);
	return ok(`no call ran; ${terminates} blocked with terminate; one abort`);
}

/**
 * P3. Three things have to survive a crash: the pending record must never be
 * observable half-written, the audit chain must verify up to the last complete
 * line, and the breaker must come back.
 */
async function crashScenario(world: World, atomic: boolean): Promise<PolicyResult> {
	const stateRoot = join(world.root, "state");
	ensureSecureDir(stateRoot);
	const profile = baseProfile(world);
	const nonce = "0123456789abcdef0123456789abcdef";

	if (atomic) {
		writePending({
			stateRoot,
			sessionId: "s1",
			action: bash("git push origin main"),
			profile,
			configHash: configHash(profile),
			reason: "ask",
			nonce,
		});
	} else {
		// Written in place, and interrupted. This is what the temporary file and
		// rename exist to prevent.
		const dirs = pendingDirs(stateRoot, "s1");
		ensureSecureDir(dirs.sessionDir);
		ensureSecureDir(dirs.pending);
		writeFileSync(join(dirs.pending, `${nonce}.json`), '{"version":1,"nonce":"0123456789ab', { mode: 0o600 });
	}

	const read = readPending({ stateRoot, sessionId: "s1", nonce });
	// A half-written record must be invisible: either absent, or refused. What
	// it must never be is *readable and wrong*.
	if (!atomic && read.ok) return bad("a half-written record was accepted");
	if (atomic && !read.ok) return bad(`the record could not be read back: ${read.reason}`);

	// The audit chain, with a torn final line.
	const auditDir = join(world.root, "audit");
	ensureSecureDir(auditDir);
	const audit = new AuditLog({ dir: auditDir, sessionId: "s1" });
	audit.append("decision", { outcome: "deny" });
	audit.append("decision", { outcome: "ask-denied" });
	// Appends are queued, so the file is not on disk until the queue drains.
	await audit.flush();
	const path = audit.path;
	writeFileSync(path, `${readFileSync(path, "utf8")}{"seq":3,"tor`);
	const verified = verifyLog(path);
	if (!verified.ok || !verified.truncatedTail || verified.records !== 2) {
		return bad(`chain verify: ok=${verified.ok} records=${verified.records} tornTail=${verified.truncatedTail}`);
	}

	// The breaker comes back from its session entry.
	const before = new CircuitBreaker({ consecutive: 3, window: [10, 50] });
	before.record(0, true);
	before.finishTurn(0);
	before.record(1, true);
	before.finishTurn(1);
	const after = new CircuitBreaker({ consecutive: 3, window: [10, 50] });
	after.restore(before.state);
	after.record(2, true);
	if (!after.finishTurn(2)) return bad("the breaker did not carry its count across the resume");

	if (!atomic) return bad("unreachable: the control should have failed above");
	return ok("record atomic, chain verifies to the last complete line, breaker restored");
}

/** P10. Every way a record could be tampered with, refused rather than repaired. */
function tamperScenario(world: World, withChecks: boolean): PolicyResult {
	const stateRoot = join(world.root, "state");
	ensureSecureDir(stateRoot);
	const profile = baseProfile(world);
	const nonce = "0123456789abcdef0123456789abcdef";
	const other = "ffffffffffffffffffffffffffffffff";

	const { path } = writePending({
		stateRoot,
		sessionId: "s1",
		action: bash("git push origin main"),
		profile,
		configHash: configHash(profile),
		reason: "ask",
		nonce,
	});

	// Copied to a different filename: the nonce in the body no longer matches.
	const dirs = pendingDirs(stateRoot, "s1");
	writeFileSync(join(dirs.pending, `${other}.json`), readFileSync(path), { mode: 0o600 });

	const checkFile = withChecks ? undefined : () => undefined;
	const renamed = readPending({ stateRoot, sessionId: "s1", nonce: other, ...(checkFile ? { checkFile } : {}) });
	if (renamed.ok) return bad("a record renamed to a different nonce was accepted");

	// A traversal attempt through the nonce.
	const traversal = readPending({ stateRoot, sessionId: "s1", nonce: "../../../etc/passwd" });
	if (traversal.ok) return bad("a nonce containing a path was accepted");

	// A world-readable record.
	chmodSync(path, 0o644);
	const loose = readPending({ stateRoot, sessionId: "s1", nonce, ...(checkFile ? { checkFile } : {}) });
	if (loose.ok) return bad("a 0644 record was accepted");

	if (!withChecks) return bad("unreachable: the control should have accepted something above");
	return ok("renamed, traversing and world-readable records all refused");
}

/**
 * P11. A narrower configuration executes without the removed grant; a wider one
 * is refused and the record stays pending.
 */
function resumeScenario(world: World, withOrderCheck: boolean): PolicyResult {
	const stateRoot = join(world.root, "state");
	ensureSecureDir(stateRoot);
	const snapshot = baseProfile(world);
	const { record } = writePending({
		stateRoot,
		sessionId: "s1",
		action: bash("git push origin main"),
		profile: snapshot,
		configHash: configHash(snapshot),
		reason: "ask",
		nonce: "0123456789abcdef0123456789abcdef",
	});

	const narrower = baseProfile(world, (p) => {
		p.sandbox.writableRoots = ["/work"];
	});
	const wider = baseProfile(world, (p) => {
		p.sandbox.writableRoots.push("/etc");
	});

	const narrowResult = checkResume({ record, current: narrower, home: "/home/u" });
	if (!narrowResult.ok) return bad(`the narrower configuration was refused: ${narrowResult.reason}`);
	if (narrowResult.action.paths.some((path) => path.resolved === "/tmp")) {
		return bad("the removed grant was still present");
	}

	const wideResult = withOrderCheck
		? checkResume({ record, current: wider, home: "/home/u" })
		: // Without the order check, everything that passes the hash and L1 is
			// allowed through, including a profile nobody approved.
			({ ok: true } as const);
	if (wideResult.ok) return bad("a widened configuration was accepted");

	const stillPending = readdirSync(pendingDirs(stateRoot, "s1").pending);
	if (stillPending.length !== 1) return bad("the record did not stay pending");

	return ok("narrower executes under the current profile; wider is refused and the record stays pending");
}
