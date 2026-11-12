/** Validation for invocation-scoped filesystem capabilities. */
import { isAbsolute, resolve } from "node:path";
import { hostRuntimeSafety } from "../probe-host.ts";
import { canonical, isUnder } from "./paths.ts";
import type { Profile } from "./types.ts";

/** Why a shell-scoped write grant cannot be contained on this platform, if any. */
export function shellWriteCapabilityIssue(platform: NodeJS.Platform = process.platform): string | undefined {
	return shellCapabilityIssue("write", platform);
}

/** Why a shell-scoped grant cannot be contained on this platform, if any. */
export function shellCapabilityIssue(
	kind: "read" | "write",
	platform: NodeJS.Platform = process.platform,
): string | undefined {
	if (platform !== "darwin") return undefined;
	return (
		`pi-enclave: Bash ${kind} capabilities are unavailable on macOS because Seatbelt has no ` +
		"reliable way to reap a child that escapes its process group; the widened profile could outlive the invocation"
	);
}

/** Resolve through existing symlinks so the granted object is the one the kernel sees. */
export function resolveCapabilityTarget(cwd: string, value: string): string {
	return canonical(isAbsolute(value) ? value : resolve(cwd, value));
}

/** True when either path contains the other, considering canonical spellings. */
export function capabilityIntersects(target: string, roots: readonly string[]): string | undefined {
	const resolvedTarget = canonical(target);
	for (const root of roots) {
		const resolvedRoot = canonical(root);
		if (
			isUnder(target, root) ||
			isUnder(root, target) ||
			isUnder(resolvedTarget, resolvedRoot) ||
			isUnder(resolvedRoot, resolvedTarget)
		) {
			return root;
		}
	}
	return undefined;
}

/** What a write capability may reach (#21). */
export interface WriteCapabilityBoundary {
	/** The workspace the action runs in. A target below it is grantable. */
	cwd: string;
	/** User-global `sandbox.grantableWriteRoots`. */
	grantableRoots: readonly string[];
	/** Never grantable, whoever approves, with the reason shown in the refusal. */
	protectedTargets: readonly { path: string; reason: string }[];
}

/**
 * Why a write capability to `target` is not grantable, or undefined.
 *
 * Two rules. A protected target -- one that intersects, either way, a path in
 * the built-in never-grantable list -- is refused whatever else is configured.
 * Otherwise the target must be below the workspace or below a user-global
 * `grantableWriteRoots` entry; with that list empty, nothing outside the
 * workspace is grantable.
 */
export function writeCapabilityBoundaryIssue(target: string, boundary: WriteCapabilityBoundary): string | undefined {
	const resolvedTarget = canonical(target);
	for (const entry of boundary.protectedTargets) {
		if (capabilityIntersects(resolvedTarget, [entry.path])) {
			return (
				`pi-enclave: refusing write capability ${resolvedTarget}: it intersects ${entry.path}, and ${entry.reason}.\n` +
				"  It is on the built-in never-grantable write list, so no approval can lift it."
			);
		}
	}
	const inside = [boundary.cwd, ...boundary.grantableRoots].some(
		(root) => isUnder(target, root) || isUnder(resolvedTarget, canonical(root)),
	);
	if (!inside) {
		return (
			`pi-enclave: refusing write capability ${resolvedTarget}: it is outside the workspace and outside every ` +
			`sandbox.grantableWriteRoots entry (${boundary.grantableRoots.join(", ") || "none configured"}).\n` +
			"  Only the user-global configuration can make a path outside the workspace grantable; no approval can."
		);
	}
	return undefined;
}

/**
 * Return the safe canonical target or throw before a prompt or sandbox wrap.
 *
 * An allow-write bind beneath a Linux read-deny tmpfs re-exposes that host
 * subtree. A grant touching a host PATH directory can also create the next
 * `which`/helper that SRT runs in the privileged parent. Both are immutable
 * boundaries, not things a one-shot capability may lift, and so are the
 * built-in never-grantable write targets and anything outside the workspace
 * and the user-global grantable write roots (#21).
 */
/**
 * A write capability no approval can lift: a never-grantable target, or one
 * outside every grantable root (#21). A type, not a phrase, so the gate can
 * tell it from an ordinary refusal without matching the message text.
 */
export class WriteBoundaryError extends Error {
	override readonly name = "WriteBoundaryError";
}

export function validateWriteCapability(profile: Profile, cwd: string, value: string): string {
	const target = resolveCapabilityTarget(cwd, value);
	// First, so a refusal names why the target is sensitive rather than only
	// the denial it also happens to intersect.
	const boundaryIssue = writeCapabilityBoundaryIssue(target, {
		cwd,
		grantableRoots: profile.grantableWriteRoots ?? [],
		protectedTargets: profile.protectedWrite ?? [],
	});
	if (boundaryIssue) throw new WriteBoundaryError(boundaryIssue);
	const denied = [...profile.readDeny, ...(profile.writeDeny ?? [])];
	const overlap = capabilityIntersects(target, denied);
	if (overlap) {
		throw new Error(`pi-enclave: refusing write capability ${target}: it intersects immutable denied path ${overlap}`);
	}
	const pathSafety = hostRuntimeSafety([...profile.writableRoots, target]);
	if (!pathSafety.ok) {
		throw new Error(`pi-enclave: refusing write capability ${target}: ${pathSafety.detail}`);
	}
	return target;
}

/**
 * Return the exact denied root a read capability may lift.
 *
 * Grantability is checked by the policy gate against the user-global config.
 * The backend repeats the structural half so a caller cannot use this method to
 * remove an arbitrary or merely overlapping denial.
 */
export function validateReadCapability(profile: Profile, cwd: string, value: string): string {
	const target = resolveCapabilityTarget(cwd, value);
	if (target === "/") throw new Error('pi-enclave: refusing read capability "/"');
	const exact = profile.readDeny.find((entry) => canonical(entry) === target);
	if (!exact) {
		throw new Error(`pi-enclave: refusing read capability ${target}: it is not an exact read-deny entry`);
	}
	return target;
}
