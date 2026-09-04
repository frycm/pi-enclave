/** Validation for Phase-2's one invocation-scoped write capability. */
import { isAbsolute, resolve } from "node:path";
import { hostRuntimeSafety } from "../probe-host.ts";
import { canonical, isUnder } from "./paths.ts";
import type { Profile } from "./types.ts";

/** Why a shell-scoped write grant cannot be contained on this platform, if any. */
export function shellWriteCapabilityIssue(platform: NodeJS.Platform = process.platform): string | undefined {
	if (platform !== "darwin") return undefined;
	return (
		"pi-enclave: Bash write capabilities are unavailable on macOS because Seatbelt has no " +
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

/**
 * Return the safe canonical target or throw before a prompt or sandbox wrap.
 *
 * An allow-write bind beneath a Linux read-deny tmpfs re-exposes that host
 * subtree. A grant touching a host PATH directory can also create the next
 * `which`/helper that SRT runs in the privileged parent. Both are immutable
 * boundaries, not things a one-shot capability may lift.
 */
export function validateWriteCapability(profile: Profile, cwd: string, value: string): string {
	const target = resolveCapabilityTarget(cwd, value);
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
