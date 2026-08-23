/**
 * The bridge between a configured profile and the backend's.
 *
 * The backend's `Profile` (`backend/types.ts`) is deliberately smaller than an
 * `EffectiveProfile`: it carries only what the kernel is told, and knows
 * nothing about rules, review, attendance or the breaker. Keeping the two apart
 * means a configuration change cannot accidentally alter what gets compiled,
 * and that a backend can be tested against a profile nobody configured.
 */
import type { Profile } from "../backend/types.ts";
import { type DefaultProfileOptions, defaultProfile } from "./defaults.ts";
import type { EffectiveProfile } from "./types.ts";

export { defaultReadDeny } from "./defaults.ts";

/** Everything the sandbox is told, and nothing else. */
export function toBackendProfile(effective: EffectiveProfile): Profile {
	return {
		mode: effective.sandbox.mode,
		writableRoots: [...effective.sandbox.writableRoots],
		readDeny: [...effective.sandbox.readDeny],
		network: effective.sandbox.network.mode,
		allowPty: effective.sandbox.allowPty,
		envPassthrough: [...effective.sandbox.env.passthrough],
		envDeny: [...effective.sandbox.env.envDeny],
	};
}

export interface DevProfileOptions extends DefaultProfileOptions {
	/**
	 * PTY allocation. On by default: Seatbelt denies PTYs unless asked, which
	 * breaks `vim`, `less` and `git log` without a pager override. On Linux the
	 * field is informational only -- bubblewrap cannot deny PTYs.
	 */
	allowPty?: boolean;
}

/**
 * The zero-configuration profile, as a backend profile.
 *
 * Retained from Phase 1 for the benchmark and the conformance fixture, which
 * exercise the backend without a configuration file in sight. Sessions go
 * through `loadConfig` instead.
 */
export function createDevProfile(options: DevProfileOptions): Profile {
	const profile = toBackendProfile(defaultProfile(options));
	if (options.allowPty !== undefined) profile.allowPty = options.allowPty;
	return profile;
}
