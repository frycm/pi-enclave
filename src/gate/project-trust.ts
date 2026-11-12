/**
 * pi-enclave's answer to pi's project-trust question (#28).
 *
 * Trusting a project makes pi load what the project directory carries: its
 * `.pi/settings.json` (which can set `shellCommandPrefix` and install
 * packages), MCP servers, extensions, skills and prompts. Every one of those
 * runs in, or configures, the pi process, outside the sandbox -- and the
 * agent can write the workspace. A person at the TUI can weigh that; a
 * headless run (print, json, or rpc before any handshake) cannot, and pi's
 * trust store may hold a "yes" given in some earlier interactive session for
 * a directory the agent has since been writing to.
 *
 * So, in auto mode:
 * - headless, for a project not listed in the user-global
 *   `attended.headlessTrust`: "no". Nothing from the project loads.
 * - headless and listed: "undecided", so pi's own rules apply.
 * - in the TUI: "undecided", with a warning that names what trusting would
 *   load, so the person answering pi's prompt knows what they are agreeing to.
 *
 * Only an extension loaded before trust is resolved sees the question, which
 * is a user-global one; a project-local pi-enclave cannot answer it.
 */
import { existsSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { canonical, isUnder } from "../backend/paths.ts";
import type { LoadResult } from "../config/sources.ts";

/** What pi loads from `<cwd>/.pi` once a project is trusted (pi 1.5.2, trust-manager.js). */
const PROJECT_CONFIG_RESOURCES = [
	"settings.json",
	"mcp.json",
	"extensions",
	"skills",
	"prompts",
	"themes",
	"SYSTEM.md",
	"APPEND_SYSTEM.md",
] as const;

/** The project resources trusting `cwd` would load, as display paths. */
export function trustRequiringResources(cwd: string, home = homedir()): string[] {
	const found: string[] = [];
	const configDir = join(cwd, ".pi");
	for (const entry of PROJECT_CONFIG_RESOURCES) {
		const path = join(configDir, entry);
		if (existsSync(path)) found.push(path);
	}
	// `.agents/skills` in the project or any ancestor, as pi walks for them,
	// except the user's own.
	const userSkills = join(home, ".agents", "skills");
	let current = cwd;
	for (;;) {
		const skills = join(current, ".agents", "skills");
		if (skills !== userSkills && existsSync(skills)) found.push(skills);
		const parent = dirname(current);
		if (parent === current) break;
		current = parent;
	}
	return found;
}

export interface TrustQuestion {
	cwd: string;
	mode: "tui" | "rpc" | "json" | "print";
	hasUI: boolean;
	/** The user-global (and environment) configuration; project files are not read. */
	config: LoadResult;
	home?: string;
}

export interface TrustAnswer {
	trusted: "yes" | "no" | "undecided";
	/** For stderr in a headless run, or a notify in the TUI. */
	message?: string;
}

export function answerProjectTrust(question: TrustQuestion): TrustAnswer {
	const headless = question.mode !== "tui" || !question.hasUI;
	const resources = trustRequiringResources(question.cwd, question.home);
	const listing = resources.map((path) => `  ${path}`).join("\n");
	if (!question.config.ok) {
		// No policy to consult. Headless, fail closed; in the TUI the session
		// refuses at session_start anyway, and pi's own prompt still applies.
		return headless
			? {
					trusted: "no",
					message: "pi-enclave: the configuration did not load, so this headless run does not trust the project.",
				}
			: { trusted: "undecided" };
	}
	const profile = question.config.profile;
	// PI_ENCLAVE_AUTO=off is the user taking pi-enclave's L1/L4 out of the loop.
	if (!profile.auto) return { trusted: "undecided" };
	if (headless) {
		const target = canonical(question.cwd);
		const listed = profile.attended.headlessTrust.some((entry) => isUnder(target, canonical(entry)));
		if (listed) return { trusted: "undecided" };
		return {
			trusted: "no",
			message:
				`pi-enclave: not loading project resources from ${question.cwd} in a headless run:\n${listing}\n` +
				"  They would run in, or configure, the pi process outside the sandbox, in a directory the agent can write.\n" +
				"  pi-enclave's own project files (.pi/enclave.json, .pi/enclave.local.json) are not applied either.\n" +
				"  List the project in the user-global attended.headlessTrust to allow it.",
		};
	}
	return {
		trusted: "undecided",
		message:
			`pi-enclave: trusting ${question.cwd} loads these into the pi process, outside the sandbox:\n${listing}\n` +
			"  The agent can write this directory, so what it changes there runs unsandboxed at the next start.",
	};
}
