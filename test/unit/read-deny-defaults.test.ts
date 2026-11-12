/**
 * The default read-deny list for `open` mode (#23): every credential store,
 * history and other-agent path the issue named is denied for a synthetic home.
 */
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { defaultReadDeny } from "../../src/config/defaults.ts";

const HOME = "/home/synthetic";
const AGENT = join(HOME, ".pi", "agent");

describe("the default read-deny list", () => {
	const deny = defaultReadDeny(HOME, AGENT, { XDG_CONFIG_HOME: undefined });
	const inHome = (...parts: string[]) => join(HOME, ...parts);

	it.each([
		// Git and forge credentials.
		inHome(".git-credentials"),
		inHome(".config", "git", "credentials"),
		inHome(".config", "glab-cli"),
		inHome(".config", "hub"),
		inHome(".config", "tea"),
		// Cloud CLIs.
		inHome(".config", "gcloud"),
		inHome(".azure"),
		inHome(".oci"),
		inHome(".config", "doctl"),
		inHome(".config", "hcloud"),
		inHome(".terraform.d", "credentials.tfrc.json"),
		inHome(".terraformrc"),
		inHome(".vault-token"),
		inHome(".config", "sops"),
		inHome(".config", "age"),
		inHome(".config", "rclone"),
		// Package and registry tokens.
		inHome(".pypirc"),
		inHome(".cargo", "credentials.toml"),
		inHome(".gem", "credentials"),
		inHome(".m2", "settings.xml"),
		inHome(".gradle", "gradle.properties"),
		inHome(".composer", "auth.json"),
		inHome(".yarnrc.yml"),
		inHome(".config", "pip"),
		// Databases and services.
		inHome(".pgpass"),
		inHome(".my.cnf"),
		inHome(".mylogin.cnf"),
		inHome(".redis-cli-auth"),
		inHome(".config", "op"),
		inHome(".password-store"),
		inHome(".local", "share", "keyrings"),
		inHome("Library", "Keychains"),
		// Histories.
		inHome(".bash_history"),
		inHome(".zsh_history"),
		inHome(".python_history"),
		inHome(".psql_history"),
		inHome(".mysql_history"),
		inHome(".node_repl_history"),
		inHome(".lesshst"),
		// Other agents and editors.
		inHome(".codex"),
		inHome(".gemini"),
		inHome(".config", "github-copilot"),
		inHome(".cursor"),
		inHome(".continue"),
		inHome(".config", "Code", "User", "globalStorage"),
		inHome(".mozilla"),
		inHome(".config", "google-chrome"),
		// pi itself.
		join(AGENT, "sessions"),
		join(AGENT, "trust.json"),
		join(AGENT, "enclave.json"),
		// Server-side.
		"/etc/letsencrypt",
		"/etc/ssl/private",
		"/run/secrets",
		"/var/run/secrets",
		"/run/credentials",
	])("denies %s", (path) => {
		expect(deny).toContain(path);
	});

	it("follows XDG_CONFIG_HOME for the per-tool config directories", () => {
		const xdg = defaultReadDeny(HOME, AGENT, { XDG_CONFIG_HOME: "/srv/conf" });
		expect(xdg).toContain("/srv/conf/gcloud");
		expect(xdg).toContain("/srv/conf/git/credentials");
	});

	it("does not deny the home directory or the system runtime", () => {
		for (const path of [HOME, "/", "/usr", "/etc", inHome(".config")]) expect(deny).not.toContain(path);
	});
});
