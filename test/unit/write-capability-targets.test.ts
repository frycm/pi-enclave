/**
 * Write capabilities and the trust roots (#21).
 *
 * A one-shot `allow_write` used to be refused only when it intersected a
 * denial or a host PATH directory, so pi-enclave's own policy, pi's
 * extensions and the user's shell startup files were ordinary `high` targets
 * one approval away. These are now never grantable, and nothing outside the
 * workspace is grantable unless the user-global configuration names a root.
 */
import { describe, expect, it } from "vitest";
import { validateWriteCapability, writeCapabilityBoundaryIssue } from "../../src/backend/capability.ts";
import { defaultProfile, OWNED_TOOLS, protectedWriteTargets } from "../../src/config/defaults.ts";
import { fold, narrowerOrEqual } from "../../src/config/merge.ts";
import { toBackendProfile } from "../../src/config/profile.ts";
import type { ConfigDocument, EffectiveProfile, SourceId } from "../../src/config/types.ts";
import { protectLoadedCode } from "../../src/gate/code-roots.ts";
import { ActionLock, decide, type Escalator } from "../../src/gate/gate.ts";
import { canonicalize } from "../../src/policy/canonical.ts";
import { minimumRisk } from "../../src/reviewer/risk.ts";

const HOME = "/home/u";
const AGENT = "/home/u/.pi/agent";
const OPTIONS = { cwd: "/work", home: HOME, tmp: "/tmp", agentDir: AGENT, env: {} };

function profile(edit: (p: EffectiveProfile) => void = () => {}): EffectiveProfile {
	const p = defaultProfile(OPTIONS);
	edit(p);
	return p;
}

/** The six rows the issue found structurally grantable at 6ed822a. */
const TRUST_ROOTS = [
	"/home/u/.pi/agent/enclave.json",
	"/home/u/.pi/agent/settings.json",
	"/home/u/.pi/agent/extensions/evil.ts",
	"/home/u/.bashrc",
	"/home/u/.gitconfig",
	"/home/u/.config/systemd/user/x.service",
];

describe("the never-grantable write list (#21)", () => {
	it.each(TRUST_ROOTS)("refuses %s even below a grantable root", (target) => {
		// "/home/u" as a grantable root is the widest a user can make it; the
		// built-in list still applies inside.
		const backend = toBackendProfile(
			profile((p) => {
				p.sandbox.grantableWriteRoots = [HOME];
			}),
			"/work",
			AGENT,
		);
		expect(() => validateWriteCapability(backend, "/work", target)).toThrow(/never-grantable/);
	});

	// `true` carries no write path, so neither L1's protected paths nor the
	// "covers a concrete write" check decide: the boundary does.
	it.each(TRUST_ROOTS)("refuses %s at the gate before any prompt", async (target) => {
		let asked = false;
		const escalator: Escalator = {
			confirm: async () => {
				asked = true;
				return true;
			},
		};
		const decision = await decide(
			{ toolName: "bash", toolCallId: "c1", input: { command: "true", allow_write: target } },
			{
				profile: profile((p) => {
					p.sandbox.grantableWriteRoots = [HOME];
				}),
				cwd: "/work",
				home: HOME,
				lock: new ActionLock(),
				owned: OWNED_TOOLS,
				escalator,
			},
		);
		expect(decision.outcome).toBe("deny");
		expect(decision.reason).toContain("no approval can");
		expect(decision.reason).toContain("never-grantable");
		expect(asked).toBe(false);
	});

	it.each([
		"/home/u/.bash_aliases",
		"/home/u/.bashrc.d/x.sh",
		"/home/u/.oh-my-zsh/custom/x.zsh",
		"/home/u/.zsh/x",
		"/home/u/.config/zsh/.zshrc",
		"/home/u/.config/direnv/direnvrc",
		"/home/u/.tmux.conf",
		"/home/u/.config/tmux/tmux.conf",
		"/home/u/.nvm/nvm.sh",
		"/home/u/.pyenv/shims/python",
		"/home/u/.rbenv/shims/ruby",
		"/home/u/.asdf/shims/x",
		"/home/u/.volta/bin/node",
		"/home/u/.local/share/pnpm/pnpm",
		"/home/u/.yarn/bin/x",
		"/home/u/.cargo/config.toml",
		"/home/u/.local/lib/python3.12/site-packages/x.pth",
		"/home/u/.config/pip/pip.conf",
		"/home/u/.pythonrc",
		"/home/u/.gdbinit",
		"/home/u/.local/share/applications/x.desktop",
	])("also refuses %s (review of #52)", (target) => {
		const backend = toBackendProfile(
			profile((p) => {
				p.sandbox.grantableWriteRoots = [HOME];
			}),
			"/work",
			AGENT,
		);
		expect(() => validateWriteCapability(backend, "/work", target)).toThrow(/never-grantable/);
	});

	it("says why the target is sensitive", () => {
		const issue = writeCapabilityBoundaryIssue("/home/u/.pi/agent/enclave.json", {
			cwd: "/work",
			grantableRoots: [HOME],
			protectedTargets: protectedWriteTargets(HOME, AGENT, {}),
		});
		expect(issue).toContain("pi-enclave's own policy");
		expect(
			writeCapabilityBoundaryIssue("/home/u/.zshrc", {
				cwd: "/work",
				grantableRoots: [HOME],
				protectedTargets: protectedWriteTargets(HOME, AGENT, {}),
			}),
		).toContain("shell or login session");
	});

	it("refuses a target that contains a protected path, not only one below it", () => {
		const issue = writeCapabilityBoundaryIssue("/home/u/.config", {
			cwd: "/work",
			grantableRoots: [HOME],
			protectedTargets: protectedWriteTargets(HOME, AGENT, {}),
		});
		expect(issue).toContain("never-grantable");
	});

	it("follows an absolute XDG_CONFIG_HOME", () => {
		const paths = protectedWriteTargets(HOME, AGENT, { XDG_CONFIG_HOME: "/srv/xdg" }).map((entry) => entry.path);
		expect(paths).toContain("/srv/xdg/git");
		expect(paths).toContain("/home/u/.config/git");
		expect(protectedWriteTargets(HOME, AGENT, { XDG_CONFIG_HOME: "rel" }).map((e) => e.path)).not.toContain("rel/git");
	});

	it("puts every loaded code root on the list", () => {
		const backend = protectLoadedCode(
			toBackendProfile(
				profile((p) => {
					p.sandbox.grantableWriteRoots = ["/opt"];
				}),
				"/work",
				AGENT,
			),
			[
				{ path: "/opt/pi-enclave", from: "pi-enclave" },
				{ path: "/opt/pi/node_modules", from: "pi" },
			],
		);
		expect(() => validateWriteCapability(backend, "/work", "/opt/pi-enclave/src/index.ts")).toThrow(
			/pi loads code from it \(pi-enclave\)/,
		);
		expect(() => validateWriteCapability(backend, "/work", "/opt/pi/node_modules/x")).toThrow(/never-grantable/);
		expect(validateWriteCapability(backend, "/work", "/opt/data/out")).toBe("/opt/data/out");
	});

	it("raises the risk floor to critical for a protected target", () => {
		const action = canonicalize({
			tool: "bash",
			input: { command: "printf x > /home/u/.bashrc", allow_write: "/home/u/.bashrc" },
			cwd: "/work",
			home: HOME,
			profileName: "dev",
			writableRoots: ["/work"],
		});
		expect(minimumRisk(action, profile())).toBe("critical");
		const plainWrite = canonicalize({
			tool: "write",
			input: { path: "/home/u/.gitconfig", content: "x" },
			cwd: "/work",
			home: HOME,
			profileName: "dev",
			writableRoots: ["/work"],
		});
		expect(minimumRisk(plainWrite, profile())).toBe("critical");
	});

	it("write-denies pi-enclave's policy and pi's trust store explicitly", () => {
		const backend = toBackendProfile(profile(), "/work", AGENT);
		expect(backend.writeDeny).toContain("/home/u/.pi/agent/enclave.json");
		expect(backend.writeDeny).toContain("/home/u/.pi/agent/trust.json");
	});
});

describe("grantable write roots (#21)", () => {
	it("grants nothing outside the workspace by default", async () => {
		const backend = toBackendProfile(profile(), "/work", AGENT);
		expect(() => validateWriteCapability(backend, "/work", "/srv/result")).toThrow(
			/outside every sandbox.grantableWriteRoots/,
		);
		const decision = await decide(
			{ toolName: "bash", toolCallId: "c1", input: { command: "touch /srv/result", allow_write: "/srv/result" } },
			{
				profile: profile(),
				cwd: "/work",
				home: HOME,
				lock: new ActionLock(),
				owned: OWNED_TOOLS,
				escalator: { confirm: async () => true },
			},
		);
		expect(decision.outcome).toBe("deny");
		expect(decision.reason).toContain("no approval can");
	});

	it("grants a target below the workspace or below a configured root", async () => {
		const backend = toBackendProfile(
			profile((p) => {
				p.sandbox.grantableWriteRoots = ["/srv"];
			}),
			"/work",
			AGENT,
		);
		expect(validateWriteCapability(backend, "/work", "/srv/result")).toBe("/srv/result");
		const decision = await decide(
			{ toolName: "bash", toolCallId: "c1", input: { command: "touch /srv/result", allow_write: "/srv/result" } },
			{
				profile: profile((p) => {
					p.sandbox.grantableWriteRoots = ["/srv"];
				}),
				cwd: "/work",
				home: HOME,
				lock: new ActionLock(),
				owned: OWNED_TOOLS,
				escalator: { confirm: async () => true },
			},
		);
		expect(decision.outcome).toBe("ask-approved");
	});

	const doc = (source: SourceId, patch: object): ConfigDocument =>
		({ source, patch, path: `/${source}.json` }) as ConfigDocument;

	it("accepts the list from the user-global file", () => {
		const result = fold(
			[{ source: "builtin" }, doc("user_global", { sandbox: { grantableWriteRoots: ["/srv"] } })],
			OPTIONS,
		);
		if (!result.ok) throw new Error(JSON.stringify(result.errors));
		expect(result.profile.sandbox.grantableWriteRoots).toEqual(["/srv"]);
	});

	it("does not let a less trusted source add to it", () => {
		const user = profile((p) => {
			p.sandbox.grantableWriteRoots = ["/srv"];
		});
		const project = profile((p) => {
			p.sandbox.grantableWriteRoots = ["/srv", "/opt"];
		});
		expect(narrowerOrEqual(project, user).map((violation) => violation.field)).toEqual(["sandbox.grantableWriteRoots"]);
		const narrowed = profile((p) => {
			p.sandbox.grantableWriteRoots = [];
		});
		expect(narrowerOrEqual(narrowed, user)).toEqual([]);
	});

	it.each([
		["/", '"/" can never be'],
		["/home/u", "contains never-grantable write target"],
		["/home", "contains never-grantable write target"],
		["/home/u/.config", "contains never-grantable write target"],
		["/var", "contains never-grantable write target"],
		["/home/u/.pi/agent/extensions", "never-grantable write target"],
		["/home/u/.config/systemd/user", "never-grantable write target"],
	])("refuses %s as a grantable write root", (root, message) => {
		const result = fold(
			[{ source: "builtin" }, doc("user_global", { sandbox: { grantableWriteRoots: [root] } })],
			OPTIONS,
		);
		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.errors.some((error) => error.message.includes(message))).toBe(true);
	});
});

describe("writable roots and pi's agent directory (#21)", () => {
	const doc = (patch: object): ConfigDocument => ({ source: "user_global", patch, path: "/u.json" }) as ConfigDocument;

	it.each(["/home/u/.pi/agent/extensions", "/home/u/.pi/agent/enclave.json"])(
		"refuses a writable root inside the agent directory: %s",
		(root) => {
			const result = fold([{ source: "builtin" }, doc({ sandbox: { writableRoots: [root] } })], OPTIONS);
			expect(result.ok).toBe(false);
			if (!result.ok) expect(result.errors.some((error) => error.message.includes("pi's agent directory"))).toBe(true);
		},
	);

	it("keeps the state-directory message for a root that contains it", () => {
		const result = fold([{ source: "builtin" }, doc({ sandbox: { writableRoots: ["/home/u"] } })], OPTIONS);
		expect(result.ok).toBe(false);
		if (!result.ok) {
			expect(result.errors.some((error) => error.message.includes("state directory"))).toBe(true);
			expect(result.errors.some((error) => error.message.includes("holds pi-enclave's policy"))).toBe(false);
		}
	});
});
