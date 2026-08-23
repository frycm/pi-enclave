import { delimiter } from "node:path";
import { describe, expect, it } from "vitest";
import {
	buildChildEnv,
	CHILD_ENV_BASE,
	CREDENTIAL_DENY_PATTERNS,
	globToRegExp,
	isCredentialName,
	validatePassthrough,
} from "../../src/env/child-env.ts";

/** A parent process carrying exactly the things that must never reach a sandbox. */
const PARENT = {
	PATH: "/usr/bin:/bin",
	HOME: "/Users/real",
	USER: "real",
	TERM: "xterm-256color",
	LANG: "en_US.UTF-8",
	ANTHROPIC_API_KEY: "sk-ant-LEAK",
	AWS_SECRET_ACCESS_KEY: "aws-LEAK",
	GITHUB_TOKEN: "ghp-LEAK",
	OPENAI_API_KEY: "sk-LEAK",
	SSH_AUTH_SOCK: "/private/tmp/agent.sock",
	KUBECONFIG: "/Users/real/.kube/config",
	DOCKER_HOST: "unix:///var/run/docker.sock",
	PI_AUTH_TOKEN: "pi-LEAK",
	MY_PASSWORD: "hunter2",
	SOME_CREDENTIALS_FILE: "/x",
	FOO_TOKEN: "tok-LEAK",
	NPM_TOKEN: "npm-LEAK",
	GPG_AGENT_INFO: "/x",
	AZURE_CLIENT_SECRET: "az-LEAK",
	GOOGLE_APPLICATION_CREDENTIALS: "/x.json",
};

const values = (env: Readonly<Record<string, string>>) => Object.values(env).join("\n");

describe("globToRegExp", () => {
	it("anchors the pattern at both ends", () => {
		expect(globToRegExp("AWS_*").test("AWS_REGION")).toBe(true);
		expect(globToRegExp("AWS_*").test("MY_AWS_REGION")).toBe(false);
		expect(globToRegExp("GH_TOKEN").test("GH_TOKEN_X")).toBe(false);
	});

	it("treats regex metacharacters in the pattern as literals", () => {
		expect(globToRegExp("A.B").test("A.B")).toBe(true);
		expect(globToRegExp("A.B").test("AxB")).toBe(false);
	});

	it("supports a wildcard in any position", () => {
		expect(globToRegExp("*_SECRET*").test("MY_SECRET_VALUE")).toBe(true);
		expect(globToRegExp("*_TOKEN").test("FOO_TOKEN")).toBe(true);
	});
});

describe("isCredentialName", () => {
	it("matches every documented credential pattern", () => {
		for (const name of [
			"ANTHROPIC_API_KEY",
			"OPENAI_API_KEY",
			"AWS_SECRET_ACCESS_KEY",
			"GITHUB_TOKEN",
			"GH_TOKEN",
			"NPM_TOKEN",
			"FOO_TOKEN",
			"MY_PASSWORD",
			"SOME_CREDENTIALS_FILE",
			"SSH_AUTH_SOCK",
			"GPG_AGENT_INFO",
			"KUBECONFIG",
			"DOCKER_HOST",
			"PI_ANYTHING",
			"AZURE_CLIENT_SECRET",
			"GOOGLE_APPLICATION_CREDENTIALS",
		]) {
			expect(isCredentialName(name), name).toBe(true);
		}
	});

	it("leaves ordinary names alone", () => {
		for (const name of ["PATH", "HOME", "LANG", "EDITOR", "NODE_ENV", "my_token_count"]) {
			expect(isCredentialName(name), name).toBe(false);
		}
	});

	it("is case-sensitive, matching POSIX semantics", () => {
		// Lowercase `my_token_count` must survive; an all-caps *_TOKEN must not.
		expect(isCredentialName("my_token_count")).toBe(false);
		expect(isCredentialName("MY_TOKEN")).toBe(true);
	});

	it("accepts extra deny patterns, which can only widen the list", () => {
		expect(isCredentialName("COMPANY_VAULT", ["COMPANY_*"])).toBe(true);
		expect(isCredentialName("COMPANY_VAULT")).toBe(false);
	});
});

describe("buildChildEnv: what reaches the sandbox", () => {
	it("copies the base list and nothing else", () => {
		const env = buildChildEnv({ ...PARENT, RANDOM_VAR: "x", EDITOR: "vim" });
		expect(env.PATH).toBe("/usr/bin:/bin");
		expect(env.TERM).toBe("xterm-256color");
		expect(env.RANDOM_VAR).toBeUndefined();
		// EDITOR is harmless, but "harmless" is not the rule -- the rule is the list.
		expect(env.EDITOR).toBeUndefined();
	});

	it("omits base variables the parent does not have", () => {
		const env = buildChildEnv({ PATH: "/bin" });
		expect(Object.keys(env)).not.toContain("LANG");
	});

	it("sets PYTHONDONTWRITEBYTECODE so Python does not generate spurious violations", () => {
		expect(buildChildEnv(PARENT).PYTHONDONTWRITEBYTECODE).toBe("1");
	});

	it("returns a frozen object", () => {
		const env = buildChildEnv(PARENT) as Record<string, string>;
		expect(Object.isFrozen(env)).toBe(true);
	});
});

describe("buildChildEnv: credential exclusion", () => {
	it("leaks none of the parent's secrets", () => {
		const env = buildChildEnv(PARENT);
		expect(values(env)).not.toMatch(/LEAK|hunter2/);
		for (const name of Object.keys(PARENT)) {
			if (isCredentialName(name)) expect(env[name], name).toBeUndefined();
		}
	});

	it("drops a credential even when explicitly passed through", () => {
		// The deny list runs last, so passthrough cannot smuggle one in.
		const env = buildChildEnv(PARENT, { passthrough: ["ANTHROPIC_API_KEY", "FOO_TOKEN", "GITHUB_TOKEN"] });
		expect(env.ANTHROPIC_API_KEY).toBeUndefined();
		expect(env.FOO_TOKEN).toBeUndefined();
		expect(values(env)).not.toContain("LEAK");
	});

	it("honours user-supplied extra deny patterns", () => {
		const env = buildChildEnv(
			{ ...PARENT, COMPANY_VAULT: "v" },
			{
				passthrough: ["COMPANY_VAULT"],
				envDeny: ["COMPANY_*"],
			},
		);
		expect(env.COMPANY_VAULT).toBeUndefined();
	});

	it("passes through a non-credential variable when asked", () => {
		const env = buildChildEnv({ ...PARENT, BUILD_NUMBER: "42" }, { passthrough: ["BUILD_NUMBER"] });
		expect(env.BUILD_NUMBER).toBe("42");
	});

	// The property the plan calls for: no name matching the deny list ever
	// survives, regardless of what passthrough asks for.
	it("property: no denied name survives any passthrough request", () => {
		const prefixes = ["", "MY_", "A", "X_", "COMPANY_", "a", "_"];
		const suffixes = ["", "_X", "1", "_VALUE", "s"];
		const cases: string[] = [];
		for (const pattern of CREDENTIAL_DENY_PATTERNS) {
			for (const prefix of prefixes) {
				for (const suffix of suffixes) {
					cases.push(pattern.replaceAll("*", "Z"), `${prefix}${pattern.replaceAll("*", "Z")}${suffix}`);
				}
			}
		}
		const parent: Record<string, string> = {};
		for (const name of cases) parent[name] = "SECRET-VALUE";

		const env = buildChildEnv(parent, { passthrough: cases });
		for (const name of cases) {
			if (isCredentialName(name)) expect(env[name], name).toBeUndefined();
		}
		// And nothing that did survive carries a secret value by another name.
		for (const [name, value] of Object.entries(env)) {
			if (value === "SECRET-VALUE") expect(isCredentialName(name), name).toBe(false);
		}
	});
});

describe("buildChildEnv: sandbox view of HOME, TMPDIR and PATH", () => {
	it("rewrites HOME and TMPDIR to the sandbox's own paths", () => {
		const env = buildChildEnv(PARENT, { home: "/tmp/box/home", tmpdir: "/tmp/box/tmp" });
		expect(env.HOME).toBe("/tmp/box/home");
		expect(env.TMPDIR).toBe("/tmp/box/tmp");
	});

	it("keeps the parent's HOME when no rewrite is requested", () => {
		expect(buildChildEnv(PARENT).HOME).toBe("/Users/real");
	});

	it("drops PATH entries under a read-denied root", () => {
		const env = buildChildEnv(
			{ ...PARENT, PATH: ["/usr/bin", "/Users/real/.secrets/bin", "/bin"].join(delimiter) },
			{ readDeny: ["/Users/real/.secrets"] },
		);
		expect(env.PATH).toBe(["/usr/bin", "/bin"].join(delimiter));
	});

	it("does not drop a PATH entry that merely shares a prefix", () => {
		const env = buildChildEnv(
			{ ...PARENT, PATH: ["/opt/secretsbin", "/opt/secrets/bin"].join(delimiter) },
			{ readDeny: ["/opt/secrets"] },
		);
		expect(env.PATH).toBe("/opt/secretsbin");
	});

	it("removes PATH entirely rather than setting it empty", () => {
		// An empty PATH has surprising shell semantics (it can mean "cwd"), so
		// absence is safer than emptiness.
		const env = buildChildEnv({ ...PARENT, PATH: "/denied/bin" }, { readDeny: ["/denied"] });
		expect("PATH" in env).toBe(false);
	});
});

describe("validatePassthrough", () => {
	it("rejects credential names loudly instead of dropping them silently", () => {
		const { accepted, rejected } = validatePassthrough(["BUILD_NUMBER", "FOO_TOKEN", "ANTHROPIC_API_KEY"]);
		expect(accepted).toEqual(["BUILD_NUMBER"]);
		expect(rejected.map((r) => r.name)).toEqual(["FOO_TOKEN", "ANTHROPIC_API_KEY"]);
		expect(rejected[0]?.reason).toContain("FOO_TOKEN");
	});

	it("accepts an empty list", () => {
		expect(validatePassthrough([])).toEqual({ accepted: [], rejected: [] });
	});

	it("applies extra deny patterns too", () => {
		const { rejected } = validatePassthrough(["COMPANY_VAULT"], ["COMPANY_*"]);
		expect(rejected).toHaveLength(1);
	});
});

describe("CHILD_ENV_BASE hygiene", () => {
	it("contains no name the deny list would strip", () => {
		// If these ever collide, the base entry silently stops arriving. Better to
		// find out here than to debug a missing LANG inside a sandbox.
		for (const name of CHILD_ENV_BASE) {
			expect(isCredentialName(name), name).toBe(false);
		}
	});
});
