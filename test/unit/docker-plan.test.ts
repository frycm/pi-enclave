import { createHash } from "node:crypto";
import {
	mkdirSync,
	mkdtempSync,
	readFileSync,
	realpathSync,
	renameSync,
	rmSync,
	symlinkSync,
	writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { compileDockerPlan, dockerPath, mountArguments, mountSnapshot } from "../../src/backend/docker/plan.ts";
import { offlineSeccomp } from "../../src/backend/docker/seccomp.ts";
import { DockerBackend } from "../../src/backend/docker.ts";
import type { Profile } from "../../src/backend/types.ts";

describe("Docker mount authority", () => {
	let root: string;
	let workspace: string;
	let state: string;
	let profile: Profile;
	beforeEach(() => {
		root = mkdtempSync(join(realpathSync(tmpdir()), "enclave-docker-plan-"));
		workspace = join(root, "workspace");
		state = join(root, "private");
		mkdirSync(workspace);
		mkdirSync(state);
		mkdirSync(join(workspace, ".git", "hooks"), { recursive: true });
		writeFileSync(join(workspace, ".git", "config"), "safe");
		mkdirSync(join(workspace, "secrets"));
		writeFileSync(join(workspace, "secret-file"), "hidden");
		profile = {
			mode: "workspace-write",
			writableRoots: [workspace],
			writeDeny: [join(workspace, ".git", "hooks"), join(workspace, ".git", "config")],
			readDeny: [join(workspace, "secrets"), join(workspace, "secret-file")],
			network: "off",
			allowPty: true,
		};
	});
	afterEach(() => {
		rmSync(root, { recursive: true, force: true });
	});
	const compile = () => compileDockerPlan(profile, state, "/usr/bin/docker");

	it("masks nested read denials, preserves ordinary writes and pins mutable deny ancestors", () => {
		const plan = compile();
		expect(plan.mounts.find((m) => m.target === workspace)).toMatchObject({ readonly: false, kind: "bind" });
		expect(plan.mounts.find((m) => m.target.endsWith("/.git"))).toMatchObject({ readonly: false });
		expect(plan.mounts.find((m) => m.target.endsWith("/config"))).toMatchObject({ readonly: true, kind: "bind" });
		expect(plan.mounts.find((m) => m.target.endsWith("/secrets"))).toMatchObject({
			readonly: true,
			kind: "mask-directory",
		});
		expect(plan.mounts.find((m) => m.target.endsWith("/secret-file"))).toMatchObject({
			readonly: true,
			kind: "mask-file",
		});
		const args = mountArguments(plan, state);
		expect(args.filter((a) => a.startsWith("type=bind")).every((a) => a.includes("bind-recursive=disabled"))).toBe(
			true,
		);
		expect(args.join(" ")).not.toContain(`source=${workspace}/secrets`);
	});

	it("lets ancestor read denials dominate all later child mounts", () => {
		profile.readDeny = [join(workspace, ".git")];
		const mounts = compile().mounts;
		expect(mounts.find((m) => m.target.endsWith("/.git"))?.kind).toBe("mask-directory");
		expect(mounts.some((m) => m.target.endsWith("/hooks") || m.target.endsWith("/config"))).toBe(false);
	});

	it("refuses an exposed root beneath a denial", () => {
		profile.readDeny = [root];
		expect(compile).toThrow(/nested beneath/);
	});

	it("refuses missing nested deny paths without creating them", () => {
		profile.readDeny = [join(workspace, "not-yet-created")];
		expect(compile).toThrow(/ENOENT/);
	});

	it.each(["root", "deny", "parent"])("refuses symlinked %s mount topology", (kind) => {
		const alias = join(root, "alias");
		symlinkSync(workspace, alias);
		if (kind === "root") profile.writableRoots = [alias];
		else if (kind === "parent") {
			profile.readableRoots = [root];
			profile.readDeny = [join(alias, "secret-file")];
			state = join(tmpdir(), "other-private-state");
		} else {
			symlinkSync(join(workspace, "secrets"), join(workspace, "alias"));
			profile.readDeny = [join(workspace, "alias")];
		}
		expect(compile).toThrow(/real file or directory/);
	});

	it("masks denied image paths without exposing their unselected host contents", () => {
		profile.readDeny = ["/home/not-exposed/.ssh"];
		const plan = compile();
		expect(plan.mounts.find((m) => m.target === profile.readDeny[0])?.kind).toBe("mask-directory");
		expect(mountArguments(plan, state).join(" ")).not.toContain("source=/home/not-exposed/.ssh");
	});

	it("refuses roots that expose the trusted runtime or private control files", () => {
		profile.readableRoots = [root];
		expect(compile).toThrow(/runtime/);
		profile.readableRoots = ["/usr"];
		expect(compile).toThrow(/runtime/);
	});

	it("freezes caller policy and detects later deny inode replacement", () => {
		const plan = compile();
		profile.readDeny = [];
		expect(plan.profile.readDeny).toHaveLength(2);
		expect(() => (plan.profile.readDeny as string[]).pop()).toThrow();
		renameSync(join(workspace, "secrets"), join(workspace, "old"));
		mkdirSync(join(workspace, "secrets"));
		expect(mountSnapshot(plan.observedPaths)).not.toBe(plan.snapshot);
	});

	it("does not mistake ordinary content edits for a topology change", () => {
		const plan = compile();
		writeFileSync(join(workspace, "ordinary.txt"), "allowed");
		expect(mountSnapshot(plan.observedPaths)).toBe(plan.snapshot);
	});

	it.each([
		"relative",
		"/tmp/a,b",
		"/tmp/a\nb",
		"/tmp/a/../b",
		"/tmp/x/",
	])("rejects ambiguous mount path %j", (path) => {
		expect(() => dockerPath(path)).toThrow(/normalized path/);
	});

	it.each([
		"node:latest",
		"node:22",
		"sha256:abc",
		"repo@sha256:XYZ",
	])("rejects mutable or malformed image %j before touching Docker", (image) => {
		expect(() => new DockerBackend({ image })).toThrow(/immutable/);
	});
});

it("preserves the pinned Moby allowlist while denying all socket creation and io_uring", () => {
	const original = readFileSync(new URL("../../src/backend/docker/vendor/moby-seccomp.json", import.meta.url));
	expect(createHash("sha256").update(original).digest("hex")).toBe(
		"536529b665dd0972c37bfb569f5d4ac8a53592e7b00752bc39ff063ca9864c74",
	);
	const profile = JSON.parse(offlineSeccomp());
	expect(profile.defaultAction).toBe("SCMP_ACT_ERRNO");
	const names = profile.syscalls.flatMap((rule: { names: string[] }) => rule.names);
	for (const name of ["socket", "socketcall", "io_uring_setup", "io_uring_enter", "io_uring_register"])
		expect(names).not.toContain(name);
	expect(names).toContain("socketpair");
	expect(names).toContain("execve");
});
