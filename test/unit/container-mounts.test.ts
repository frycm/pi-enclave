import { mkdirSync, mkdtempSync, realpathSync, renameSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { assertMounts, compileMounts } from "../../src/backend/container/mounts.ts";
import { CONTAINER_SECCOMP } from "../../src/backend/container/seccomp.ts";
import type { Profile } from "../../src/backend/types.ts";

const roots: string[] = [];
afterEach(() => {
	for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});
function fixture() {
	const root = realpathSync(mkdtempSync(join(tmpdir(), "enclave-mount-plan-")));
	roots.push(root);
	const workspace = join(root, "workspace");
	mkdirSync(workspace);
	mkdirSync(join(workspace, "nested", "secrets"), { recursive: true });
	writeFileSync(join(workspace, "nested", "secrets", "key"), "secret");
	mkdirSync(join(root, "empty"));
	writeFileSync(join(root, "empty-file"), "");
	const profile: Profile = {
		mode: "workspace-write",
		writableRoots: [workspace],
		readDeny: [join(workspace, "nested", "secrets")],
		network: "off",
		allowPty: true,
	};
	return {
		root,
		workspace,
		profile,
		compile: () => compileMounts(profile, join(root, "empty"), join(root, "empty-file")),
	};
}
describe("container mount authority", () => {
	it("pins denial ancestors and rejects a retargeted source", () => {
		const f = fixture();
		const plan = f.compile();
		expect(plan.mounts.some((mount) => mount.target === join(f.workspace, "nested") && !mount.mask)).toBe(true);
		renameSync(join(f.workspace, "nested"), join(f.workspace, "moved"));
		mkdirSync(join(f.workspace, "nested"));
		expect(() => assertMounts(plan)).toThrow(/topology changed/);
	});
	it("refuses a mount below a denial and runtime mounts", () => {
		const f = fixture();
		f.profile.readableRoots = [join(f.workspace, "nested", "secrets")];
		expect(f.compile).toThrow(/under a read denial/);
		f.profile.readableRoots = ["/usr"];
		expect(f.compile).toThrow(/runtime path/);
	});
	it("refuses missing and symlinked nested deny topology", () => {
		const f = fixture();
		f.profile.readDeny = [join(f.workspace, "absent")];
		expect(f.compile).toThrow(/missing nested/);
		symlinkSync(join(f.workspace, "nested"), join(f.workspace, "link"));
		f.profile.readDeny = [join(f.workspace, "link", "secrets")];
		expect(f.compile).toThrow(/unsafe nested/);
	});
	it("default-denies socket creation, io_uring and namespace syscalls", () => {
		const allowed = CONTAINER_SECCOMP.syscalls
			.filter((rule) => rule.action === "SCMP_ACT_ALLOW")
			.flatMap((rule) => rule.names);
		expect(CONTAINER_SECCOMP.defaultAction).toBe("SCMP_ACT_ERRNO");
		for (const name of [
			"socket",
			"socketcall",
			"connect",
			"io_uring_setup",
			"mount",
			"unshare",
			"setns",
			"ptrace",
			"bpf",
		])
			expect(allowed).not.toContain(name);
	});
	it("does not ignore a denied alias outside a bind that resolves into it", () => {
		const f = fixture();
		const alias = join(f.root, "alias");
		symlinkSync(join(f.workspace, "nested", "secrets"), alias);
		f.profile.readDeny = [alias];
		expect(f.compile).toThrow(/unsafe nested denial alias/);
	});
});
