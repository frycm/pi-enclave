import { lstatSync, realpathSync, type Stats } from "node:fs";
import { dirname, isAbsolute, normalize } from "node:path";
import { canonical, isUnder } from "../paths.ts";
import type { Profile } from "../types.ts";

export interface BindMount {
	source: string;
	target: string;
	readonly: boolean;
	mask?: boolean;
}
export interface MountPlan {
	mounts: BindMount[];
	identities: Map<string, string>;
}

export function containerPath(path: string): string {
	if (
		!isAbsolute(path) ||
		normalize(path) !== path ||
		/[,:]/.test(path) ||
		[...path].some((char) => char.charCodeAt(0) < 32)
	)
		throw new Error(`pi-enclave: unsupported container path ${JSON.stringify(path)}`);
	return path;
}

function identity(path: string): string {
	try {
		const stat = lstatSync(path);
		if (stat.isSymbolicLink()) throw new Error(`pi-enclave: symlinked mount topology: ${path}`);
		if (realpathSync(path) !== path) throw new Error(`pi-enclave: symlinked mount ancestor: ${path}`);
		return `${stat.dev}:${stat.ino}:${stat.mode & 0xf000}`;
	} catch (error) {
		if ((error as NodeJS.ErrnoException).code === "ENOENT") return "missing";
		throw error;
	}
}

export function assertMounts(plan: MountPlan): void {
	for (const [path, original] of plan.identities) {
		if (identity(path) !== original)
			throw new Error(`pi-enclave: mount topology changed at ${path}; recompile the profile`);
	}
}

/** Pin every ancestor of a nested denial as a mount, so renaming it cannot uncover the source. */
export function compileMounts(profile: Profile, emptyDir: string, emptyFile: string): MountPlan {
	const identities = new Map<string, string>();
	const mounts = new Map<string, BindMount>();
	const roots = [
		...(profile.readableRoots ?? []).map((path) => ({ path, readonly: true })),
		...profile.writableRoots.map((path) => ({ path, readonly: false })),
	].filter(({ path }) => path !== "/tmp/claude");
	const reserved = ["/", "/proc", "/sys", "/dev", "/usr", "/bin", "/sbin", "/lib", "/lib64", "/etc", "/enclave"];
	for (const { path, readonly } of roots.sort((a, b) => a.path.length - b.path.length)) {
		containerPath(path);
		if (reserved.some((root) => root === path || (root !== "/" && isUnder(path, root))))
			throw new Error(`pi-enclave: container runtime path cannot be a host mount: ${path}`);
		if (realpathSync(path) !== path) throw new Error(`pi-enclave: host mount must be canonical: ${path}`);
		const stat = lstatSync(path);
		if (!stat.isDirectory() && !stat.isFile()) throw new Error(`pi-enclave: unsupported mount source ${path}`);
		if (profile.readDeny.some((deny) => isUnder(path, canonical(deny))))
			throw new Error(`pi-enclave: host mount is under a read denial: ${path}`);
		if (profile.writeDeny?.some((deny) => isUnder(path, canonical(deny))))
			throw new Error(`pi-enclave: host mount is under a write denial: ${path}`);
		identities.set(path, identity(path));
		mounts.set(path, { source: path, target: path, readonly });
	}
	const exposedRoot = (path: string) =>
		[...mounts.values()]
			.filter((mount) => !mount.mask && isUnder(path, mount.target))
			.sort((a, b) => b.target.length - a.target.length)[0];
	for (const [denials, mask] of [
		[profile.readDeny, true],
		[profile.writeDeny ?? [], false],
	] as const) {
		for (const path of [...new Set(denials)].sort((a, b) => a.length - b.length)) {
			containerPath(path);
			const root = exposedRoot(path);
			if (!root && exposedRoot(canonical(path))) throw new Error(`pi-enclave: unsafe nested denial alias ${path}`);
			if (!root) continue; // Unmounted host paths are absent; images must be explicitly trusted.
			if ([...mounts.values()].some((mount) => mount.mask && isUnder(path, mount.target))) continue;
			let stat: Stats;
			try {
				stat = lstatSync(path);
			} catch {
				throw new Error(`pi-enclave: missing nested denial ${path}; container topology is unsupported`);
			}
			if (stat.isSymbolicLink() || (!stat.isDirectory() && !stat.isFile()) || realpathSync(path) !== path)
				throw new Error(`pi-enclave: unsafe nested denial ${path}`);
			for (
				let ancestor = dirname(path);
				ancestor !== root.target && isUnder(ancestor, root.target);
				ancestor = dirname(ancestor)
			) {
				identities.set(ancestor, identity(ancestor));
				if (!mounts.has(ancestor))
					mounts.set(ancestor, { source: ancestor, target: ancestor, readonly: root.readonly });
			}
			identities.set(path, identity(path));
			mounts.set(path, {
				source: mask ? (stat.isDirectory() ? emptyDir : emptyFile) : path,
				target: path,
				readonly: true,
				...(mask ? { mask: true } : {}),
			});
		}
	}
	return { mounts: [...mounts.values()].sort((a, b) => a.target.length - b.target.length), identities };
}
