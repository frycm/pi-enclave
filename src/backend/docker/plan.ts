/** Strict host-mount compiler for the experimental offline Docker backend. */
import { lstatSync } from "node:fs";
import { dirname, isAbsolute, normalize } from "node:path";
import { canonical, isUnder } from "../paths.ts";
import type { Profile } from "../types.ts";

export interface DockerMount {
	source: string;
	target: string;
	readonly: boolean;
	kind: "bind" | "mask-directory" | "mask-file";
}

export interface DockerPlan {
	profile: Profile;
	mounts: readonly DockerMount[];
	/** inode identities, including ancestors, checked again before each launch/call. */
	snapshot: string;
	observedPaths: readonly string[];
}

const RESERVED = ["/bin", "/sbin", "/usr", "/lib", "/lib64", "/etc", "/dev", "/proc", "/sys", "/opt/pi-enclave"];

export function dockerPath(path: string): string {
	if (
		!isAbsolute(path) ||
		normalize(path) !== path ||
		(path !== "/" && path.endsWith("/")) ||
		// biome-ignore lint/suspicious/noControlCharactersInRegex: reject ambiguous Docker CSV/control input
		/[,\x00-\x1f\x7f]/.test(path)
	) {
		throw new Error(
			`pi-enclave: Docker requires an absolute, normalized path without commas/control characters: ${path}`,
		);
	}
	return path;
}

/** Fail closed on missing components and symlinks, including symlinked parents. */
function components(path: string): string[] {
	const out: string[] = [];
	for (let current = dockerPath(path); current !== "/"; current = dirname(current)) out.unshift(current);
	return out;
}

export function mountSnapshot(paths: readonly string[]): string {
	return [...new Set(paths.flatMap(components))]
		.map((path) => {
			const stat = lstatSync(path);
			if (stat.isSymbolicLink() || (!stat.isDirectory() && !stat.isFile())) {
				throw new Error(`pi-enclave: Docker mount path must be a real file or directory: ${path}`);
			}
			return `${path}:${stat.dev}:${stat.ino}:${stat.isDirectory() ? "d" : "f"}`;
		})
		.join("\n");
}

export function compileDockerPlan(
	input: Profile,
	privateDir: string,
	dockerBinary: string,
	socket = "/var/run/docker.sock",
): DockerPlan {
	if (input.mode !== "workspace-write" || input.network !== "off")
		throw new Error("pi-enclave: Docker supports workspace-write with network off only");
	const profile: Profile = structuredClone(input);
	const writes = [...new Set(profile.writableRoots.map(dockerPath))];
	const reads = [...new Set((profile.readableRoots ?? []).map(dockerPath))].filter((path) => !writes.includes(path));
	const roots = [...reads, ...writes];
	if (!writes.length) throw new Error("pi-enclave: Docker requires an explicit writable workspace");
	for (const root of roots) {
		if (
			[...RESERVED, privateDir, dockerBinary, canonical(dockerBinary), socket, canonical(socket)].some(
				(path) => isUnder(path, root) || isUnder(root, path),
			)
		) {
			throw new Error(`pi-enclave: Docker host root overlaps its runtime or a reserved image path: ${root}`);
		}
		mountSnapshot([root]);
		if (!lstatSync(root).isDirectory()) throw new Error(`pi-enclave: Docker host roots must be directories: ${root}`);
	}
	const mounts = new Map<string, DockerMount>();
	for (const root of roots)
		mounts.set(root, { source: root, target: root, readonly: !writes.includes(root), kind: "bind" });
	const readDeny = [...new Set(profile.readDeny.map(dockerPath))];
	const writeDeny = [...new Set((profile.writeDeny ?? []).map(dockerPath))];
	const observed = new Set(roots);
	for (const [kind, denies] of [
		["write", writeDeny],
		["read", readDeny],
	] as const) {
		for (const denied of denies) {
			// An exposed descendant of a denied ancestor cannot be remounted over its mask.
			if (roots.some((root) => root !== denied && isUnder(root, denied))) {
				throw new Error(`pi-enclave: Docker host root is nested beneath a ${kind} denial: ${denied}`);
			}
			const root = roots.filter((candidate) => isUnder(denied, candidate)).sort((a, b) => b.length - a.length)[0];
			if (!root) {
				if (kind === "read") {
					// Host contents are absent here, but the image may contain the same
					// pathname. Mask it too. An unknown/mismatched file type makes Docker
					// startup refuse instead of exposing image data at a denied path.
					let file = false;
					try {
						file = lstatSync(denied).isFile();
					} catch (error) {
						if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
					}
					mounts.set(denied, {
						source: denied,
						target: denied,
						readonly: true,
						kind: file ? "mask-file" : "mask-directory",
					});
				}
				continue;
			}
			// Docker cannot mask an absent/symlinked nested target safely. Do not guess its type,
			// create credential paths, or depend on a daemon following a moving symlink.
			mountSnapshot([denied]);
			observed.add(denied);
			const stat = lstatSync(denied);
			mounts.set(denied, {
				source: denied,
				target: denied,
				readonly: true,
				kind: kind === "write" ? "bind" : stat.isDirectory() ? "mask-directory" : "mask-file",
			});
			// Pin movable ancestors so a writable .git cannot be renamed and replaced
			// around a read-only hooks/config mount (the existing C16 contract).
			for (let parent = dirname(denied); parent !== root && isUnder(parent, root); parent = dirname(parent)) {
				if (!mounts.has(parent))
					mounts.set(parent, {
						source: parent,
						target: parent,
						readonly: !writes.some((w) => isUnder(parent, w)),
						kind: "bind",
					});
				observed.add(parent);
			}
		}
	}
	const ordered = [...mounts.values()].sort(
		(a, b) => a.target.split("/").length - b.target.split("/").length || a.target.localeCompare(b.target),
	);
	// Ancestor denials dominate: no later child bind may re-expose their contents.
	const effective = ordered.filter(
		(mount) =>
			!ordered.some(
				(parent) =>
					parent !== mount &&
					isUnder(mount.target, parent.target) &&
					(parent.kind !== "bind" || (parent.readonly && writeDeny.includes(parent.target) && mount.kind === "bind")),
			),
	);
	profile.writableRoots = Object.freeze(writes);
	profile.readableRoots = Object.freeze(reads);
	profile.readDeny = Object.freeze(readDeny);
	profile.writeDeny = Object.freeze(writeDeny);
	// Docker exposes private /tmp and /dev/shm in addition to host write roots.
	profile.tmpDir = "/tmp";
	profile.allowPty = true;
	for (const value of Object.values(profile)) if (Array.isArray(value)) Object.freeze(value);
	return Object.freeze({
		profile: Object.freeze(profile),
		mounts: Object.freeze(effective.map((m) => Object.freeze(m))),
		snapshot: mountSnapshot([...observed]),
		observedPaths: Object.freeze([...observed]),
	});
}

export function mountArguments(plan: DockerPlan, privateDir: string): string[] {
	return plan.mounts.flatMap((mount) => {
		const source =
			mount.kind === "bind"
				? mount.source
				: `${privateDir}/${mount.kind === "mask-directory" ? "empty-dir" : "empty-file"}`;
		return [
			"--mount",
			`type=bind,source=${source},target=${mount.target},bind-recursive=disabled${mount.readonly ? ",readonly" : ""}`,
		];
	});
}
