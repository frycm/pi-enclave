import { readFileSync } from "node:fs";

interface SeccompProfile {
	defaultAction: string;
	syscalls: { names: string[]; action: string; [key: string]: unknown }[];
	[key: string]: unknown;
}

/** Keep Moby's allowlist and remove socket creation, including the 32-bit multiplexer. */
export function offlineSeccomp(): string {
	const profile = JSON.parse(
		readFileSync(new URL("./vendor/moby-seccomp.json", import.meta.url), "utf8"),
	) as SeccompProfile;
	if (profile.defaultAction !== "SCMP_ACT_ERRNO") throw new Error("pi-enclave: unexpected seccomp default");
	const forbidden = new Set(["socket", "socketcall", "io_uring_setup", "io_uring_enter", "io_uring_register"]);
	profile.syscalls = profile.syscalls
		.map((rule) => ({ ...rule, names: rule.names.filter((name) => !forbidden.has(name)) }))
		.filter((rule) => rule.names.length > 0);
	return JSON.stringify(profile);
}
