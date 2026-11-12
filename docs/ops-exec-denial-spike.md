# Ops profile spike: does a read denial stop execution? (#31)

**Question:** can `@anthropic-ai/sandbox-runtime` deny execution of named binaries, which
Phase 5b's broker design asks of the native Linux backend (no `sudo`, `su`, `doas`, `pkexec`
from inside the sandbox), or does the ops profile need an owned backend?

**Answer on Linux, in a container:** yes. A `readDeny` entry on a binary stops running it
directly, from a script, through the dynamic loader, and copying it elsewhere to run the
copy. The same binary without the entry runs. This decided the
[backend decision](../README.md#backend-decision-sandbox-runtime-until-a-conformance-row-says-otherwise)
for now. It is **not** Checkpoint A: it ran once, in a cloud container, as an ordinary user
created for the purpose. Checkpoint A re-runs it on a real Linux server and tries it on a Mac,
and adds the results below.

| | |
| --- | --- |
| Date | November 12, 2026 |
| pi-enclave | `main` at `7e60bc0` (the `SrtBackend` used here is unchanged since) |
| SRT | `@anthropic-ai/sandbox-runtime` 0.0.82, as pinned |
| Sandbox | bubblewrap 0.9.0 (Ubuntu package), socat from the same archive |
| Host | Ubuntu 24.04.5 LTS container, kernel 6.18.44, x86-64, Node 22.23.4, `user.max_user_namespaces` 64250 |
| User | `tuser` (uid 30033), no groups, no `sudoers` entry |

## Setup

As root in the container, which had no bubblewrap, socat or unprivileged user:

```sh
apt-get update && apt-get install -y bubblewrap socat
useradd -m tuser
cp -a /home/user/pi-enclave /home/tuser/pe     # a checkout with node_modules installed
mkdir -p /home/tuser/pe/test/spike
# the two files below go into /home/tuser/pe/test/spike/
chown -R tuser:tuser /home/tuser/pe
su tuser -s /bin/bash -c 'cd /home/tuser/pe && npx vitest --run test/spike/exec-deny.test.ts --silent=false'
```

Running as root in this container fails (bubblewrap cannot write the namespace's `uid_map`),
and a server runs pi-enclave as an ordinary user anyway. The spike uses the conformance suite's own fixture (`createFixture`), so the
profile is the suite's ordinary workspace-write profile, with one path added to `readDeny`.

`test/spike/shim.ts`:

```ts
export { createFixture } from "../conformance/fixture.ts";
export { scenarioEnv as scenarioEnvFor } from "../conformance/scenarios.ts";
```

`test/spike/exec-deny.test.ts`:

```ts
// Spike for #31 (not committed): can a read denial in SRT stop execution of a binary?
import { chmodSync, copyFileSync, mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { SrtBackend } from "../../src/backend/srt.ts";
import { createFixture, scenarioEnvFor } from "./shim.ts";

describe("exec denial via readDeny", () => {
	it("runs", async () => {
		const fixture = createFixture();
		const tools = join(fixture.outside, "tools");
		mkdirSync(tools);
		copyFileSync("/usr/bin/id", join(tools, "escalate"));
		chmodSync(join(tools, "escalate"), 0o755);
		copyFileSync("/usr/bin/id", join(tools, "control"));
		chmodSync(join(tools, "control"), 0o755);
		writeFileSync(join(fixture.workspace, "wrap.sh"), `#!/bin/sh\n${tools}/escalate -u\n`);
		const profile = { ...fixture.profile, readDeny: [...fixture.profile.readDeny, join(tools, "escalate")] };
		const backend = new SrtBackend({});
		const compiled = await backend.compile(profile);
		const out: string[] = [];
		for (const command of [
			`${tools}/control -u`,
			`${tools}/escalate -u`,
			"sh ./wrap.sh",
			`cp ${tools}/escalate ./copy && chmod +x ./copy && ./copy -u`,
			`/lib64/ld-linux-x86-64.so.2 ${tools}/escalate -u`,
			"grep -E '^(Uid|NoNewPrivs|CapEff)' /proc/self/status",
		]) {
			const chunks: Buffer[] = [];
			const result = await backend.run(compiled, {
				command,
				cwd: fixture.workspace,
				env: scenarioEnvFor(fixture),
				commandId: `spike-${out.length}`,
				timeout: 30,
				onData: (c) => chunks.push(c),
			});
			out.push(`${command} => exit ${result.exitCode}: ${Buffer.concat(chunks).toString().trim().slice(0, 400)}`);
		}
		console.log(out.join("\n"));
		await backend.dispose();
		fixture.cleanup();
		expect(out.length).toBe(6);
	}, 120_000);
});
```

`escalate` and `control` are both copies of `/usr/bin/id`, outside the workspace; only
`escalate` is in `readDeny`. `wrap.sh` is in the workspace and runs `escalate`.

## Output

Verbatim, from the second run (the first run had the same exit codes and messages, without
the last command):

```
/tmp/enclave-outside-eN0h9s/tools/control -u => exit 0: 30033
/tmp/enclave-outside-eN0h9s/tools/escalate -u => exit 126: /bin/bash: line 1: /tmp/enclave-outside-eN0h9s/tools/escalate: Permission denied
sh ./wrap.sh => exit 126: ./wrap.sh: 2: /tmp/enclave-outside-eN0h9s/tools/escalate: Permission denied
cp /tmp/enclave-outside-eN0h9s/tools/escalate ./copy && chmod +x ./copy && ./copy -u => exit 1: cp: cannot open '/tmp/enclave-outside-eN0h9s/tools/escalate' for reading: Permission denied
/lib64/ld-linux-x86-64.so.2 /tmp/enclave-outside-eN0h9s/tools/escalate -u => exit 127: /tmp/enclave-outside-eN0h9s/tools/escalate: error while loading shared libraries: /tmp/enclave-outside-eN0h9s/tools/escalate: cannot open shared object file: Permission denied
grep -E '^(Uid|NoNewPrivs|CapEff)' /proc/self/status => exit 0: Uid:	30033	30033	30033	30033
CapEff:	0000000000000000
NoNewPrivs:	1
```

(The `ld-linux` and `/proc` lines come from a third run with the output limit raised from
120 to 400 characters and the `/proc` command added; the temporary directory name differs
between runs.)

## What it shows

- **The control runs**, so the profile itself does not stop `id`.
- **Direct execution, a script, and the dynamic loader all fail with `EACCES`.** bubblewrap
  makes a denied path unreadable by mounting over it, and executing or mapping a file needs
  read access to it, so the loader route is closed as well as `execve`.
- **Copying the binary does not get around it**, because the copy has to read the file.
- **A setuid bit grants nothing inside the sandbox**: `NoNewPrivs` is 1 (bubblewrap sets
  `PR_SET_NO_NEW_PRIVS`) and the effective capability set is empty. So a binary that is
  reachable gives the agent no more than its own uid, and the exec denial is a second line
  behind "no `sudoers` entry, no polkit grant, no reachable broker socket", which is the
  boundary [Phase 5b](../README.md#phase-5b--ops-broker-in-slices) relies on.

## What was not tried

- **macOS Seatbelt.** Whether SRT's read denial also denies `process-exec` there, and how
  setuid binaries are enumerated on macOS. The ops profile targets Linux; macOS ops stays
  out of scope until this is tried.
- **A real server.** Only a container with a recent kernel; no systemd, no polkit, no real
  `sudo` configuration, no AppArmor or SELinux policy in the way.
- **The real targets.** `sudo`, `su`, `doas`, `pkexec` themselves were not denied and run;
  a copy of `id` stood in for them. The Phase 5b conformance row names the real paths, and
  every other name a package manager may install them under (`/usr/bin/sudo` and
  `/bin/sudo` on a merged-`/usr` system are one file; on a split one they are not).
- **Other loaders and interpreters.** `busybox`, a static loader, `memfd_create` plus
  `fexecve` from an interpreter that is allowed: none of these can read the denied file
  either, but they were not run.
- **The container backend.** Docker and Podman were not part of this; they have their own
  mount and capability rules.

## Re-running it at Checkpoint A

On the Linux server, as the user pi-enclave will run as: put the two files into
`test/spike/` of a checkout, run the `vitest` command above, and add a section here with
the host details and the output. On the Mac, change the loader line to something that exists
there or drop it, and record whether `escalate` runs.
