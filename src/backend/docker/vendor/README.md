# Moby seccomp profile

`moby-seccomp.json` and `LICENSE.moby` are unmodified copies from
[moby/profiles seccomp/v0.2.3](https://github.com/moby/profiles/tree/836ae4d37ef2ec995c77c99fc55f5b5f3af3a897),
commit `836ae4d37ef2ec995c77c99fc55f5b5f3af3a897`.

Upstream JSON SHA-256: `536529b665dd0972c37bfb569f5d4ac8a53592e7b00752bc39ff063ca9864c74`.

`../seccomp.ts` derives the offline policy by removing every allow rule for
`socket`, `socketcall`, and io_uring. It preserves all other upstream restrictions.
This prevents access to host Unix sockets even when one is inside an exposed
workspace. `socketpair` remains available for communication within a process tree.
Review this pinned profile when updating Docker/kernel support; it does not
automatically inherit later upstream hardening.
