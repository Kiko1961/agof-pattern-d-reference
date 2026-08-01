# AGOF™ Pattern D — Verify It Yourself

**If you opened this from the verification link:** you don't need to do
anything. The 12-test verification is running **by itself** in the terminal at
the bottom of this screen. Expected final line:

```
============================== 12 passed ==============================
```

> **About the wait:** the ~2-minute initial load is GitHub provisioning a
> fresh, disposable cloud machine — it is **not** AGOF™. The AGOF™
> verification itself completes in **under one second** (12 tests in ~0.3s).

**Didn't see it run?** Click the terminal at the bottom, type `make test`,
press Enter. Same expected result: `12 passed`.

## What you just verified

You ran real Linux `seccomp` **kernel-level containment** against 12
conformance tests — including escape attempts via `fork`, threads, raw
syscalls with no libc, and the `io_uring` alternate I/O path.

- **TD01–03 (permit):** in-scope writes/reads run and take real effect on disk.
- **TD04–08 (deny):** out-of-scope writes, deletes, network connections and
  process spawns are blocked **at the kernel** with `EPERM`.
- **TD09–12 (bypass resistance):** escapes via `fork`, threads, raw syscalls
  and `io_uring` are all trapped. Enforcement is a property of the OS, not of
  cooperative library calls.

## Browsing this repository on GitHub instead?

Launch the disposable test environment with one click (a free GitHub account
is all you need) — then everything above applies:

[![Open in GitHub Codespaces](https://github.com/codespaces/badge.svg)](https://codespaces.new/Kiko1961/agof-pattern-d-reference?quickstart=1)

## Prefer to run it on your own machine?

Linux or Windows + WSL2. Full step-by-step instructions, including a
from-zero WSL2 setup for Windows users and a troubleshooting table:
**[HOW_TO_RUN.md](HOW_TO_RUN.md)**.

## What this is (and honestly is not)

This bundle is the enforcement **mechanism** (real Linux `seccomp` syscall
interception) driven by a **tiny, non-normative policy stub** that stands in
for the licensed AGOF™ Evaluation Engine. That is deliberate: it lets you
confirm the *containment* is real without us shipping the proprietary engine.
The engine's decision model (BIS/ECS/ACS + cryptographic lineage) and the full
conformance matrix are demonstrated separately under NDA.

---

© 2026 PRASOL LLC · AGOF™ Pattern D public reference · Code licensed under
[Apache-2.0](LICENSE).
