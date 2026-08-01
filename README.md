# AGOF™ Pattern D — Verify It Yourself

**Watch a misbehaving AI agent get blocked at the operating-system kernel — on
your own screen, in about 3 minutes, with nothing to install.**

[![Open in GitHub Codespaces](https://github.com/codespaces/badge.svg)](https://codespaces.new/Kiko1961/agof-pattern-d-reference?quickstart=1)

## One-click path (recommended — works from any browser, including Windows)

1. Click the **Open in GitHub Codespaces** button above (a free GitHub account
   is all you need).
2. Wait for the environment to finish loading (~1–2 minutes, one time).
3. In the terminal at the bottom, type:

   ```bash
   make test
   ```

4. Expected result: **`12 passed`**.

That's it. You just ran real Linux `seccomp` kernel-level containment against
12 conformance tests — including escape attempts via `fork`, threads, raw
syscalls with no libc, and the `io_uring` alternate I/O path.

> If the Codespaces container restricts `seccomp` and the run cannot start,
> use the local path below — same tests, same expected `12 passed`.

## Local path (Linux or Windows + WSL2)

Full step-by-step instructions, including a from-zero WSL2 setup for Windows
users and a troubleshooting table: **[HOW_TO_RUN.md](HOW_TO_RUN.md)**.

## What this is (and honestly is not)

This bundle is the enforcement **mechanism** (real Linux `seccomp` syscall
interception) driven by a **tiny, non-normative policy stub** that stands in
for the licensed AGOF™ Evaluation Engine. That is deliberate: it lets you
confirm the *containment* is real without us shipping the proprietary engine.
The engine's decision model (BIS/ECS/ACS + cryptographic lineage) and the full
conformance matrix are demonstrated separately under NDA.

**What the 12 tests prove:**

- **TD01–03 (permit):** in-scope writes/reads run and take real effect on disk.
- **TD04–08 (deny):** out-of-scope writes, deletes, network connections and
  process spawns are blocked **at the kernel** with `EPERM`.
- **TD09–12 (bypass resistance):** escapes via `fork`, threads, raw syscalls
  and `io_uring` are all trapped. Enforcement is a property of the OS, not of
  cooperative library calls.

---

© 2026 PRASOL LLC · AGOF™ Pattern D public reference · Code licensed under
[Apache-2.0](LICENSE).
