# AGOF™ Pattern D — Verify It Yourself

*Public reference repository — detailed run instructions*

**Watch a misbehaving AI agent get blocked at the operating-system kernel — on
your own machine, on a real Linux kernel.** Final result you are aiming for:
**`12 passed`**.

> **What you are running.** This bundle is the enforcement **mechanism** (real
> Linux `seccomp` syscall interception) plus a **tiny, non-normative policy
> stub** that stands in for the licensed AGOF™ Evaluation Engine. That lets you
> confirm the *containment* is real without us shipping the proprietary engine.
> The engine's proprietary decision logic and the full conformance matrix are
> demonstrated separately under NDA.

Pattern D enforces at the **Linux kernel**, so it needs a **real Linux kernel** —
native Linux, or **Windows + WSL2**. It does not run in a browser sandbox or a
restricted container (those block the `seccomp` user-notification mechanism this
reference depends on).

---

## Windows users — one-time WSL2 setup (~10 min)

If you already have native Linux, skip to **"Run it"** below.

### 1. Install WSL2

Press the **Windows key**, type `powershell`, right-click **Terminal
(Administrator)** → **Run as administrator**, and run:

```
wsl --install
```

This installs WSL2 and Ubuntu automatically. If it asks you to **restart**, do
so. On first launch Ubuntu asks for a **username** and **password** — create them
(⚠️ while typing the password **nothing appears on screen — no dots. That is
normal**). You end up at a green prompt like `you@PC:~$` — that is Linux.

### 2. Update the WSL2 kernel — REQUIRED

**This is the #1 thing people miss.** An older WSL2 kernel (5.x) silently hangs
the test at the first case. Update it. Back in the **Windows** Terminal
(Administrator) — **not** the Ubuntu window — run:

```
wsl --update
wsl --shutdown
```

> `wsl` is a **Windows** command. Do not run it inside Ubuntu (there it says
> "command not found"; ignore the `apt install wsl` suggestion).

Then **open a fresh Ubuntu window** and confirm the kernel is **6.x**:

```
uname -r
```

If it shows `6.` you are good. If it still shows `5.15…`, repeat `wsl --update`
/ `wsl --shutdown` and reopen Ubuntu.

---

## Run it

At an Ubuntu (or native Linux) prompt:

### 1. Get the code (into your Linux home — NOT `/mnt/c`)

```
git clone https://github.com/Kiko1961/agof-pattern-d-reference ~/agof-d && cd ~/agof-d
```

Running from a Windows path (`/mnt/c/...`) causes permission errors when the
test compiles a helper — always work from your Linux home (`~`).

### 2. Install the four tools (one time)

```
sudo apt update && sudo apt install -y python3 gcc python3-pytest make
```

(`sudo` asks for the password you created — invisible while typing.)

### 3. Run — watch the screen (do not redirect to a file)

```
make test
```

With a 6.x kernel this finishes in about a second. Expected final line:

```
============================== 12 passed ==============================
```

That's it — you just ran real Linux `seccomp` kernel-level containment against
12 conformance tests, on your own machine, and watched the result live.

---

## Troubleshooting (the exact snags, pre-answered)

| You see | Do this |
|---|---|
| Test **hangs at `test_TD01…`** and never finishes | Your WSL2 kernel is too old (5.x). Ctrl+C, then in the **Windows** Terminal run `wsl --update` and `wsl --shutdown`, reopen Ubuntu, confirm `uname -r` is `6.x`, retry. |
| `make: command not found` | `sudo apt install -y make` (it's in the tools line above). |
| `wsl` "command not found" | You're inside Ubuntu. `wsl` runs in the **Windows** Terminal, not Ubuntu. |
| `Permission denied` compiling `.so` | You're on a Windows path. Work from `~` (step 1), not `/mnt/c`. |
| `No module named pytest` | Use `sudo apt install -y python3-pytest` (not `pip`). |
| Password shows nothing while typing | Normal — it is being entered. Type it and press Enter. |

---

## What the 12 tests prove

- **TD01–03 (permit):** in-scope writes/reads run and take real effect on disk.
- **TD04–08 (deny):** out-of-scope writes, deletes, network connections and
  process spawns are blocked **at the kernel** with `EPERM` — they never reach
  the filesystem or network.
- **TD09–12 (bypass resistance):** escapes via `fork`, threads, raw syscalls
  with no libc, and the `io_uring` alternate I/O path are all trapped.
  Enforcement is a property of the OS, not of cooperative library calls.

## Honest scope (read before you cite us)

This reference proves the **Linux `seccomp` OS-level enforcement mechanism** and
its bypass resistance, driven by a **non-normative policy stub**. It does **not**
include the licensed AGOF™ Evaluation Engine, hypervisor-level enforcement, or
independent third-party red-team results. A **residual TOCTOU on the permitted
path** (a check→use race in multi-threaded targets, affecting permitted calls
only) is documented in the evidence record and must be mitigated before Pattern D
is relied on for high-assurance enforcement. It was exercised under WSL2 (a real
Linux kernel, not bare-metal). We say all this plainly — overstating one's own
assurance is the exact failure mode AGOF™ exists to prevent. The engine and the
full conformance matrix are shown under NDA.

---

© 2026 PRASOL LLC · AGOF™ Pattern D public reference · Code licensed under
[Apache-2.0](LICENSE).
