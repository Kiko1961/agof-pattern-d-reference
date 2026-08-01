# AGOF™ Pattern D — Verify It Yourself

**Goal:** in about 10 minutes, on your own machine, watch AGOF™ block a
misbehaving agent **at the operating-system kernel** — and watch the usual
escape tricks fail. You run everything; we hand over nothing but this small
open reference. Expected result at the end: **`12 passed`**.

> **What you are running.** This bundle is the enforcement **mechanism** (real
> Linux `seccomp` syscall interception) plus a **tiny, non-normative policy
> stub** that stands in for the licensed AGOF™ Evaluation Engine. That is
> deliberate: it lets you confirm the *containment* is real without us shipping
> the proprietary engine. The engine's decision model (BIS/ECS/ACS + lineage)
> is demonstrated separately under NDA.

---

## 0. What you need

- **Linux x86_64**, kernel **5.0 or newer** (any recent Ubuntu, Debian, Fedora…).
- If you are on **Windows**, use **WSL2** — Section A sets it up (5 minutes).
- If you already have Linux (or a Linux VM), skip straight to **Section B**.

You do **not** need root for the test itself, only for installing packages.

---

## Section A — Windows users: set up WSL2 (one time)

WSL2 is Microsoft's built-in Linux. Do this exactly; it avoids the two traps
people hit most.

**A1. Turn OFF "Fast Startup"** (this is the #1 reason WSL2 "won't start"):
1. Press the **Windows key**, type `powershell`, right-click **Windows
   PowerShell → Run as administrator**.
2. Run: `powercfg /h off`
3. Fully shut down — **Start → Power → Shut down** (a *Restart* is not enough
   here). Then power the machine back on.

**A2. Install Ubuntu from the Microsoft Store** (do **not** use `wsl --install`
from the command line — it fails silently on some machines):
1. Windows key → type `store` → open **Microsoft Store**.
2. Search **Ubuntu** → open **"Ubuntu 24.04 LTS"** (publisher: Canonical) →
   **Get / Install**. Wait for the button to change to **Open**.
3. Click **Open**. The first launch shows *"Installing, this may take a few
   minutes."*
4. It then asks for a **UNIX username** (lowercase, no spaces — e.g. `analyst`)
   and a **password**. ⚠️ **While you type the password nothing appears on
   screen — no dots, no stars. That is normal.** Type it, Enter, type it again.
5. You now have a green prompt like `analyst@PC:~$`. You're in Linux.

**Check it worked:** at the green prompt, run `uname -r`. If you see a kernel
version (e.g. `5.x`/`6.x`), you're ready. Continue to Section B **inside this
Ubuntu window**.

> If `wsl --status` earlier said *"virtualization … enable in BIOS"* even though
> it's enabled: that's almost always Fast Startup (step A1) — do A1 and fully
> power-cycle. Only if it persists, enable "Virtualization/SVM" in your BIOS.

---

## Section B — Run the verification (Linux or WSL2)

**B1. Put this folder in your Linux home directory — NOT under `/mnt/c`.**
Running from a Windows path (`/mnt/c/...`) causes permission errors when the
test compiles a helper. Copy it into your home folder first:

```bash
# if you received a zip, from the folder where it landed:
cp -r "agof-pattern-d-reference" ~/agof-pattern-d && cd ~/agof-pattern-d
# (or: git clone <repo-url> ~/agof-pattern-d && cd ~/agof-pattern-d)
```

If you copied from a Windows path, make the files writable once:

```bash
chmod -R u+rwX .
```

**B2. Install the three tools you need** (Python, a C compiler, pytest):

```bash
sudo apt update
sudo apt install -y python3 gcc python3-pytest
```

> Use `python3-pytest` from apt as shown. `pip install pytest` can leave pytest
> "not importable" on Ubuntu — avoid it here.

**B3. Run it:**

```bash
make test
```

That compiles the `io_uring` helper and runs the 12 conformance tests.

---

## What you should see

```
test_pattern_d_conformance.py::test_TD01_permit_write_mkdir PASSED
... (TD02 … TD11) ...
test_pattern_d_conformance.py::test_TD12_bypass_iouring_blocked PASSED
============================== 12 passed ==============================
```

**What the 12 tests prove:**
- **TD01–03 (permit):** writes/reads *inside* the agent's authorized scope run
  and take real effect on disk.
- **TD04–08 (deny):** out-of-scope writes, deletes, network connections, and
  process spawns are blocked **at the kernel** with `EPERM` — they never reach
  the filesystem or network.
- **TD09–12 (bypass resistance):** attempts to escape via `fork`, via threads,
  via **raw syscalls with no libc**, and via the **`io_uring`** alternate path
  are all trapped. Enforcement is a property of the OS, not of cooperative
  library calls.

---

## Troubleshooting (the exact snags, pre-answered)

| You see | Do this |
|---|---|
| `make: command not found` | `sudo apt install -y make` then rerun `make test`. |
| `gcc: not found` / compile error on `.so` | `sudo apt install -y gcc`; ensure you're in your **home** copy (B1), not `/mnt/c`. |
| `No module named pytest` | Use `sudo apt install -y python3-pytest` (not pip). |
| `Permission denied` writing `libiouring_bypass.so` | You're on a Windows path. Do B1 (copy to `~`) and `chmod -R u+rwX .`. |
| `ubuntu` "not recognized" (Windows) | Ubuntu isn't installed yet — do Section A2. |
| `TD12 … SKIPPED` | The `.so` didn't build. Run `make lib` and read any gcc error; usually a missing `gcc`. |
| WSL2 "won't start" / hypervisor error | Fast Startup — do A1 and **fully power off**, not restart. |

---

## Honest scope (read before you cite us)

This reference proves the **Linux `seccomp` OS-level enforcement mechanism** and
its bypass resistance, driven by a **non-normative policy stub**. It does **not**
include or demonstrate the licensed AGOF™ Evaluation Engine, hypervisor-level
enforcement, or independent third-party red-team results. We say so plainly —
overstating one's own assurance is the exact failure mode AGOF™ exists to
prevent. The engine and the full conformance matrix are shown under NDA.

© 2026 PRASOL LLC · Pattern D public reference · Apache-2.0 (code).
