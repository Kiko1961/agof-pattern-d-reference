# AGOF™ Pattern D — See It Block a Rogue AI Agent, On Your Own Computer

*Step-by-step. No computer knowledge needed. You will only copy, paste,
and press Enter.*

## What this is

AI agents are programs that act on their own. AGOF™ is not a program —
it is a set of licensed documents: exact rules for keeping AI agents
inside their limits. From those documents, a company builds its own
protection software. It stops an agent’s dangerous action **before it
happens**. This demo shows that protection live, on your own computer. A test agent tries to break its limits, again and again.
The operating system blocks every attempt. At the end, your screen will
say: `14 passed`. That is the proof.

> **Honesty note.** This demo contains the real enforcement mechanism
> (the small program that does the blocking), plus a tiny stand-in
> “brain” so it runs on its own. The real brain — the AGOF™ Evaluation
> Engine, software built from the licensed documents — is not included;
> it is shown privately under NDA. What you verify here, with your own eyes, is that
> the blocking is real, at the deepest level of the operating system.

## What you need

- A Windows PC — or a Linux computer.
- About 10 minutes.
- Everything used is free.

## The only skill you need: copy → paste → Enter

Every command in this guide sits in a gray box. Never type it. Instead:

1.  **Copy:** move the mouse over the gray box. A small icon appears at
    the **top-right corner of the box**. Click it once — that copies the
    whole command.
2.  **Paste:** click inside the command window. Then **right-click**.
    Right-click pastes.
3.  **Press Enter.** Nothing happens until you press Enter.

You will use two windows, and each step tells you which one:

- **Terminal window** — you open it in Part 1, Step 1. Used for the
  setup.
- **Ubuntu window** — appears at the end of Part 1. The demo runs here.
  Its last line ends in `$`.

If right-click does not paste, press **Ctrl+Shift+V**.

## Why is there a setup?

In this demo, the operating system itself blocks the agent — in its
deepest core, called the **kernel**. The kernel technique used here
lives in **Linux**. Windows can run a real Linux inside itself with
**WSL2**, a free feature from Microsoft. Part 1 turns WSL2 on.

Already on Linux? Skip to Part 2. (A browser or online sandbox cannot
run this demo — and that is the point: the protection lives in the
operating system itself.)

## Part 1 — Windows: turn on WSL2 (one time, ~10 min)

**Step 1. Open the Terminal window.**

1.  Press the **Windows key**.
2.  Type `powershell`.
3.  A search menu opens, with a **panel on its right side**. The panel
    shows the PowerShell logo and the words **Windows PowerShell**.
4.  In that panel, below the name, there is a list of options: *Open*,
    *Run as Administrator*, *Run ISE as Administrator*… Click **Run as
    Administrator**.
5.  If Windows asks for permission, click **Yes**.

A window for typing commands opens. This is the **Terminal window**.

**Step 2. Install WSL2.** Copy the gray box below → paste in the Terminal window →
**Enter**:

    wsl --install

What you will see: Windows installs Ubuntu (a Linux) by itself. If it
asks to **restart** the PC, restart. After the restart, Ubuntu opens by
itself. If it does not: press the **Windows key**, type `Ubuntu`, press
**Enter**. When Ubuntu opens for the first time, it asks you to create a
**username** and a **password**.

⚠️ While you type the password, the screen shows **nothing**. That is
normal. Type it and press **Enter**.

You end at a line ending in `$`. That is the **Ubuntu window**. Keep it
open.

**Step 3. Update Linux. Do not skip this.**

If Linux is old, the test freezes. Update it now, back in the **Terminal
window**. (Did the restart close it? Open it again as in Step 1.)

First box (gray box below). Copy it → paste in the **Terminal window** → **Enter**, and wait for it to finish:

    wsl --update

Second box (gray box below). Copy it → paste in the **Terminal window** → **Enter**:

    wsl --shutdown

Now open Ubuntu again: press the **Windows key**, type `Ubuntu`, press
**Enter**.

**Check that the update worked.** Copy the gray box below → paste in the **Ubuntu window** → **Enter**:

    uname -r

If the answer starts with **6**, you are ready. If it still starts with
5, repeat Step 3.

## Part 2 — Run the demo (3 commands)

All three go in the **Ubuntu window**, one at a time.

**Command 1 — install the five tools** (one time). Copy the gray box below → paste → **Enter**:

    sudo apt update && sudo apt install -y git python3 gcc python3-pytest make

What you will see: it asks for your **password**. Type it — invisible,
that is normal — and press **Enter**. Then it downloads for a minute or
two.

**Command 2 — download the demo.** Copy the gray box below → paste → **Enter**:

    git clone https://github.com/Kiko1961/agof-pattern-d-reference ~/agof-d && cd ~/agof-d

**Command 3 — run the 14 tests.** Copy the gray box below → paste → **Enter**:

    make test

What you will see: 14 lines, each ending in `PASSED`, and then:

    ============================== 14 passed ==============================

That’s it. A real operating system just contained a misbehaving agent —
on your machine, in front of you.

## If something goes wrong

| What you see                               | What to do                                                                                 |
|--------------------------------------------|--------------------------------------------------------------------------------------------|
| The test **freezes** at the first case     | Linux is old. Do Part 1, Step 3 again. Run Command 3 again.                                |
| `wsl: command not found`                   | You typed `wsl` in Ubuntu. It goes in the **Terminal window**.                             |
| `git`, `make` or `pytest` “not found”      | Run Command 1 again and watch for errors.                                                  |
| `Permission denied`                        | Run Command 2 again, exactly as written.                                                   |
| Password shows nothing while typing        | Normal. Type it and press **Enter**.                                                       |
| I can’t find the copy icon                 | Move the mouse over the gray box. The icon appears at its top-right corner.                |
| `destination path 'agof-d' already exists` | You already downloaded it. Copy → paste → **Enter**: `cd ~/agof-d` — then go to Command 3. |

## What the 14 tests prove

In plain words:

- Tests 1–3: the agent CAN do what it is allowed to do.
- Tests 4–8: every forbidden action — writing outside its area,
  deleting, reaching the network, launching programs — is stopped before
  it happens.
- Tests 9–12: the classic escape tricks do not work either.
- Tests 13–14: swapping a permitted file path for a forbidden one at the
  last instant is also caught.

In technical terms: real Linux `seccomp` user-notification syscall
interception. TD01–03 permit in-scope operations with real on-disk
effect; TD04–08 deny out-of-scope `openat`/`unlink`/`connect`/`execve`
with `EPERM` at the kernel; TD09–12 trap `fork`, thread, raw-syscall (no
libc) and `io_uring` escape paths; TD13–14 close the check→use (TOCTOU)
race on the permitted path — permitted operations execute
supervisor-side via `openat2` with
`RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS`, so the
kernel never re-resolves an attacker-swapped path. TD13–14 fail against
the previous build; they exist to prove the window is closed.

## Honest scope (read before you cite us)

This reference proves the OS-level enforcement mechanism and its bypass
resistance, driven by a non-normative stand-in policy. It does **not**
include the licensed AGOF™ Evaluation Engine, hypervisor-level
enforcement, or independent third-party red-team results. The check→use
(TOCTOU) race reported in earlier revisions is **mitigated in this
build** (see TD13–14); requires Linux 5.6 or newer. Governed permitted
operations carry a modest latency premium — Pattern D is intended for
high-assurance surfaces. It was exercised under WSL2 (a real Linux
kernel, not bare-metal). We say all this plainly — overstating one’s own
assurance is the exact failure mode AGOF™ exists to prevent. The engine
and the full conformance matrix are shown under NDA.

© 2026 PRASOL LLC · AGOF™ Pattern D public reference · Code licensed
under [Apache-2.0](LICENSE).
