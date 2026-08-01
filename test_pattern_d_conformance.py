"""
AGOF(TM) Enterprise — Pattern D (OS-level Kernel Enforcement) conformance suite.

T-D01..T-D11. Real Linux seccomp user-notification syscall interception driving
the certified agof_engine.BEE.evaluate() (no stub / no mock / no monkey-patch).
Each test forks a governed child that issues REAL syscalls; the kernel traps them
and this process supervises the decision through the real engine, then asserts
BOTH the BEE verdict AND the real on-disk / observable effect.

Scope (declared, per Synthesis Prompt v5 honesty): OS-level Linux seccomp only.
Hypervisor-level (VM-I/O) enforcement and independent third-party red teaming are
OUT OF SCOPE and remain open. Permitted-path enforcement uses USER_NOTIF_CONTINUE,
which carries a residual TOCTOU re-resolution risk documented in the evidence record.

Run:  python -m pytest test_pattern_d_conformance.py -v
Requires: Linux >= 5.0 with seccomp user_notif; x86_64; the Enterprise TEST KIT
agof_engine.py importable (set AGOF_KIT env var if not at the default path).
"""
import os, errno, uuid, ctypes
import pytest
from pattern_d_kernel import KernelSupervisor, libc, SYS, ALL_SYS, AT_FDCWD, O_WRONLY, O_CREAT

pytestmark = pytest.mark.skipif(not os.path.exists("/proc/sys/kernel"),
                                reason="Linux seccomp required")

_HERE = os.path.dirname(os.path.abspath(__file__))
_IOU_LIB = os.path.join(_HERE, "libiouring_bypass.so")


@pytest.fixture(scope="module")
def sup(tmp_path_factory):
    root = str(tmp_path_factory.mktemp("agof_d"))
    # Govern io_uring too (ALL_SYS): a syscall-only filter is bypassable via io_uring.
    s = KernelSupervisor(root, governed_syscalls=ALL_SYS)  # creates res/ and secret/
    open(f"{root}/res/precious", "w").write("keep")        # target for denied-delete tests
    return s


def _only(decisions, syscall):
    hits = [d for d in decisions if d["syscall"] == syscall]
    assert hits, f"no {syscall} syscall was trapped; got {decisions}"
    return hits[-1]


# ----------------------------------------------------------- PERMIT coverage
def test_TD01_permit_write_mkdir(sup):
    d = sup.run(lambda r: os.mkdir(f"{r}/res/td01"))
    v = _only(d, "mkdir")
    assert v["verdict"] == "PERMITTED"
    assert os.path.isdir(f"{sup.root}/res/td01")            # real effect happened


def test_TD02_permit_write_create_file(sup):
    d = sup.run(lambda r: os.close(os.open(f"{r}/res/td02", O_WRONLY | O_CREAT, 0o644)))
    assert _only(d, "openat")["verdict"] == "PERMITTED"
    assert os.path.isfile(f"{sup.root}/res/td02")


def test_TD03_permit_read_open(sup):
    open(f"{sup.root}/res/td03", "w").write("x")
    d = sup.run(lambda r: os.close(os.open(f"{r}/res/td03", 0)))
    v = _only(d, "openat")
    assert v["action"] == "READ_DATA" and v["verdict"] == "PERMITTED"


# --------------------------------------------------------- DENY by resource
def test_TD04_deny_write_out_of_scope(sup):
    d = sup.run(lambda r: _try(lambda: os.mkdir(f"{r}/secret/td04")))
    v = _only(d, "mkdir")
    assert v["verdict"] == "CONTAINED" and v["reason"] == "RESOURCE_SCOPE_BREACH"
    assert not os.path.isdir(f"{sup.root}/secret/td04")     # never created


def test_TD05_deny_path_traversal(sup):
    d = sup.run(lambda r: _try(lambda: os.mkdir(f"{r}/res/../secret/td05")))
    v = _only(d, "mkdir")
    assert v["verdict"] == "CONTAINED" and v["reason"] == "RESOURCE_SCOPE_BREACH"
    assert not os.path.isdir(f"{sup.root}/secret/td05")     # traversal blocked


# ----------------------------------------------------------- DENY by action
def test_TD06_deny_delete_action(sup):
    d = sup.run(lambda r: _try(lambda: os.unlink(f"{r}/res/precious")))
    v = _only(d, "unlink")
    assert v["verdict"] == "CONTAINED" and v["reason"] == "ACTION_SCOPE_BREACH"
    assert os.path.isfile(f"{sup.root}/res/precious")       # file survived


def test_TD07_deny_network_invoke(sup):
    import socket as _s
    def act(r):
        s = _s.socket(_s.AF_INET, _s.SOCK_STREAM)
        try: _try(lambda: s.connect(("93.184.216.34", 80)))
        finally: s.close()
    v = _only(sup.run(act), "connect")
    assert v["action"] == "INVOKE_API" and v["verdict"] == "CONTAINED"


def test_TD08_deny_process_spawn(sup):
    def act(r):
        path = b"/bin/true"
        argv = (ctypes.c_char_p * 2)(ctypes.c_char_p(path), None)
        envp = (ctypes.c_char_p * 1)(None)
        libc.execve(path, argv, envp)   # trapped+denied -> returns, process NOT replaced
    v = _only(sup.run(act), "execve")
    assert v["action"] == "SPAWN_AGENT" and v["verdict"] == "CONTAINED"


# ------------------------------------------------ BYPASS resistance battery
def test_TD09_bypass_fork_escape(sup):
    def act(r):
        pid = os.fork()
        if pid == 0:
            _try(lambda: os.mkdir(f"{r}/secret/td09")); os._exit(0)
        os.waitpid(pid, 0)
    d = sup.run(act)
    assert _only(d, "mkdir")["verdict"] == "CONTAINED"       # grandchild trapped too
    assert not os.path.isdir(f"{sup.root}/secret/td09")


def test_TD10_bypass_thread_escape(sup):
    import threading
    def act(r):
        t = threading.Thread(target=lambda: _try(lambda: os.mkdir(f"{r}/secret/td10")))
        t.start(); t.join()
    d = sup.run(act)
    assert _only(d, "mkdir")["verdict"] == "CONTAINED"       # sibling thread trapped
    assert not os.path.isdir(f"{sup.root}/secret/td10")


def test_TD11_bypass_raw_syscall_no_libc(sup):
    def act(r):
        p = ctypes.create_string_buffer(f"{r}/secret/td11".encode())
        rc = libc.syscall(SYS["openat"], AT_FDCWD, p, O_WRONLY | O_CREAT, 0o644)
        if rc >= 0: os.close(rc)
    d = sup.run(act)
    assert _only(d, "openat")["verdict"] == "CONTAINED"      # raw syscall trapped
    assert not os.path.isfile(f"{sup.root}/secret/td11")


@pytest.mark.skipif(not os.path.exists(_IOU_LIB),
                    reason="libiouring_bypass.so not built (see README: gcc build step)")
def test_TD12_bypass_iouring_blocked(sup):
    """io_uring is an alternate submission path that never issues an openat syscall.
    A syscall-only filter is bypassable through it; governing io_uring_setup closes
    the hole. This asserts the CLOSED state: the ring-creation syscall is trapped,
    the BEE denies it, and no file is created under the denied secret/ path."""
    lib = ctypes.CDLL(_IOU_LIB)
    lib.iouring_openat.restype = ctypes.c_int
    lib.iouring_openat.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.c_int]
    def act(r):
        lib.iouring_openat(f"{r}/secret/td12_iou".encode(), O_WRONLY | O_CREAT, 0o644)
    d = sup.run(act)
    assert _only(d, "io_uring_setup")["verdict"] == "CONTAINED"   # ring creation denied
    assert not os.path.isfile(f"{sup.root}/secret/td12_iou")      # bypass blocked


def _try(fn):
    """Run fn, swallowing the EPERM the kernel returns for a denied syscall."""
    try: fn()
    except OSError as e:
        if e.errno != errno.EPERM: raise
