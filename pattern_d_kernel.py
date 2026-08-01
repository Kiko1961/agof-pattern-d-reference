"""
AGOF(TM) Enterprise — Pattern D kernel-enforcement harness (shared helpers).

Real Linux seccomp user-notification syscall interception. PUBLIC REFERENCE:
drives a local non-normative POLICY STUB (agof_engine.py in this folder), not the
licensed engine. The interception mechanism is the real thing; the stub only
decides permit/deny so the demo runs standalone.
"""
import ctypes, os, socket, sys, errno, uuid, time, threading, select, fcntl
from datetime import datetime, timedelta, timezone

# PUBLIC REFERENCE: the decision authority is the LOCAL non-normative policy
# stub (agof_engine.py in this folder), NOT the licensed AGOF Evaluation Engine.
# The seccomp enforcement MECHANISM below is identical to the internal version;
# only the brain behind evaluate() is a stub, so this runs standalone.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from agof_engine import (BEE, AgentLineageStore, BoundaryRegistry,   # noqa: E402
                         ed25519_public_key, ed25519_sign,
                         registration_payload_hash, issuance_payload_hash)

libc = ctypes.CDLL(None, use_errno=True)
PR_SET_NO_NEW_PRIVS=38; SECCOMP_SET_MODE_FILTER=1; SECCOMP_FILTER_FLAG_NEW_LISTENER=8
SECCOMP_RET_ALLOW=0x7fff0000; SECCOMP_RET_USER_NOTIF=0x7fc00000
SECCOMP_USER_NOTIF_FLAG_CONTINUE=1; NR_SECCOMP=317
SYS={"openat":257,"mkdir":83,"mkdirat":258,"unlink":87,"unlinkat":263,"connect":42,"execve":59}
SYS_IOURING={"io_uring_setup":425,"io_uring_enter":426,"io_uring_register":427}
ALL_SYS={**SYS,**SYS_IOURING}
NAME={v:k for k,v in ALL_SYS.items()}
AT_FDCWD=-100; O_WRONLY=1; O_RDWR=2; O_CREAT=0o100
def _IOC(d,t,nr,size): return (d<<30)|(size<<16)|(t<<8)|nr
RECV=_IOC(3,0x21,0,80); SEND=_IOC(3,0x21,1,24); IDVALID=_IOC(1,0x21,2,8)

class sock_filter(ctypes.Structure):
    _fields_=[("code",ctypes.c_uint16),("jt",ctypes.c_uint8),("jf",ctypes.c_uint8),("k",ctypes.c_uint32)]
class sock_fprog(ctypes.Structure):
    _fields_=[("len",ctypes.c_ushort),("filter",ctypes.POINTER(sock_filter))]
class seccomp_data(ctypes.Structure):
    _fields_=[("nr",ctypes.c_int),("arch",ctypes.c_uint32),("ip",ctypes.c_uint64),("args",ctypes.c_uint64*6)]
class seccomp_notif(ctypes.Structure):
    _fields_=[("id",ctypes.c_uint64),("pid",ctypes.c_uint32),("flags",ctypes.c_uint32),("data",seccomp_data)]
class seccomp_notif_resp(ctypes.Structure):
    _fields_=[("id",ctypes.c_uint64),("val",ctypes.c_int64),("error",ctypes.c_int32),("flags",ctypes.c_uint32)]

BPF_LD=0x00;BPF_W=0x00;BPF_ABS=0x20;BPF_JMP=0x05;BPF_JEQ=0x10;BPF_K=0x00;BPF_RET=0x06
def build_filter(nrs):
    ins=[sock_filter(BPF_LD|BPF_W|BPF_ABS,0,0,0)]
    trapped=list(nrs); n=len(trapped)
    for i,nr in enumerate(trapped):
        ins.append(sock_filter(BPF_JMP|BPF_JEQ|BPF_K, n-i, 0, nr))
    ins.append(sock_filter(BPF_RET|BPF_K,0,0,SECCOMP_RET_ALLOW))
    ins.append(sock_filter(BPF_RET|BPF_K,0,0,SECCOMP_RET_USER_NOTIF))
    return (sock_filter*len(ins))(*ins)

def _read_str(pid,addr):
    with open(f"/proc/{pid}/mem","rb",0) as m:
        m.seek(addr); buf=b""
        while len(buf)<4096:
            c=m.read(64)
            if not c: break
            if b"\x00" in c: buf+=c[:c.index(b"\x00")]; break
            buf+=c
    return buf.decode("utf-8","replace")

class KernelSupervisor:
    """Builds the real BEE once; supervises seccomp listeners driving it."""
    def __init__(self, root, permitted_actions=("READ_DATA","WRITE_DATA"),
                 permitted_resources=("res/",), governed_syscalls=None):
        self.root=root
        # default: govern file/net/exec syscalls. Pass ALL_SYS to also govern io_uring.
        self.gov_nrs=list((governed_syscalls if governed_syscalls is not None else SYS).values())
        os.makedirs(f"{root}/res",exist_ok=True); os.makedirs(f"{root}/secret",exist_ok=True)
        self.bee,self.arr,self.org=self._build(f"{root}/alr.jsonl",
                                               permitted_actions,permitted_resources)

    def _build(self,store_path,pa,pr):
        ORG=str(uuid.uuid4()); ISS=str(uuid.uuid4()); SEC=bytes(range(32)); PUB=ed25519_public_key(SEC)
        T0=datetime.now(timezone.utc)
        iso=lambda d: d.astimezone(timezone.utc).isoformat().replace("+00:00","Z")
        reg=BoundaryRegistry(); reg.register_issuer(ISS,PUB,"ROOT"); store=AgentLineageStore(store_path)
        arr={"agent_id":str(uuid.uuid4()),"agent_name":"kernel-agent","agent_version":"1.0.0",
             "organization_id":ORG,"registration_timestamp":iso(T0-timedelta(days=1)),
             "registered_by":ISS,"status":"ACTIVE","assigned_boundaries":[],
             "agent_class":"AUTONOMOUS","description":"pattern-D","tags":[]}
        arr["registration_signature"]=ed25519_sign(SEC,bytes.fromhex(registration_payload_hash(arr)))
        reg.register_agent(arr)
        aeb={"aeb_id":str(uuid.uuid4()),"aeb_version":"1.0.0","agent_id":arr["agent_id"],
             "organization_id":ORG,"issued_by":ISS,"issued_timestamp":iso(T0-timedelta(days=1)),
             "effective_from":iso(T0-timedelta(days=1)),"effective_until":None,"status":"ACTIVE",
             "action_scope":{"permitted_actions":list(pa),"denied_actions":[]},
             "resource_scope":{"permitted_resources":list(pr),"scope_resolution":"PREFIX","cross_boundary_allowed":False},
             "context_conditions":{"permitted_system_states":["OPERATIONAL","TESTING"],
                                   "time_restrictions":{"allowed_windows":None},"concurrent_agent_policy":"ALLOW"},
             "boundary_responses":{"on_action_scope_breach":"CONTAIN","on_resource_scope_breach":"CONTAIN","on_context_breach":"CONTAIN"},
             "escalation_target":ISS,"escalation_timeout_seconds":None,"supersedes":None,
             "amendment_category":None,"amendment_notes":None}
        aeb["issuance_signature"]=ed25519_sign(SEC,bytes.fromhex(issuance_payload_hash(aeb)))
        reg.register_aeb(aeb)
        return BEE(reg,store),arr,ORG

    def _map(self,nr,data,pid):
        name=NAME[nr]
        if name=="openat":
            path=_read_str(pid,data.args[1]); flags=data.args[2]
            action="WRITE_DATA" if (flags&(O_WRONLY|O_RDWR|O_CREAT)) else "READ_DATA"
        elif name=="mkdir": path=_read_str(pid,data.args[0]); action="WRITE_DATA"
        elif name=="mkdirat": path=_read_str(pid,data.args[1]); action="WRITE_DATA"
        elif name=="unlink": path=_read_str(pid,data.args[0]); action="DELETE_DATA"
        elif name=="unlinkat": path=_read_str(pid,data.args[1]); action="DELETE_DATA"
        elif name=="connect": path="net/egress"; action="INVOKE_API"
        elif name=="execve": path="proc/"+os.path.basename(_read_str(pid,data.args[0])); action="SPAWN_AGENT"
        elif name in ("io_uring_setup","io_uring_enter","io_uring_register"):
            # io_uring is an alternate submission path that bypasses per-syscall
            # filtering; governing ring creation/entry forces it through the BEE.
            path="io_uring/"+name; action="INVOKE_API"
        else: path="?"; action="READ_DATA"
        if path.startswith("/") or ".." in path:
            real=os.path.normpath(path)
            try: rel=os.path.relpath(real,self.root)
            except ValueError: rel=real
            base=os.path.basename(real.rstrip("/"))
            rt=("res/"+base) if rel.startswith("res") else (("secret/"+base) if rel.startswith("secret") else ("other/"+base))
        else: rt=path
        return name,action,rt

    def _evaluate(self,action,rt):
        req={"request_id":str(uuid.uuid4()),"agent_id":self.arr["agent_id"],"organization_id":self.org,
             "request_timestamp":datetime.now(timezone.utc).isoformat().replace("+00:00","Z"),
             "request_nonce":uuid.uuid4().hex+uuid.uuid4().hex,"action_type":action,
             "action_class":"DERIVED_BY_BEE","resource_target":rt,"resource_type":"DATA_STORE",
             "context_snapshot":{"requesting_pipeline":"pattern-d","request_chain_id":str(uuid.uuid4())}}
        return self.bee.evaluate(req)

    def run(self, child_action):
        """Fork a governed child that runs child_action() (which does one or more
        governed syscalls); supervise every trapped syscall through the real BEE.
        Returns list of dicts: {syscall, action, resource, verdict, reason}."""
        ps,cs=socket.socketpair(socket.AF_UNIX)
        pid=os.fork()
        if pid==0:
            ps.close()
            try:
                if libc.prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0)!=0: os._exit(10)
                flt=build_filter(self.gov_nrs)
                fprog=sock_fprog(len(flt),ctypes.cast(flt,ctypes.POINTER(sock_filter)))
                fd=libc.syscall(NR_SECCOMP,SECCOMP_SET_MODE_FILTER,SECCOMP_FILTER_FLAG_NEW_LISTENER,ctypes.byref(fprog))
                if fd<0: os._exit(11)
                socket.send_fds(cs,[b"L"],[fd]); os.close(fd)
                child_action(self.root)
            except SystemExit: raise
            except BaseException:
                pass   # denied syscalls raise EPERM in the child; that is expected
            finally:
                try: cs.sendall(b"DONE")
                except OSError: pass
            os._exit(0)
        cs.close()
        _,fds,_,_=socket.recv_fds(ps,1,1); fd=fds[0]
        fcntl.fcntl(fd,fcntl.F_SETFL,fcntl.fcntl(fd,fcntl.F_GETFL)|os.O_NONBLOCK)
        decisions=[]; done=False; reaped=False; deadline=time.time()+20

        def drain():
            """Handle every currently-pending trapped syscall (non-blocking)."""
            while True:
                notif=seccomp_notif()
                try:
                    if libc.ioctl(fd,RECV,ctypes.byref(notif))!=0: return
                except OSError: return   # EAGAIN: nothing pending
                nid=ctypes.c_uint64(notif.id)
                if libc.ioctl(fd,IDVALID,ctypes.byref(nid))!=0: continue
                name,action,rt=self._map(notif.data.nr,notif.data,notif.pid)
                v=self._evaluate(action,rt)
                resp=seccomp_notif_resp(id=notif.id,val=0,error=0,flags=0)
                if v["final_verdict"]=="PERMITTED": resp.flags=SECCOMP_USER_NOTIF_FLAG_CONTINUE
                else: resp.error=-errno.EPERM
                libc.ioctl(fd,SEND,ctypes.byref(resp))
                decisions.append({"syscall":name,"action":action,"resource":rt,
                                  "verdict":v["final_verdict"],"reason":v.get("reason_code")})

        while time.time()<deadline:
            select.select([fd,ps],[],[],0.2)
            drain()                                  # service pending syscalls
            try:                                     # control-channel DONE?
                if ps.recv(64, socket.MSG_DONTWAIT).startswith(b"DONE"): done=True
            except (BlockingIOError, OSError): pass
            try:                                     # child exited?
                if os.waitpid(pid, os.WNOHANG)[0]==pid: reaped=True
            except ChildProcessError: reaped=True
            if done or reaped:
                drain()                              # final straggler drain
                break
        os.close(fd)
        if not reaped:
            try: os.waitpid(pid,0)
            except ChildProcessError: pass
        return decisions
