"""
=====================================================================
  NON-NORMATIVE POLICY STUB  --  NOT the AGOF(TM) Evaluation Engine
=====================================================================

This file exists ONLY so the Pattern D enforcement MECHANISM (real Linux
seccomp syscall interception, in pattern_d_kernel.py) can run standalone for
public verification. It is a deliberately trivial policy: it does NOT contain
the AGOF Evaluation Engine or any of its proprietary decision logic. That
remains licensed and is demonstrated separately under NDA.

What this stub decides (all it does):
  * action must be in the boundary's permitted_actions      -> else CONTAINED / ACTION_SCOPE_BREACH
  * resource must sit under a permitted_resources prefix     -> else CONTAINED / RESOURCE_SCOPE_BREACH
  * otherwise                                                -> PERMITTED

That is enough to prove the KERNEL MECHANISM works (permitted syscalls run;
everything else is blocked with EPERM before it touches the disk or network,
and the bypass attempts fork / thread / raw-syscall / io_uring are all trapped).
It is NOT a governance engine and must not be represented as one.

The public API surface below mirrors only what pattern_d_kernel.py imports.
Signatures/hashes are inert placeholders (this stub verifies nothing crypto).
"""
import hashlib
import json
import uuid


# ---- inert crypto placeholders (the stub verifies no signatures) -----------
def ed25519_public_key(secret: bytes) -> bytes:
    return hashlib.sha256(b"stub-pub:" + secret).digest()


def ed25519_sign(secret: bytes, msg: bytes) -> bytes:
    return hashlib.sha256(b"stub-sig:" + secret + msg).digest()


def registration_payload_hash(arr: dict) -> str:
    return hashlib.sha256(
        json.dumps({k: arr[k] for k in arr if k != "registration_signature"},
                   sort_keys=True, default=str).encode()).hexdigest()


def issuance_payload_hash(aeb: dict) -> str:
    return hashlib.sha256(
        json.dumps({k: aeb[k] for k in aeb if k != "issuance_signature"},
                   sort_keys=True, default=str).encode()).hexdigest()


# ---- minimal registry / store -------------------------------------------
class AgentLineageStore:
    """Inert audit sink. The real product keeps a durable audit chain; this stub
    just holds records in memory so construction succeeds."""

    def __init__(self, path: str):
        self.path = path
        self._records = []

    def append(self, record: dict) -> bool:
        self._records.append(record)
        return True


class BoundaryRegistry:
    def __init__(self):
        self._issuers = {}
        self._agents = {}      # agent_id -> arr
        self._aebs = {}        # agent_id -> aeb

    def register_issuer(self, issuer_id, public_key, role):
        self._issuers[issuer_id] = (public_key, role)

    def register_agent(self, arr: dict):
        self._agents[arr["agent_id"]] = arr

    def register_aeb(self, aeb: dict):
        self._aebs[aeb["agent_id"]] = aeb
        return {"registered": True}

    def get_arr(self, agent_id):
        return self._agents.get(agent_id)

    def get_aeb(self, agent_id):
        return self._aebs.get(agent_id)


# ---- the stub "BEE": a plain scope check, nothing more -------------------
class BEE:
    """NON-NORMATIVE. Replaces the licensed Evaluation Engine with a bare
    permitted-actions + permitted-resources check, so the seccomp mechanism
    has something to ask. Returns the same verdict/reason vocabulary the
    conformance suite asserts, and nothing else the real engine produces."""

    def __init__(self, registry: BoundaryRegistry, store: AgentLineageStore):
        self.registry = registry
        self.store = store

    def evaluate(self, request: dict) -> dict:
        agent_id = request.get("agent_id")
        action = request.get("action_type")
        resource = request.get("resource_target", "")

        arr = self.registry.get_arr(agent_id)
        if arr is None or arr.get("status") != "ACTIVE":
            return self._out("TERMINATED", "UNREGISTERED_AGENT")

        aeb = self.registry.get_aeb(agent_id)
        if aeb is None:
            return self._out("TERMINATED", "NO_ACTIVE_BOUNDARY")

        permitted_actions = aeb["action_scope"]["permitted_actions"]
        denied_actions = aeb["action_scope"].get("denied_actions", [])
        permitted_resources = aeb["resource_scope"]["permitted_resources"]

        # 1) action must be explicitly permitted (and not denied)
        if action in denied_actions or action not in permitted_actions:
            return self._out("CONTAINED", "ACTION_SCOPE_BREACH")

        # 2) resource must fall under a permitted prefix (PREFIX resolution)
        if not any(resource.startswith(p) for p in permitted_resources):
            return self._out("CONTAINED", "RESOURCE_SCOPE_BREACH")

        # 3) otherwise allow
        return self._out("PERMITTED", None)

    @staticmethod
    def _out(verdict, reason):
        return {"final_verdict": verdict,
                "reason_code": reason,
                "alr_id": str(uuid.uuid4())}   # placeholder id (stub only)
