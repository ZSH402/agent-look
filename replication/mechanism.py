"""R1：规格 §2.2–§2.5、§3.1–§3.2、§7 的最小机制实现。

只依赖 spec/spec.md 的文字。未规定处的取舍见 REPORT.md「规格不足之处」。
"""
from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

import patterns as P

# §3.2「时效窗口是双向的（差分测试后钉死）」：默认 50 tick，且未来时间戳同样拒绝。
MAX_REQUEST_AGE = 50.0


# ---------------------------------------------------------------- 密码学原语
def gen_keypair():
    sk = Ed25519PrivateKey.generate()
    return sk, sk.public_key()


def sign(sk: Ed25519PrivateKey, payload: bytes) -> bytes:
    return sk.sign(payload)


def verify_sig(pk: Ed25519PublicKey, payload: bytes, sig: bytes) -> bool:
    try:
        pk.verify(sig, payload)
        return True
    except InvalidSignature:
        return False


def _canon(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str).encode()


def _sha(obj) -> str:
    return hashlib.sha256(_canon(obj)).hexdigest()


# ---------------------------------------------------------------- §2.2 / §2.3
@dataclass
class RootGrant:
    subject_id: str
    scope: frozenset[str]
    key_epoch: int
    cred_epoch: int
    issued_at: float
    not_after: float
    sig_A: bytes = b""

    def body(self) -> dict:
        return {
            "subject_id": self.subject_id,
            "scope": sorted(self.scope),
            "key_epoch": self.key_epoch,
            "cred_epoch": self.cred_epoch,
            "issued_at": self.issued_at,
            "not_after": self.not_after,
        }


@dataclass
class Link:
    parent_token_id: str
    attenuator_id: str
    attenuator_key_epoch: int
    new_scope: frozenset[str]
    sig_attenuator: bytes = b""

    def body(self) -> dict:
        return {
            "parent_token_id": self.parent_token_id,
            "attenuator_id": self.attenuator_id,
            "attenuator_key_epoch": self.attenuator_key_epoch,
            "new_scope": sorted(self.new_scope),
        }

    def scope_hash(self) -> str:
        return _sha({"new_scope": sorted(self.new_scope)})


@dataclass
class Token:
    token_id: str
    root_subject_id: str
    holder_id: str
    scope: frozenset[str]
    task_id: str
    parent_task_id: str | None
    issued_at: float
    not_after: float
    depth: int
    redelegatable: bool = True
    # §5「凭证刷新语义」：验证方按令牌**链根**解析授权。本字段即链根的解析键
    # （= H(根授权的 body)），由根令牌设定、逐级继承。
    # 规格未命名该键，见 REPORT-r2.md「规格仍不够清楚的地方」。
    root_grant_id: str = ""
    chain: tuple[Link, ...] = ()

    def body(self) -> dict:
        return {
            "root_subject_id": self.root_subject_id,
            "holder_id": self.holder_id,
            "scope": sorted(self.scope),
            "task_id": self.task_id,
            "parent_task_id": self.parent_task_id,
            "issued_at": self.issued_at,
            "not_after": self.not_after,
            "depth": self.depth,
            "redelegatable": self.redelegatable,
            "root_grant_id": self.root_grant_id,
            "chain": [l.body() for l in self.chain],
        }

    def recompute_id(self) -> str:
        return _sha(self.body())


@dataclass
class ActionRequest:
    request_id: str
    from_id: str
    to_id: str
    task_id: str
    token_id: str
    capability: str
    resource: str
    params_hash: str = ""
    nonce: str = ""
    ts: float = 0.0
    required: tuple[str, ...] = ()          # §2.12：其余能力的 "cap@resource" 序列
    sig_from_pep: bytes = b""

    def body(self) -> dict:
        return {
            "request_id": self.request_id,
            "from_id": self.from_id,
            "to_id": self.to_id,
            "task_id": self.task_id,
            "token_id": self.token_id,
            "capability": self.capability,
            "resource": self.resource,
            "params_hash": self.params_hash,
            "nonce": self.nonce,
            "ts": self.ts,
            "required": list(self.required),
        }


@dataclass
class Receipt:
    receipt_id: str
    from_id: str
    to_id: str
    request_id: str
    token_id: str
    task_id: str
    capability: str
    resource: str
    decision: str
    reason_code: str
    ts: float
    sig_to_pep: bytes = b""

    def body(self) -> dict:
        return {
            "receipt_id": self.receipt_id,
            "from_id": self.from_id,
            "to_id": self.to_id,
            "request_id": self.request_id,
            "token_id": self.token_id,
            "task_id": self.task_id,
            "capability": self.capability,
            "resource": self.resource,
            "decision": self.decision,
            "reason_code": self.reason_code,
            "ts": self.ts,
        }


def token_issuer(t: Token) -> str:
    """§2.3.1：链上最后一级衰减者；无链时等于 root_subject_id。"""
    return t.chain[-1].attenuator_id if t.chain else t.root_subject_id


def grant_key(grant: RootGrant) -> str:
    """§5：令牌**链根**的解析键 = H(根授权 body)。权威凭此保留授权历史。"""
    return _sha(grant.body())


# ---------------------------------------------------------------- §7 TCB 组件
class WorldModel:
    """副作用只在 §3.2 第 8 步产生。"""

    def __init__(self):
        self.effects: list[dict] = []

    def apply(self, req: ActionRequest) -> None:
        self.effects.append(
            {
                "request_id": req.request_id,
                "from_id": req.from_id,
                "to_id": req.to_id,
                "capability": req.capability,
                "resource": req.resource,
            }
        )


class EvidencePlane:
    """只读收据流（权威副本）。"""

    def __init__(self):
        self.receipts: list[Receipt] = []

    def append(self, r: Receipt) -> None:
        self.receipts.append(r)


class Authority:
    """A：持 K_A。权威签发。

    §5 前置假设「权威保留授权历史」：`grant_history` 按链根键保留历次签发的根授权，
    验证方据此按链根解析——**不总是使用当前授权**。
    """

    def __init__(self):
        self.sk, self.pk = gen_keypair()
        self.grant_history: dict[str, RootGrant] = {}
        self.latest: dict[str, RootGrant] = {}

    def issue_root_grant(self, subject_id, scope, key_epoch=1, cred_epoch=1, now=0.0, ttl=1e9):
        g = RootGrant(
            subject_id=subject_id,
            scope=frozenset(scope),
            key_epoch=key_epoch,
            cred_epoch=cred_epoch,
            issued_at=now,
            not_after=now + ttl,
        )
        g.sig_A = sign(self.sk, _canon(g.body()))
        self.register(g)
        return g

    def register(self, grant: RootGrant) -> str:
        rid = grant_key(grant)
        self.grant_history[rid] = grant
        cur = self.latest.get(grant.subject_id)
        if cur is None or grant.cred_epoch >= cur.cred_epoch:
            self.latest[grant.subject_id] = grant
        return rid

    def issue_grant(self, subject_id, scope, now=0.0, ttl=1e9) -> RootGrant:
        """§2.2：`cred_epoch` 单调递增。参考实现的 `issue_grant` 每次调用 +1。"""
        cur = self.latest.get(subject_id)
        ce = 1 if cur is None else cur.cred_epoch + 1
        return self.issue_root_grant(subject_id, scope, cred_epoch=ce, now=now, ttl=ttl)

    def grant_for_root_id(self, rid: str) -> RootGrant | None:
        return self.grant_history.get(rid)


class RevocationState:
    def __init__(self):
        self.revoked_tokens: set[str] = set()
        self.revoked_key_epoch_upper: int = 0


class PEP:
    """主体 s 的可信执行点。持 K_s、令牌库、凭证缓存。"""

    def __init__(self, subject_id, world: WorldModel, evidence: EvidencePlane, authority):
        self.subject_id = subject_id
        self.sk, self.pk = gen_keypair()
        self.world = world
        self.evidence = evidence
        self.authority = authority
        self.auth_pk = authority.pk
        self.store: dict[str, Token] = {}
        self.root_token: Token | None = None
        self.max_seen_cred: dict[str, int] = {}
        self.seen_nonces: set[tuple[str, str]] = set()
        self.revoked_tokens: set[str] = set()
        # §3.3 撤销粒度含"主体"：被撤销的主体不得再接收获新的委托令牌
        self.revoked_subjects: set[str] = set()
        # §2.3 规则 6：按主体记录 key_epoch 作废上限（等于即为已作废）
        self.revoked_key_epochs: dict[str, int] = {}
        self.partitioned = False
        self.peers: dict[str, object] = {}

    # -------------------------------------------------- §5 凭证刷新语义
    def install_grant(self, grant: RootGrant, now: float) -> bool:
        """装入一份根授权。§5 / P2：
        - 回滚防护以**验证方已见**的最高 epoch 为准（I4 单调不减）：
          更旧的授权**拒绝装入**（返回 False），不回退、不重建根令牌；
        - 若该授权是本级自己的，**同时更新本级持有的根令牌**，否则新旧混用会派生失败。
        """
        prev = self.max_seen_cred.get(grant.subject_id, 0)
        if grant.cred_epoch < prev:
            return False
        self.max_seen_cred[grant.subject_id] = grant.cred_epoch
        rid = self.authority.register(grant)
        if grant.subject_id == self.subject_id:
            self._rebuild_root_token(grant, rid)
        return True

    def _rebuild_root_token(self, grant: RootGrant, rid: str) -> None:
        old = self.root_token
        rt = Token(
            token_id="",
            root_subject_id=grant.subject_id,
            holder_id=self.subject_id,
            scope=frozenset(grant.scope),
            task_id="root",
            parent_task_id=None,
            issued_at=grant.issued_at,
            not_after=grant.not_after,
            depth=0,
            redelegatable=True,
            root_grant_id=rid,
        )
        rt.token_id = rt.recompute_id()
        if old is not None:
            self.store.pop(old.token_id, None)
        self.root_token = rt
        self.store[rt.token_id] = rt

    def resolve_grant(self, t: Token) -> RootGrant | None:
        """§5：按令牌**链根**解析，不总是使用当前授权。"""
        return self.authority.grant_for_root_id(t.root_grant_id)

    # ------------------------------------------------------------ §3.1 委托
    def receive_token(self, t: Token, now: float) -> tuple[bool, str]:
        g = self.resolve_grant(t)
        if g is None:
            return False, "TOKEN_INVALID"
        # §3.2 步骤 4 的回滚防护同样适用于接收派生令牌：
        # 已刷新到新 epoch 的一方拒绝接受锚在旧根上的令牌（新旧混用会派生失败）。
        if g.cred_epoch < self.max_seen_cred.get(g.subject_id, 0):
            return False, "STALE_CREDENTIAL"
        ok, why = self.verify_token(t, now)
        if not ok:
            return False, why
        self.store[t.token_id] = t
        prev = self.max_seen_cred.get(g.subject_id, 0)
        if g.cred_epoch > prev:
            self.max_seen_cred[g.subject_id] = g.cred_epoch
        return True, "OK"

    # ------------------------------------------------------ §2.3 verify（离线）
    def verify_token(self, t: Token, now: float) -> tuple[bool, str]:
        # 0. 按链根解析该链实际根植的那份授权
        grant = self.resolve_grant(t)
        if grant is None:
            return False, "TOKEN_INVALID"
        # 1. 根授权签名与主体绑定
        if not verify_sig(self.auth_pk, _canon(grant.body()), grant.sig_A):
            return False, "TOKEN_INVALID"
        if grant.subject_id != t.root_subject_id:
            return False, "TOKEN_INVALID"
        # 2. 逐级验签 + 范围非增 + not_after 非增
        prev_scope = grant.scope
        for link in t.chain:
            # spec §2.3 verify-3 要求 "Link.parent_token_id 与链上前一项一致"。
            # 迭代式衰减下，第 i 项的 parent_token_id 是"前 i 级构成的中间令牌"的 id，
            # 而该中间令牌的头部字段（holder/task_id/issued_at）不在链上，
            # 验证方无法离线重算 ⇒ 该条退化为止于整链 token_id 哈希绑定（见 REPORT）。
            if not verify_sig(
                self.peers[link.attenuator_id].pk,
                _canon(link.body()),
                link.sig_attenuator,
            ):
                return False, "TOKEN_INVALID"
            if not P.scope_subset(set(link.new_scope), set(prev_scope)):
                return False, "TOKEN_INVALID"
            prev_scope = link.new_scope
        # 3. token_id 派生自链内容哈希（含 redelegatable / root_grant_id）
        if t.recompute_id() != t.token_id:
            return False, "TOKEN_INVALID"
        # §2.3「检查顺序（差分测试后钉死）」：规则 4–6 的触发优先级为
        # 撤销 → 过期 → 密钥作废。同时撤销且过期时报 TOKEN_REVOKED。
        # 4'/5. 撤销（令牌撤销 / 持有者主体撤销）
        if t.token_id in self.revoked_tokens:
            return False, "TOKEN_REVOKED"
        if self.subject_id in self.revoked_subjects:
            return False, "TOKEN_REVOKED"
        # 4. 过期
        if now > t.not_after:
            return False, "TOKEN_EXPIRED"
        # 6. 密钥作废：所有**涉及的** key_epoch 必须严格大于该主体的作废上限
        pairs = [(t.root_subject_id, grant.key_epoch)] + [
            (l.attenuator_id, l.attenuator_key_epoch) for l in t.chain
        ]
        if any(e <= self.revoked_key_epochs.get(sid, 0) for sid, e in pairs):
            return False, "TOKEN_REVOKED"
        # 7. 末链 redelegatable 与 token 字段一致由构造保证（Link 不含该字段，见 REPORT）
        return True, "OK"

    # ------------------------------------------------------------ §3.2 判定
    def handle(self, req: ActionRequest, now: float) -> Receipt:
        code = self._decide(req, now)
        if code == "OK":
            self.world.apply(req)
        rec = Receipt(
            receipt_id=_sha({"req": req.request_id, "to": self.subject_id, "ts": now}),
            from_id=req.from_id,
            to_id=req.to_id,
            request_id=req.request_id,
            token_id=req.token_id,
            task_id=req.task_id,
            capability=req.capability,
            resource=req.resource,
            decision="ALLOW" if code == "OK" else "DENY",
            reason_code="OK" if code == "OK" else code,
            ts=now,
        )
        rec.sig_to_pep = sign(self.sk, _canon(rec.body()))
        self.evidence.append(rec)
        return rec

    def _decide(self, req: ActionRequest, now: float) -> str:
        # 1. 归因
        sender = self.peers.get(req.from_id)
        if sender is None or not verify_sig(
            sender.pk, _canon(req.body()), req.sig_from_pep
        ):
            return "REQUEST_UNSIGNED"
        # 1b. 重放
        key = (req.from_id, req.nonce)
        if key in self.seen_nonces:
            return "REPLAY"
        self.seen_nonces.add(key)
        # 1c. 时窗：§3.2「时效窗口是双向的」 0 ≤ now - req.ts ≤ max_request_age
        age = now - req.ts
        if age < 0 or age > MAX_REQUEST_AGE:
            return "REPLAY"
        # 2. 令牌查找
        t = self.store.get(req.token_id)
        if t is None:
            return "TOKEN_INVALID"
        # 3. 签发者绑定
        if token_issuer(t) != req.from_id:
            return "TOKEN_INVALID"
        # 4. 回滚防护 —— 按**链根**解析出的那份授权比较，而非"当前授权"
        grant = self.resolve_grant(t)
        if grant is None:
            return "TOKEN_INVALID"
        if grant.cred_epoch < self.max_seen_cred.get(grant.subject_id, 0):
            return "STALE_CREDENTIAL"
        # 5. 离线验证
        ok, why = self.verify_token(t, now)
        if not ok:
            return why
        # 6. 任务绑定
        if t.task_id != req.task_id:
            return "TASK_MISMATCH"
        # 7. 范围检查
        if not P.scope_allows(set(t.scope), req.capability, req.resource):
            return "SCOPE_VIOLATION"
        # 7b. 复合动作（§2.12）：{capability@resource} ∪ required 必须**全部**在范围内
        for item in req.required:
            rcap, _, rres = item.partition("@")
            if not P.scope_allows(set(t.scope), rcap, rres):
                return "SCOPE_VIOLATION"
        # 8. 副作用由 handle 执行
        return "OK"


# ---------------------------------------------------------------- §2.3 衰减
class DerivationRejected(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


def attenuate(
    parent: Token,
    holder_id: str,
    child_scope: set[str],
    task_id: str,
    ttl: float,
    attenuator,
    now: float,
    root_grant: RootGrant,
    new_token_id: str | None = None,
) -> Token:
    """派生规则 §2.3。attenuator 为持有父令牌的派生者（持其私钥）。"""
    if parent.holder_id != attenuator.subject_id:
        raise DerivationRejected("TOKEN_INVALID")
    if not P.scope_subset(child_scope, set(parent.scope)):
        raise DerivationRejected("SCOPE_VIOLATION")
    not_after = min(now + ttl, parent.not_after)
    if not_after > parent.not_after:
        raise DerivationRejected("TOKEN_EXPIRED")
    if not parent.redelegatable:
        raise DerivationRejected("NOT_REDELEGATABLE")
    link = Link(
        parent_token_id=parent.token_id,
        attenuator_id=attenuator.subject_id,
        attenuator_key_epoch=parent.chain[-1].attenuator_key_epoch
        if parent.chain
        else root_grant.key_epoch,
        new_scope=frozenset(child_scope),
    )
    link.sig_attenuator = sign(attenuator.sk, _canon(link.body()))
    child = Token(
        token_id="",
        root_subject_id=parent.root_subject_id,
        holder_id=holder_id,
        scope=frozenset(child_scope),
        task_id=task_id,
        parent_task_id=parent.task_id,
        issued_at=now,
        not_after=not_after,
        depth=parent.depth + 1,
        redelegatable=parent.redelegatable,
        root_grant_id=parent.root_grant_id,
        chain=parent.chain + (link,),
    )
    child.token_id = _sha(child.body())
    return child
