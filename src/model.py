"""数据对象。字段与 spec/spec.md §2 一一对应。"""
from __future__ import annotations

from dataclasses import dataclass, field

from .crypto import h

CAP_UNIVERSE = [
    "order.read",
    "order.update",
    "food.prepare",
    "kitchen.execute",
    "kitchen.manage",
    "service.execute",
    "inventory.read",
    "inventory.update",
    "payment.read",
    "payment.refund",
    "db.read",
    "db.export",
    "db.admin",
    "credential.read",
    "credential.export",
    "shell.execute",
    "net.external",
    "agent.delegate",
]

# 能力敏感度排名：数值越大越敏感。仅用于漂移检测的 "拒绝后升级" 特征与日志展示，
# 不参与任何授权判定（授权只看集合包含关系）。
CAP_SENSITIVITY = {c: i for i, c in enumerate(CAP_UNIVERSE)}


@dataclass(frozen=True)
class Subject:
    subject_id: str
    role: str
    pubkey: str          # 十六进制
    key_epoch: int

    def to_dict(self) -> dict:
        return {"subject_id": self.subject_id, "role": self.role,
                "pubkey": self.pubkey, "key_epoch": self.key_epoch}


@dataclass(frozen=True)
class RootGrant:
    subject_id: str
    scope: tuple[str, ...]
    key_epoch: int
    cred_epoch: int
    issued_at: int
    not_after: int
    sig: str = ""

    def body(self) -> dict:
        return {"subject_id": self.subject_id, "scope": list(self.scope),
                "key_epoch": self.key_epoch, "cred_epoch": self.cred_epoch,
                "issued_at": self.issued_at, "not_after": self.not_after}

    def to_dict(self) -> dict:
        d = self.body()
        d["sig"] = self.sig
        return d

    @staticmethod
    def from_dict(d: dict) -> "RootGrant":
        return RootGrant(subject_id=d["subject_id"], scope=tuple(d["scope"]),
                         key_epoch=d["key_epoch"], cred_epoch=d["cred_epoch"],
                         issued_at=d["issued_at"], not_after=d["not_after"], sig=d["sig"])


@dataclass(frozen=True)
class Link:
    """一次衰减。由父令牌持有者的 PEP 私钥签名。"""
    parent_token_id: str
    token_id: str
    attenuator_id: str
    attenuator_key_epoch: int
    holder_id: str
    scope: tuple[str, ...]
    task_id: str
    parent_task_id: str
    not_after: int
    depth: int
    redelegatable: bool = True
    sig: str = ""

    def body(self) -> dict:
        return {"parent_token_id": self.parent_token_id, "token_id": self.token_id,
                "attenuator_id": self.attenuator_id,
                "attenuator_key_epoch": self.attenuator_key_epoch,
                "holder_id": self.holder_id, "scope": list(self.scope),
                "task_id": self.task_id, "parent_task_id": self.parent_task_id,
                "not_after": self.not_after, "depth": self.depth,
                "redelegatable": self.redelegatable}

    def to_dict(self) -> dict:
        d = self.body()
        d["sig"] = self.sig
        return d

    @staticmethod
    def from_dict(d: dict) -> "Link":
        return Link(parent_token_id=d["parent_token_id"], token_id=d["token_id"],
                    attenuator_id=d["attenuator_id"],
                    attenuator_key_epoch=d["attenuator_key_epoch"],
                    holder_id=d["holder_id"], scope=tuple(d["scope"]),
                    task_id=d["task_id"], parent_task_id=d["parent_task_id"],
                    not_after=d["not_after"], depth=d["depth"],
                    redelegatable=d.get("redelegatable", True), sig=d["sig"])


@dataclass(frozen=True)
class Token:
    """衰减式委托令牌。chain 为空表示这是主体自己的根令牌（等同其 RootGrant）。"""
    token_id: str
    root_subject_id: str
    holder_id: str
    scope: tuple[str, ...]
    task_id: str
    parent_task_id: str
    not_after: int
    depth: int
    redelegatable: bool = True
    chain: tuple[Link, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict:
        return {"token_id": self.token_id, "root_subject_id": self.root_subject_id,
                "holder_id": self.holder_id, "scope": list(self.scope),
                "task_id": self.task_id, "parent_task_id": self.parent_task_id,
                "not_after": self.not_after, "depth": self.depth,
                "redelegatable": self.redelegatable,
                "chain": [l.to_dict() for l in self.chain]}

    @staticmethod
    def from_dict(d: dict) -> "Token":
        return Token(token_id=d["token_id"], root_subject_id=d["root_subject_id"],
                     holder_id=d["holder_id"], scope=tuple(d["scope"]),
                     task_id=d["task_id"], parent_task_id=d["parent_task_id"],
                     not_after=d["not_after"], depth=d["depth"],
                     redelegatable=d.get("redelegatable", True),
                     chain=tuple(Link.from_dict(l) for l in d["chain"]))


# --- 可注入的能力宇宙 ---------------------------------------------------
# 玩具宇宙是本仓库声明的；真实基底来自 AgentDojo 工具集（见 experiments/substrate.py）。
# 用**就地修改**而非重新绑定，使得所有 `from .model import CAP_UNIVERSE` 的引用同步生效。
_TOY_UNIVERSE: tuple[str, ...] = tuple(CAP_UNIVERSE)


def set_cap_universe(names) -> None:
    CAP_UNIVERSE[:] = list(names)
    CAP_SENSITIVITY.clear()
    CAP_SENSITIVITY.update({c: i for i, c in enumerate(CAP_UNIVERSE)})


def reset_cap_universe() -> None:
    set_cap_universe(_TOY_UNIVERSE)


def current_universe() -> tuple[str, ...]:
    return tuple(CAP_UNIVERSE)


def is_toy_universe() -> bool:
    return tuple(CAP_UNIVERSE) == _TOY_UNIVERSE


def toy_universe() -> tuple[str, ...]:
    return _TOY_UNIVERSE


def root_token_id(grant: RootGrant) -> str:
    return h({"root_of": grant.subject_id, "scope": list(grant.scope),
              "key_epoch": grant.key_epoch, "cred_epoch": grant.cred_epoch,
              "not_after": grant.not_after})


def derive_token_id(parent_token_id: str, holder_id: str, scope, task_id: str,
                    not_after: int, depth: int, redelegatable: bool = True) -> str:
    return h({"parent": parent_token_id, "holder": holder_id,
              "scope": sorted(scope), "task": task_id,
              "not_after": not_after, "depth": depth,
              "redelegatable": redelegatable})


@dataclass(frozen=True)
class ActionRequest:
    """由发送方 PEP 签名：提供归因，不提供授权。"""
    request_id: str
    from_id: str
    to_id: str
    task_id: str
    token_id: str
    capability: str
    resource: str
    params_hash: str
    nonce: str
    ts: int
    text: str = ""       # 规划进程的自然语言负载。授权判定禁止读取此字段（见 spec §3.2）。
    # 复合动作的其余能力，每项形如 "cap@resource"。全部必须落在令牌范围内才执行（原子）。
    required: tuple[str, ...] = ()
    sig: str = ""

    def body(self) -> dict:
        return {"request_id": self.request_id, "from_id": self.from_id, "to_id": self.to_id,
                "task_id": self.task_id, "token_id": self.token_id,
                "capability": self.capability, "resource": self.resource,
                "params_hash": self.params_hash, "nonce": self.nonce, "ts": self.ts,
                "required": sorted(self.required)}

    def to_dict(self) -> dict:
        d = self.body()
        d["sig"] = self.sig
        return d

    @staticmethod
    def from_dict(d: dict) -> "ActionRequest":
        return ActionRequest(request_id=d["request_id"], from_id=d["from_id"],
                             to_id=d["to_id"], task_id=d["task_id"],
                             token_id=d["token_id"], capability=d["capability"],
                             resource=d["resource"], params_hash=d["params_hash"],
                             nonce=d["nonce"], ts=d["ts"], text=d.get("text", ""),
                             required=tuple(d.get("required", ())), sig=d["sig"])


@dataclass(frozen=True)
class Receipt:
    """由接收方 PEP 签名。进证据平面，不回传发送方。"""
    receipt_id: str
    from_id: str
    to_id: str
    request_id: str
    token_id: str
    task_id: str
    capability: str
    resource: str
    decision: str          # ALLOW | DENY
    reason_code: str
    ts: int
    drift_score: float = 0.0   # 由证据平面回填，不参与签名
    sig: str = ""

    def body(self) -> dict:
        return {"receipt_id": self.receipt_id, "from_id": self.from_id, "to_id": self.to_id,
                "request_id": self.request_id, "token_id": self.token_id,
                "task_id": self.task_id, "capability": self.capability,
                "resource": self.resource, "decision": self.decision,
                "reason_code": self.reason_code, "ts": self.ts}

    def to_dict(self) -> dict:
        d = self.body()
        d["drift_score"] = self.drift_score
        d["sig"] = self.sig
        return d

    @staticmethod
    def from_dict(d: dict) -> "Receipt":
        return Receipt(receipt_id=d["receipt_id"], from_id=d["from_id"], to_id=d["to_id"],
                       request_id=d["request_id"], token_id=d["token_id"],
                       task_id=d["task_id"], capability=d["capability"],
                       resource=d["resource"], decision=d["decision"],
                       reason_code=d["reason_code"], ts=d["ts"],
                       drift_score=d.get("drift_score", 0.0), sig=d["sig"])


@dataclass(frozen=True)
class RevocationEpoch:
    epoch: int
    revoked_token_ids: tuple[str, ...]
    revoked_subject_ids: tuple[str, ...]
    revoked_key_epochs: dict          # subject_id -> 该值及以下 key_epoch 全部作废
    log_head_hash: str
    issued_at: int
    sig: str = ""

    def body(self) -> dict:
        return {"epoch": self.epoch,
                "revoked_token_ids": sorted(self.revoked_token_ids),
                "revoked_subject_ids": sorted(self.revoked_subject_ids),
                "revoked_key_epochs": dict(sorted(self.revoked_key_epochs.items())),
                "log_head_hash": self.log_head_hash, "issued_at": self.issued_at}

    def to_dict(self) -> dict:
        d = self.body()
        d["sig"] = self.sig
        return d

    @staticmethod
    def from_dict(d: dict) -> "RevocationEpoch":
        return RevocationEpoch(epoch=d["epoch"],
                               revoked_token_ids=tuple(d["revoked_token_ids"]),
                               revoked_subject_ids=tuple(d["revoked_subject_ids"]),
                               revoked_key_epochs=dict(d["revoked_key_epochs"]),
                               log_head_hash=d["log_head_hash"],
                               issued_at=d["issued_at"], sig=d["sig"])


class Deny(Exception):
    def __init__(self, reason_code: str, detail: str = ""):
        super().__init__(f"{reason_code}: {detail}")
        self.reason_code = reason_code
        self.detail = detail
