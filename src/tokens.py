"""权威与令牌代数：衰减派生、离线验证。对应 spec §2.2–§2.3、§2.6。"""
from __future__ import annotations

from .crypto import h, new_keypair, pub_of, sign, verify
from .patterns import scope_subset
from .model import (
    CAP_UNIVERSE,
    Deny,
    Link,
    RevocationEpoch,
    RootGrant,
    Subject,
    Token,
    derive_token_id,
    root_token_id,
)


class Authority:
    """TCB。只负责建立身份、签发根授权、发布撤销 epoch。不参与每次运行时判定。"""

    def __init__(self, ttl: int = 100, start_epoch: int = 0):
        self.sk, self.pk_raw = new_keypair()
        self.pk = self.pk_raw.hex()
        self.ttl = ttl
        self.registry: dict[str, Subject] = {}
        self.grants: dict[str, RootGrant] = {}          # 当前授权
        self.grant_history: dict[str, dict[int, RootGrant]] = {}   # cred_epoch → 授权
        self.cred_epoch: dict[str, int] = {}
        self.epoch = start_epoch
        self.revoked_token_ids: set[str] = set()
        self.revoked_subject_ids: set[str] = set()
        self.revoked_key_epochs: dict[str, int] = {}
        self._log: list[str] = []
        self._head = h({"genesis": self.pk})
        # epoch 0：空撤销集，作为所有 PEP 的初始已知状态
        e0 = RevocationEpoch(epoch=0, revoked_token_ids=(), revoked_subject_ids=(),
                             revoked_key_epochs={}, log_head_hash=self._head, issued_at=0)
        self._current = RevocationEpoch(**{**e0.__dict__, "sig": sign(self.sk, e0.body())})
        # 攻击模式：为 split-view 实验提供"对不同主体发布不同日志头"的能力
        self._equivocating_head: str | None = None
        self._fork_group: set[str] = set()

    # --- 身份 ---
    def register(self, subject_id: str, role: str, key_epoch: int = 1,
                 with_key: bool = True):
        """返回 (Subject, 私钥原始字节)。私钥交给该主体的 PEP，规划进程不持有。"""
        if with_key:
            sk, pk_raw = new_keypair()
            pubkey = pk_raw.hex()
        else:
            sk, pubkey = None, ""
        s = Subject(subject_id=subject_id, role=role, pubkey=pubkey, key_epoch=key_epoch)
        self.registry[subject_id] = s
        return s, sk

    def issue_grant(self, subject_id: str, scope, now: int, ttl: int | None = None) -> RootGrant:
        ttl = self.ttl if ttl is None else ttl
        ce = self.cred_epoch.get(subject_id, 0) + 1
        self.cred_epoch[subject_id] = ce
        s = self.registry[subject_id]
        g = RootGrant(subject_id=subject_id, scope=tuple(sorted(scope)),
                      key_epoch=s.key_epoch, cred_epoch=ce,
                      issued_at=now, not_after=now + ttl)
        g = RootGrant(**{**g.__dict__, "sig": sign(self.sk, g.body())})
        self.grants[subject_id] = g
        self.grant_history.setdefault(subject_id, {})[ce] = g
        return g

    def grant_for_root_id(self, subject_id: str, root_token_id_: str):
        """按**链根标识**解析出该令牌链实际根植的那份授权。

        必要性：`RootGrant` 每次签发都会使 `cred_epoch` 递增，而链根的 `token_id`
        含 `cred_epoch`。若总是拿**当前**授权去验，一次常规重签发就会让全部在途令牌
        （以及用旧根新派生的令牌）报"链断裂"——参考实现曾如此，由差分测试发现。
        """
        for g in self.grant_history.get(subject_id, {}).values():
            if globals()["root_token_id"](g) == root_token_id_:
                return g
        return None

    # --- 验证（任何人可用权威公钥离线执行）---
    def verify_grant(self, grant: RootGrant) -> bool:
        return verify(self.pk, grant.body(), grant.sig)

    # --- 撤销 ---
    def _bump(self, now: int) -> RevocationEpoch:
        self.epoch += 1
        rec = {"epoch": self.epoch,
               "tokens": sorted(self.revoked_token_ids),
               "subjects": sorted(self.revoked_subject_ids),
               "keys": dict(sorted(self.revoked_key_epochs.items()))}
        self._log.append(h(rec))
        self._head = h({"prev": self._head, "record": h(rec)})
        e = RevocationEpoch(epoch=self.epoch,
                            revoked_token_ids=tuple(sorted(self.revoked_token_ids)),
                            revoked_subject_ids=tuple(sorted(self.revoked_subject_ids)),
                            revoked_key_epochs=dict(self.revoked_key_epochs),
                            log_head_hash=self._head, issued_at=now)
        self._current = RevocationEpoch(**{**e.__dict__, "sig": sign(self.sk, e.body())})
        return self._current

    def current(self) -> RevocationEpoch:
        """当前撤销状态。PEP 周期性拉取（模型化 pull_interval）。"""
        return self._current

    def revoke_token(self, token_id: str, now: int) -> RevocationEpoch:
        self.revoked_token_ids.add(token_id)
        return self._bump(now)

    def revoke_subject(self, subject_id: str, now: int) -> RevocationEpoch:
        self.revoked_subject_ids.add(subject_id)
        return self._bump(now)

    def revoke_key_epochs(self, subject_id: str, upto: int, now: int) -> RevocationEpoch:
        """作废该主体 key_epoch <= upto 的所有密钥（密钥泄露场景，由权威单方触发）。"""
        self.revoked_key_epochs[subject_id] = max(
            upto, self.revoked_key_epochs.get(subject_id, 0))
        return self._bump(now)

    def verify_epoch(self, e: RevocationEpoch) -> bool:
        return verify(self.pk, e.body(), e.sig)

    # --- split-view（攻击模拟）---
    def enable_equivocation(self, fork_group) -> None:
        """模拟等价分歧的权威：对 fork_group 内的主体发布不同的日志头。"""
        self._equivocating_head = h({"fork": self._head})
        self._fork_group = set(fork_group)

    @property
    def view_a_head(self) -> str:
        return self._head

    @property
    def view_b_head(self) -> str:
        return self._equivocating_head if self._equivocating_head else self._head

    def current_for(self, subject_id: str):
        """按主体返回撤销状态。诚实权威返回同一对象；分叉权威返回不同日志头。"""
        if self._equivocating_head and subject_id in getattr(self, "_fork_group", ()):
            e = self._current
            e2 = RevocationEpoch(**{**e.__dict__, "log_head_hash": self._equivocating_head})
            return RevocationEpoch(**{**e2.__dict__, "sig": sign(self.sk, e2.body())})
        return self._current


def detect_split_view(views: list[tuple[str, int, str]]) -> list[str]:
    """views: [(subject_id, epoch, head_hash)]。返回检出等价分歧的主体对描述。"""
    by_epoch: dict[int, dict[str, str]] = {}
    for sid, epoch, head in views:
        by_epoch.setdefault(epoch, {})[sid] = head
    findings = []
    for epoch, heads in sorted(by_epoch.items()):
        distinct = set(heads.values())
        if len(distinct) > 1:
            findings.append(
                f"EQUIVOCATION epoch={epoch} heads={ {k: v[:8] for k, v in heads.items()} }")
    return findings


# --- 令牌代数 -------------------------------------------------------------

def token_issuer(token: Token) -> str:
    """令牌的签发者：链上最后一级衰减者；无链则为根主体。

    语义：持有者 holder 只能被 issuer 以本令牌范围内的能力驱使。
    因此接收方要求 req.from_id == token_issuer(token)。
    """
    return token.chain[-1].attenuator_id if token.chain else token.root_subject_id


def root_token(grant: RootGrant) -> Token:    return Token(token_id=root_token_id(grant), root_subject_id=grant.subject_id,
                 holder_id=grant.subject_id, scope=grant.scope, task_id="<root>",
                 parent_task_id="", not_after=grant.not_after, depth=0, chain=())


def attenuate(parent: Token, holder_id: str, scope, task_id: str, not_after: int,
              attenuator: Subject, attenuator_sk: bytes, now: int,
              unconstrained: bool = False, redelegatable: bool = True) -> Token:
    """派生一个受约束的子令牌。全部本地完成，不调用权威。

    unconstrained=True 仅用于 B0 基线：模拟"根本不存在能力约束"的系统。
    """
    if parent.holder_id != attenuator.subject_id:
        raise Deny("TOKEN_INVALID", "派生者不是父令牌持有者")
    # 检查顺序按 spec §2.3 派生规则 1–5 的**列举顺序**：
    # 持有者 → 范围 ⊆ → 有效期 → 深度 → 转委托封条。
    # 早期实现把封条提到范围检查之前，于是"父令牌已封条且子范围越界"时报
    # NOT_REDELEGATABLE，与规格列举顺序推出的 SCOPE_VIOLATION 不符
    # （第二轮差分测试判定为规格歧义，已按列举顺序钉死）。
    if unconstrained:
        scope = list(CAP_UNIVERSE)
    if not unconstrained and not scope_subset(scope, parent.scope):
        raise Deny("SCOPE_VIOLATION",
                   f"派生范围超出父令牌: {sorted(set(scope) - set(parent.scope))}")
    if not set(scope):
        raise Deny("SCOPE_VIOLATION", "空范围无意义")
    if not_after > parent.not_after:
        raise Deny("TOKEN_INVALID", "子令牌有效期超过父令牌")
    if now > parent.not_after:
        raise Deny("TOKEN_EXPIRED", "父令牌已过期")
    if not parent.redelegatable:
        raise Deny("NOT_REDELEGATABLE", "父令牌不可转委托")
    depth = parent.depth + 1
    tid = derive_token_id(parent.token_id, holder_id, scope, task_id, not_after, depth,
                          redelegatable)
    link = Link(parent_token_id=parent.token_id, token_id=tid,
                attenuator_id=attenuator.subject_id,
                attenuator_key_epoch=attenuator.key_epoch,
                holder_id=holder_id, scope=tuple(sorted(scope)), task_id=task_id,
                parent_task_id=parent.task_id, not_after=not_after, depth=depth,
                redelegatable=redelegatable)
    link = Link(**{**link.__dict__, "sig": sign(attenuator_sk, link.body())})
    return Token(token_id=tid, root_subject_id=parent.root_subject_id, holder_id=holder_id,
                 scope=tuple(sorted(scope)), task_id=task_id,
                 parent_task_id=parent.task_id, not_after=not_after, depth=depth,
                 redelegatable=redelegatable, chain=parent.chain + (link,))


def verify_token(token: Token, grant: RootGrant, authority_pub: str,
                 registry: dict[str, Subject], revoked: RevocationEpoch,
                 now: int, clock_skew: int = 0) -> None:
    """离线验证。失败抛 Deny。不访问网络、不调用权威、不做 LLM 推理。"""
    if not verify(authority_pub, grant.body(), grant.sig):
        raise Deny("TOKEN_INVALID", "根授权签名无效")
    if grant.subject_id != token.root_subject_id:
        raise Deny("TOKEN_INVALID", "根授权主体不匹配")
    if token.token_id in revoked.revoked_token_ids:
        raise Deny("TOKEN_REVOKED", "令牌已被撤销")
    if token.holder_id in revoked.revoked_subject_ids:
        raise Deny("TOKEN_REVOKED", "持有主体已被撤销")

    # 优先级（spec §2.3 钉死）：撤销 → **过期** → 密钥作废。
    # 过期必须先于密钥作废判定：早期实现把密钥检查放在前面，报 TOKEN_REVOKED，
    # 与规格文字（把密钥作废单列为第三级）不符——由第二轮差分测试判定为我方 bug。
    if now > token.not_after + clock_skew:
        raise Deny("TOKEN_EXPIRED", f"now={now} > not_after={token.not_after}")

    def key_ok(subject_id: str, key_epoch: int) -> bool:
        return key_epoch > revoked.revoked_key_epochs.get(subject_id, 0)

    if not key_ok(token.root_subject_id, grant.key_epoch):
        raise Deny("TOKEN_REVOKED", "根密钥 epoch 已作废")

    if not token.chain:
        if token.token_id != root_token_id(grant):
            raise Deny("TOKEN_INVALID", "根令牌与其授权不匹配")
        if token.scope != grant.scope or token.holder_id != grant.subject_id:
            raise Deny("TOKEN_INVALID", "根令牌字段被篡改")
        if token.depth != 0:
            raise Deny("TOKEN_INVALID", "depth 与链不一致")
        if token.not_after != grant.not_after:
            raise Deny("TOKEN_INVALID", "有效期被篡改")
    else:
        prev_id = root_token_id(grant)
        prev_scope = tuple(grant.scope)
        prev_na = grant.not_after
        prev_depth = 0
        prev_task = "<root>"
        for link in token.chain:
            if link.parent_token_id != prev_id:
                raise Deny("TOKEN_INVALID", "链断裂")
            if link.depth != prev_depth + 1:
                raise Deny("TOKEN_INVALID", "depth 不连续")
            if not key_ok(link.attenuator_id, link.attenuator_key_epoch):
                raise Deny("TOKEN_REVOKED", f"派生者 {link.attenuator_id} 密钥 epoch 已作废")
            att = registry.get(link.attenuator_id)
            if att is None or att.pubkey == "":
                raise Deny("TOKEN_INVALID", "派生者不在注册表")
            if not verify(att.pubkey, link.body(), link.sig):
                raise Deny("TOKEN_INVALID", f"派生链接签名无效 ({link.attenuator_id})")
            if not scope_subset(link.scope, prev_scope):
                raise Deny("SCOPE_VIOLATION",
                           f"范围非单调收缩: {sorted(set(link.scope) - set(prev_scope))}")
            if link.not_after > prev_na:
                raise Deny("TOKEN_INVALID", "有效期非单调不增")
            exp = derive_token_id(link.parent_token_id, link.holder_id, link.scope,
                                  link.task_id, link.not_after, link.depth,
                                  link.redelegatable)
            if exp != link.token_id:
                raise Deny("TOKEN_INVALID", "链接 token_id 与内容不符")
            prev_id, prev_scope, prev_na, prev_depth = (
                link.token_id, tuple(link.scope), link.not_after, link.depth)
            prev_task = link.task_id
            prev_redelegatable = link.redelegatable
        if token.redelegatable != prev_redelegatable:
            raise Deny("TOKEN_INVALID", "转委托标志与链不一致")
        if token.token_id != prev_id:
            raise Deny("TOKEN_INVALID", "末链与令牌 id 不符")
        if tuple(token.scope) != prev_scope or token.not_after != prev_na:
            raise Deny("TOKEN_INVALID", "令牌字段与链不一致")
        if token.depth != prev_depth:
            raise Deny("TOKEN_INVALID", "depth 与链不一致")
        if token.task_id != prev_task:
            raise Deny("TOKEN_INVALID", "task 与链不一致")

    # （过期检查已按钉死的优先级前移，见下）
