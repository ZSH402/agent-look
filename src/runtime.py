"""运行时：世界模型、证据平面、漂移检测、PEP、规划进程、系统装配、基线 B0/B1/B2。"""
from __future__ import annotations

import math
import re
import time
from collections import Counter, defaultdict
from dataclasses import replace

from .crypto import STATS, h, sign, verify
from .model import (
    CAP_SENSITIVITY,
    CAP_UNIVERSE,
    ActionRequest,
    Deny,
    Receipt,
)
from .patterns import scope_allows
from .tokens import (Authority, attenuate, root_token, root_token_id,
                     token_issuer, verify_token)

# 补充的 reason_code（spec §2.5 的基础集之外，实现需要）
R_UNSIGNED = "REQUEST_UNSIGNED"
R_REPLAY = "REPLAY"
R_STALE = "STALE_CREDENTIAL"
R_PDP_DOWN = "PDP_UNAVAILABLE"
R_GUARD = "GUARD_BLOCK"
R_RECEIPT = "RECEIPT_INVALID"
R_FAILFAST = "LOCAL_FAILFAST"


# ---------------------------------------------------------------- 世界模型
class World:
    """副作用只经 PEP 的执行步骤产生。"""

    def __init__(self):
        self.effects: list[dict] = []

    def execute(self, capability: str, resource: str, actor: str,
                params_hash: str, ts: int) -> dict:
        e = {"capability": capability, "resource": resource, "actor": actor,
             "params_hash": params_hash, "ts": ts}
        self.effects.append(e)
        return e


# ------------------------------------------------------------ 漂移检测（代理）
class DriftDetector:
    """确定性统计代理，用于替代 LLM 漂移检测器以获得可复现性。

    ***这是代理实现，不是 LLM 检测器。其 FPR/Recall 不代表 LLM 检测器的表现。***
    输入仅为收据的结构化字段，不读取 ActionRequest.text。
    """

    def __init__(self, threshold: float = 3.5):
        self.threshold = threshold
        self.training = True
        self.cap_counts: dict[str, Counter] = defaultdict(Counter)
        self.res_counts: dict[str, Counter] = defaultdict(Counter)
        self.total: Counter = Counter()
        self.surprise_hist: dict[str, list] = defaultdict(list)
        self.median: dict[str, float] = {}
        self.mad: dict[str, float] = {}
        self.last_allowed_rank: dict[str, int] = defaultdict(int)
        self.alerts = 0
        self.scored = 0

    def _surprise(self, sid: str, cap: str, res: str) -> float:
        n = self.total[sid] + len(CAP_UNIVERSE)
        p_cap = (self.cap_counts[sid][cap] + 1) / n
        p_res = (self.res_counts[sid][res] + 1) / (self.total[sid] + 50)
        return -math.log(p_cap) - 0.5 * math.log(p_res)

    def freeze(self) -> None:
        """结束训练期，落定基线。"""
        self.training = False
        for sid, vals in self.surprise_hist.items():
            if not vals:
                continue
            s = sorted(vals)
            med = s[len(s) // 2]
            dev = sorted(abs(v - med) for v in vals)
            mad = dev[len(dev) // 2]
            self.median[sid] = med
            self.mad[sid] = mad
        allv = [v for vals in self.surprise_hist.values() for v in vals]
        if allv:
            s = sorted(allv)
            gmed = s[len(s) // 2]
            dev = sorted(abs(v - gmed) for v in allv)
            self.median["__global__"] = gmed
            self.mad["__global__"] = dev[len(dev) // 2]

    def observe(self, r: Receipt) -> float:
        sid = r.from_id
        surprise = self._surprise(sid, r.capability, r.resource)
        escalation = (r.decision == "DENY"
                      and CAP_SENSITIVITY.get(r.capability, 0) > self.last_allowed_rank[sid])

        if self.training:
            self.surprise_hist[sid].append(surprise)
            self._update(sid, r)
            return 0.0

        med = self.median.get(sid, self.median.get("__global__", 0.0))
        mad = self.mad.get(sid, self.mad.get("__global__", 1.0))
        scale = mad if mad > 1e-9 else 1.0
        z = 0.6745 * (surprise - med) / scale
        score = max(0.0, z) + (3.0 if escalation else 0.0)
        self.scored += 1
        if score >= self.threshold:
            self.alerts += 1
        self._update(sid, r)
        return score

    def _update(self, sid: str, r: Receipt) -> None:
        self.cap_counts[sid][r.capability] += 1
        self.res_counts[sid][r.resource] += 1
        self.total[sid] += 1
        if r.decision == "ALLOW":
            self.last_allowed_rank[sid] = max(self.last_allowed_rank[sid],
                                              CAP_SENSITIVITY.get(r.capability, 0))


# ---------------------------------------------------------------- 证据平面
class EvidencePlane:
    """只读收据流。TCB。"""

    def __init__(self, drift: DriftDetector, registry: dict):
        self.receipts: list[Receipt] = []
        self.registry = registry
        self.invalid = 0
        self.drift = drift

    def submit(self, r: Receipt) -> Receipt:
        pk = self.registry.get(r.to_id)
        if pk is None or not verify(pk.pubkey, r.body(), r.sig):
            self.invalid += 1
            raise Deny(R_RECEIPT, f"收据 {r.receipt_id[:8]} 签名无效")
        score = self.drift.observe(r)
        r2 = replace(r, drift_score=score)
        self.receipts.append(r2)
        return r2

    # --- 分析 ---
    def denies(self) -> list[Receipt]:
        return [r for r in self.receipts if r.decision == "DENY"]

    def reason_hist(self) -> Counter:
        return Counter(r.reason_code for r in self.denies())

    def edges(self) -> Counter:
        return Counter((r.from_id, r.to_id) for r in self.receipts)

    def check_invariant_i5(self) -> bool:
        """I5：所有请求都留下收据，无静默丢弃。"""
        return all(r.decision in ("ALLOW", "DENY") for r in self.receipts)


# --------------------------------------------------------------------- 策略
def _enforce(sys, req: ActionRequest, token, now: int, seen_nonces: set,
             max_seen_cred: dict, known_epoch, grants_held: dict) -> tuple[str, str]:
    """spec §3.2 的判定算法。仅读取结构化字段。返回 (decision, reason_code)。"""
    reg = sys.authority.registry
    # 1. 归因：请求必须由发送方 PEP 签名
    pk = reg.get(req.from_id)
    if pk is None or not verify(pk.pubkey, req.body(), req.sig):
        return "DENY", R_UNSIGNED
    # 2. 重放
    key = (req.from_id, req.nonce)
    if key in seen_nonces:
        return "DENY", R_REPLAY
    if now - req.ts > sys.max_request_age or req.ts > now + sys.clock_skew:
        return "DENY", R_REPLAY
    seen_nonces.add(key)
    # 3. 令牌
    if token is None:
        return "DENY", "TOKEN_INVALID"
    if token_issuer(token) != req.from_id:
        return "DENY", "TOKEN_INVALID"
    # 4. 回滚防护：根授权的 cred_epoch 不得低于已见最大值
    # 按令牌链根解析出它**实际根植**的授权，而不是总是用当前授权——
    # 否则一次常规重签发会让全部在途令牌误判为链断裂。
    root_id = token.chain[0].parent_token_id if token.chain else token.token_id
    grant = next((g for g in grants_held.get(token.root_subject_id, {}).values()
                  if root_token_id(g) == root_id), None)
    if grant is None:
        return "DENY", "TOKEN_INVALID"      # 本地未持有该链根的授权副本
    if grant.cred_epoch < max_seen_cred.get(token.root_subject_id, 0):
        return "DENY", R_STALE
    max_seen_cred[token.root_subject_id] = max(
        max_seen_cred.get(token.root_subject_id, 0), grant.cred_epoch)
    # 5. 离线验证令牌链
    try:
        verify_token(token, grant, sys.authority.pk, reg, known_epoch, now,
                     sys.clock_skew)
    except Deny as d:
        return "DENY", d.reason_code
    # 6. 任务绑定与范围
    if token.task_id != req.task_id:
        return "DENY", "TASK_MISMATCH"
    if not scope_allows(token.scope, req.capability, req.resource):
        return "DENY", "SCOPE_VIOLATION"
    # 复合动作：required 中每一项都必须落在同一令牌范围内，否则整体拒绝（原子）
    for item in req.required:
        cap, _, res = item.partition("@")
        if not scope_allows(token.scope, cap, res or req.resource):
            return "DENY", "SCOPE_VIOLATION"
    return "ALLOW", "OK"


# -------------------------------------------------------------------- 基线
class CentralPDP:
    """B1：中心策略判定点。策略与 P 相同，但每条跨 Agent 调用都要过一次中心。"""

    def __init__(self, sys):
        self.sys = sys
        self.seen_nonces: set = set()
        self.max_seen_cred: dict = {}
        self.calls = 0
        # 中心判定点与权威同址，因此**合法地**持有全部授权历史。
        # （边级 PEP 只能持有自己收到的那几份副本——见 PEP.grants_held。）
        self.grants_held = sys.authority.grant_history

    def decide(self, req, token, now):
        self.calls += 1
        self.sys.round_trips += 1
        return _enforce(self.sys, req, token, now, self.seen_nonces,
                        self.max_seen_cred, self.sys.authority.current(),
                        self.grants_held)


SUSPICIOUS = re.compile(
    r"(?i)(admin|root\b|sudo|export|credential|password|secret|shell|/etc/|"
    r"drop\s+table|ignore previous|exfiltrat|database\.admin|db\.admin)")


def prompt_guard(text: str) -> bool:
    """B2：提示层护栏。只看自由文本。"""
    return bool(SUSPICIOUS.search(text or ""))


# --------------------------------------------------------------------- PEP
class PEP:
    """策略执行点。持密钥、判范围、执行副作用。属于 TCB。"""

    def __init__(self, sys, subject, sk, grant):
        self.sys = sys
        self.subject = subject
        self.sk = sk
        self.grant = grant
        self.root = root_token(grant)
        self.tokens: dict[str, object] = {self.root.token_id: self.root}
        self.seen_nonces: set = set()
        self.max_seen_cred: dict = {subject.subject_id: grant.cred_epoch}
        # **本地持有的根授权副本**（按 (主体, cred_epoch) 索引）。
        # 验证一律查本地，绝不查权威——否则"纯离线验证"这个说法不成立。
        # 构造时按当前权威状态播种，模拟凭据的带外分发。
        self.grants_held: dict[str, dict[int, object]] = {}
        for sid, g in sys.authority.grants.items():
            self.grants_held.setdefault(sid, {})[g.cred_epoch] = g
        self.known_epoch = sys.authority.current()
        self.pull_count = 0
        self.last_pull_tick = sys.now
        self.partitioned = False        # 网络分区：拉不到撤销状态
        self.head_records: list[tuple[int, str]] = []
        self.fail_fast_blocked = 0
        self.pull()

    # --- 撤销状态同步 ---
    def pull(self, epoch=None) -> None:
        epoch = (self.sys.authority.current_for(self.subject.subject_id)
                 if epoch is None else epoch)
        self.known_epoch = epoch
        self.pull_count += 1
        self.last_pull_tick = self.sys.now
        self.head_records.append((epoch.epoch, epoch.log_head_hash))

    def resolve_grant(self, subject_id: str, root_token_id_):
        """在**本地持有的副本**中按链根解析授权。解析不到即拒绝——不向权威查询。"""
        for g in self.grants_held.get(subject_id, {}).values():
            if root_token_id(g) == root_token_id_:
                return g
        return None

    def install_grant(self, grant) -> bool:
        """带外收到一份授权副本（不改变最大已见 epoch，只登记）。"""
        if not self.sys.authority.verify_grant(grant):
            return False
        self.grants_held.setdefault(grant.subject_id, {})[grant.cred_epoch] = grant
        return True

    def refresh_grant(self, grant) -> bool:
        """凭证刷新：回滚防护（P2）+ 更新本级持有的根令牌。

        **必须同时更新根令牌**：否则本主体后续派生仍用旧授权，而验证方按链根解析——
        新旧混用会使派生出的令牌无法通过验证（差分测试发现的操作隐患）。
        """
        seen = self.max_seen_cred.get(grant.subject_id, 0)
        if grant.cred_epoch < seen:
            return False
        if not self.sys.authority.verify_grant(grant):
            return False
        self.max_seen_cred[grant.subject_id] = max(seen, grant.cred_epoch)
        self.grants_held.setdefault(grant.subject_id, {})[grant.cred_epoch] = grant
        if grant.subject_id == self.subject.subject_id:
            self.grant = grant
            self.root = root_token(grant)
            self.tokens[self.root.token_id] = self.root
        return True

    def maybe_pull(self) -> None:
        if self.partitioned:
            return                      # 分区中：本地撤销状态冻结
        if self.sys.now - self.last_pull_tick >= self.sys.pull_interval:
            self.pull()

    # --- 作为接收方 ---
    def accept_token(self, token) -> None:
        if self.sys.mode == "B0":
            # B0 基线：根本不存在凭证体系，委托不产生任何约束
            self.tokens[token.token_id] = token
            return
        if token.holder_id != self.subject.subject_id:
            raise Deny("TOKEN_INVALID",
                       f"令牌持有者是 {token.holder_id}，本 PEP 是 {self.subject.subject_id}")
        root_id = token.chain[0].parent_token_id if token.chain else token.token_id
        grant = self.resolve_grant(token.root_subject_id, root_id)
        if grant is None:
            raise Deny("TOKEN_INVALID", "本地未持有该链根对应的根授权副本")
        seen = self.max_seen_cred.get(token.root_subject_id, 0)
        if grant.cred_epoch < seen:
            raise Deny(R_STALE, f"根授权 cred_epoch={grant.cred_epoch} < 已见 {seen}")
        self.max_seen_cred[token.root_subject_id] = max(seen, grant.cred_epoch)
        verify_token(token, grant, self.sys.authority.pk, self.sys.authority.registry,
                     self.known_epoch, self.sys.now, self.sys.clock_skew)
        self.tokens[token.token_id] = token

    def handle(self, req: ActionRequest, source: str = "net") -> Receipt:
        mode = self.sys.mode
        s = self.sys
        token = self.tokens.get(req.token_id)

        if mode == "B0":
            decision, reason = "ALLOW", "OK"
        elif mode == "B2":
            if prompt_guard(req.text):
                decision, reason = "DENY", R_GUARD
            else:
                decision, reason = "ALLOW", "OK"
        elif mode == "B4":
            # **B4：静态配置，无令牌层。** 每个 Agent 按角色配置自己的工具集，
            # 接收方只检查能力是否在**自己的**配置范围内——不验令牌、不查签发者。
            # 这是实践中最常见的做法，也是"多 Agent 分解 + 最少权限配置"的形态。
            if req.capability in set(self.grant.scope):
                decision, reason = "ALLOW", "OK"
            else:
                decision, reason = "DENY", "SCOPE_VIOLATION"
        elif mode == "B1":
            if not s.pdp_available:
                decision, reason = "DENY", R_PDP_DOWN
            else:
                decision, reason = s.pdp.decide(req, token, s.now)
        else:  # P
            decision, reason = _enforce(s, req, token, s.now, self.seen_nonces,
                                        self.max_seen_cred, self.known_epoch,
                                        self.grants_held)

        if decision == "ALLOW":
            s.world.execute(req.capability, req.resource, req.from_id,
                            req.params_hash, s.now)

        r = Receipt(receipt_id=h({"r": req.request_id, "to": self.subject.subject_id}),
                    from_id=req.from_id, to_id=self.subject.subject_id,
                    request_id=req.request_id, token_id=req.token_id,
                    task_id=req.task_id, capability=req.capability,
                    resource=req.resource, decision=decision, reason_code=reason,
                    ts=s.now)
        r = replace(r, sig=sign(self.sk, r.body()))
        return s.evidence.submit(r)

    # --- 作为发送方 ---
    def send_to(self, to_id: str, token_id: str, capability: str, resource: str,
                task_id: str, text: str = "", params: str = "p",
                required: tuple = ()) -> Receipt:
        s = self.sys
        if s.fail_fast:
            t = self.tokens.get(token_id)
            if t is None or not scope_allows(t.scope, capability, resource) or any(
                    not scope_allows(t.scope, it.partition("@")[0],
                                     it.partition("@")[2] or resource)
                    for it in required):
                self.fail_fast_blocked += 1
                # 本地拒绝：不发出请求，但留下一条归属明确的收据（由本 PEP 记录）
                r = Receipt(receipt_id=h({"ff": s.seq, "to": to_id, "ts": s.now}),
                            from_id=self.subject.subject_id, to_id=self.subject.subject_id,
                            request_id=f"ff-{s.seq}", token_id=token_id,
                            task_id=task_id, capability=capability, resource=resource,
                            decision="DENY", reason_code=R_FAILFAST, ts=s.now)
                return s.evidence.submit(replace(r, sig=sign(self.sk, r.body())))
        rid = f"req-{s.seq}"
        s.seq += 1
        req = ActionRequest(request_id=rid, from_id=self.subject.subject_id, to_id=to_id,
                            task_id=task_id, token_id=token_id, capability=capability,
                            resource=resource, params_hash=h({"p": params}),
                            nonce=h({"n": rid, "ts": s.now}), ts=s.now, text=text,
                            required=tuple(required))
        req = replace(req, sig=sign(self.sk, req.body()))
        s._log_request(req)
        return s.peps[to_id].handle(req)


class Planner:
    """不可信规划进程。不持有任何密钥，只能提议。

    "被 prompt injection 控制"在本模型中等价于：以任意 capability 调用 propose()。
    无需专门代码。
    """

    def __init__(self, subject_id: str, pep: PEP):
        self.subject_id = subject_id
        self.pep = pep

    def propose(self, to_id: str, token_id: str, capability: str, resource: str,
                task_id: str, text: str = "", required: tuple = ()) -> Receipt:
        return self.pep.send_to(to_id, token_id, capability, resource, task_id,
                                text=text, required=required)


# -------------------------------------------------------------------- 系统
class System:
    MODES = ("P", "B0", "B1", "B2", "B4")

    def __init__(self, mode: str = "P", ttl: int = 100, pull_interval: int = 10,
                 max_request_age: int = 50, clock_skew: int = 0,
                 fail_fast: bool = False, central_rtt_us: float = 1500.0):
        assert mode in self.MODES, mode
        self.mode = mode
        self.now = 1
        self.seq = 0
        self.authority = Authority(ttl=ttl)
        self.world = World()
        self.drift = DriftDetector()
        self.evidence = EvidencePlane(self.drift, self.authority.registry)
        self.peps: dict[str, PEP] = {}
        self.planners: dict[str, Planner] = {}
        self.edges: list[tuple[str, str, object]] = []
        self.requests: list[ActionRequest] = []
        self.ttl = ttl
        self.pull_interval = pull_interval
        self.max_request_age = max_request_age
        self.clock_skew = clock_skew
        self.fail_fast = fail_fast
        self.round_trips = 0
        self.central_rtt_us = central_rtt_us
        self.pdp_available = True
        self.pdp = CentralPDP(self)
        self.pdp_refusals = 0

    # --- 装配 ---
    def add_agent(self, sid: str, role: str, scope, key_epoch: int = 1):
        subj, sk = self.authority.register(sid, role, key_epoch=key_epoch)
        grant = self.authority.issue_grant(sid, scope, self.now)
        pep = PEP(self, subj, sk, grant)
        self.evidence.registry[sid] = subj
        self.peps[sid] = pep
        self.planners[sid] = Planner(sid, pep)
        return subj, grant, pep

    def rotate_key(self, sid: str, new_epoch: int, scope):
        """密钥轮换：权威单方重签根授权（泄露场景下不得由旧密钥自证，见 spec §2.3/§3.3）。"""
        old = self.authority.registry[sid]
        subj, sk = self.authority.register(sid, old.role, key_epoch=new_epoch)
        grant = self.authority.issue_grant(sid, scope, self.now)
        return subj, grant, sk

    def advance(self, n: int = 1) -> None:
        for _ in range(n):
            self.now += 1
            for pep in self.peps.values():
                pep.maybe_pull()

    # --- 委托 ---
    def delegate(self, frm: str, to: str, scope, task_id: str,
                 ttl: int | None = None, parent_token_id: str | None = None,
                 redelegatable: bool = True):
        p = self.peps[frm]
        if parent_token_id:
            parent = p.tokens.get(parent_token_id)
            if parent is None:
                raise Deny("TOKEN_INVALID",
                           f"{frm} 不持有父令牌 {parent_token_id[:8]}")   # 曾抛裸 KeyError
        else:
            parent = p.root
        not_after = min(parent.not_after, self.now + (ttl or self.ttl))
        tok = attenuate(parent, to, scope, task_id, not_after,
                        self.authority.registry[frm], p.sk, self.now,
                        unconstrained=(self.mode == "B0"),
                        redelegatable=redelegatable)
        # **委托随令牌一并送达其所依据的根凭据副本**（凭据是公开的，见 spec §2.2）。
        # 早先版本把副本可得性绑在"创建顺序"上（构造时播种），那是不真实的：
        # 真实验证方拿到的是随委托一起收到的凭据副本。此改动同时修复了
        # 因创建顺序导致部分委托无法验证的问题。
        self.peps[to].install_grant(self.authority.grants[tok.root_subject_id])
        self.peps[to].accept_token(tok)
        # 委托方**不保留**所授令牌副本（spec §3.1）：令牌只存于持有者的 PEP。
        self.edges.append((frm, to, tok))
        return tok

    # --- 请求 ---
    def request(self, frm: str, to: str, token_id: str, capability: str,
                resource: str, task_id: str, text: str = "",
                required: tuple = ()) -> Receipt:
        return self.planners[frm].propose(to, token_id, capability, resource,
                                          task_id, text=text, required=required)

    # --- 网络分区 ---
    def set_partition(self, sids) -> None:
        """把给定主体置于分区中：它们不再能拉取撤销状态。"""
        for sid, pep in self.peps.items():
            pep.partitioned = sid in set(sids)

    def _log_request(self, req: ActionRequest) -> None:
        self.requests.append(req)

    # --- 度量 ---
    def stats(self) -> dict:
        return {"round_trips": self.round_trips,
                "sign_ops": STATS["sign"], "verify_ops": STATS["verify"],
                "sign_bytes": STATS["sign_bytes"],
                "verify_bytes": STATS["verify_bytes"],
                "receipts": len(self.evidence.receipts),
                "effects": len(self.world.effects),
                "pulls": sum(p.pull_count for p in self.peps.values())}
