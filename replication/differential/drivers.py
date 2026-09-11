"""把两侧实现包装成同一门面，供差分装置对称调用。

REF 侧只通过黑盒接口调用：`src.runtime.System` 的公开方法、`src.model` 的公开
dataclass、`src.crypto` 的公开原语、以及 `src.patterns` 的公开谓词函数。
本文件不读取任何 `src/` 源码内容。

MINE 侧包装 `replication/mechanism.py` + `replication/patterns.py`（上一轮的独立实现）。
"""
from __future__ import annotations

import dataclasses
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
REPL = os.path.join(ROOT, "replication")
for p in (ROOT, REPL):
    if p not in sys.path:
        sys.path.insert(0, p)

# ---- 参考实现（只 import 公开 API）-----------------------------------------
from src.runtime import System as RefSystem          # noqa: E402
from src.model import Deny as RefDeny                # noqa: E402
from src.model import ActionRequest as RefRequest    # noqa: E402
from src.crypto import sign as ref_sign              # noqa: E402
import src.patterns as ref_patterns                  # noqa: E402

import mechanism as MINE_M                           # noqa: E402
import patterns as MINE_P                            # noqa: E402


class Denied(Exception):
    def __init__(self, code, detail=""):
        super().__init__(f"{code}: {detail}")
        self.reason_code = code
        self.detail = detail


class Res:
    __slots__ = ("decision", "reason_code", "effects_delta", "note")

    def __init__(self, decision, reason_code, effects_delta=0, note=""):
        self.decision = decision
        self.reason_code = reason_code
        self.effects_delta = effects_delta
        self.note = note

    def key(self):
        return (self.decision, self.reason_code)

    def __repr__(self):
        return f"Res({self.decision},{self.reason_code},eff={self.effects_delta})"


# ============================================================== REFERENCE ====
class RefDriver:
    name = "ref"

    def __init__(self, ttl=1000, pull_interval=10):
        self.s = RefSystem(mode="P", ttl=ttl, pull_interval=pull_interval)
        self.ttl = ttl
        self.pull_interval = pull_interval
        self.max_request_age = self.s.max_request_age
        self._tokens = {}

    # -- 结构 ---------------------------------------------------------------
    def add_agent(self, sid, role, scope):
        self.s.add_agent(sid, role, list(scope))

    def has_agent(self, sid):
        return sid in self.s.peps

    def advance(self, n):
        self.s.advance(n)

    @property
    def now(self):
        return self.s.now

    @property
    def n_effects(self):
        return len(self.s.world.effects)

    @property
    def n_receipts(self):
        return len(self.s.evidence.receipts)

    def effects(self):
        return [(e.get("capability"), e.get("resource"), e.get("actor"))
                for e in self.s.world.effects]

    def set_partition(self, sids):
        self.s.set_partition(list(sids))

    # -- 令牌 ---------------------------------------------------------------
    def delegate(self, frm, to, scope, task_id, ttl=None, parent_token_id=None,
                 redelegatable=True):
        try:
            t = self.s.delegate(frm, to, list(scope), task_id, ttl=ttl,
                                parent_token_id=parent_token_id,
                                redelegatable=redelegatable)
        except RefDeny as e:
            raise Denied(e.reason_code, getattr(e, "detail", "")) from None
        self._tokens[t.token_id] = t
        return t.token_id

    def token_info(self, tid):
        t = self._tokens[tid]
        return {"scope": tuple(sorted(t.scope)), "depth": t.depth,
                "holder_id": t.holder_id, "redelegatable": t.redelegatable,
                "not_after": t.not_after, "task_id": t.task_id,
                "chain_len": len(t.chain)}

    def root_token_id(self, sid):
        return self.s.peps[sid].root.token_id

    # -- 请求 ---------------------------------------------------------------
    def force_request(self, frm, to, token_id, cap, res, task_id, nonce, ts,
                      bad_sig=False, required=()):
        n0 = self.n_effects
        req = RefRequest(request_id=f"force-{nonce}", from_id=frm, to_id=to,
                         task_id=task_id, token_id=token_id, capability=cap,
                         resource=res, params_hash="p", nonce=nonce, ts=ts,
                         text="", required=tuple(required), sig="")
        if not bad_sig:
            body = {k: v for k, v in vars(req).items() if k not in ("sig", "text")}
            # 实测：参考实现签名前把 required 排序（to_dict() 亦返回排序后的值）。
            # 不排序会产生假 REQUEST_UNSIGNED —— 这是本装置的缺陷，不是被测行为。
            body["required"] = tuple(sorted(body["required"]))
            req = dataclasses.replace(req, sig=ref_sign(self.s.peps[frm].sk, body))
        self._last_req = req
        rec = self.s.peps[to].handle(req)
        return Res(rec.decision, rec.reason_code, self.n_effects - n0)

    def request(self, frm, to, token_id, cap, res, task_id, text="", required=(),
                nonce=None, ts=None, bad_sig=False, replay_last=False):
        if replay_last:
            n0 = self.n_effects
            rec = self.s.peps[to].handle(self._last_req)
            return Res(rec.decision, rec.reason_code, self.n_effects - n0)
        n0 = self.n_effects
        self.s.peps[frm].send_to(to, token_id, cap, res, task_id, text=text,
                                 required=tuple(required))
        req = self.s.requests[-1]
        self._last_req = req
        return Res(req.decision, req.reason_code, self.n_effects - n0)

    # -- 撤销 / 凭证 --------------------------------------------------------
    def revoke_token(self, tid):
        self.s.authority.revoke_token(tid, self.s.now)

    def revoke_subject(self, sid):
        self.s.authority.revoke_subject(sid, self.s.now)

    def revoke_key_epoch(self, sid, upto):
        self.s.authority.revoke_key_epochs(sid, upto, self.s.now)

    def set_clock_skew(self, k):
        self.s.clock_skew = k

    def issue_grant(self, sid, scope, ttl=None):
        return self.s.authority.issue_grant(sid, list(scope), self.s.now, ttl)

    def refresh_grant(self, sid, grant):
        return self.s.peps[sid].refresh_grant(grant)

    def current_grant(self, sid):
        return self.s.authority.grants.get(sid)

    def rollback_credential(self, sid, grant):
        """模拟"接收方持有的根授权副本被回滚"。
        走 PEP 的公开 refresh_grant 入口；返回值即该入口的判定。"""
        return self.s.peps[sid].refresh_grant(grant)


# =================================================================== MINE ====
class MyDriver:
    name = "mine"

    def __init__(self, ttl=1000, pull_interval=10):
        self.world = MINE_M.WorldModel()
        self.evidence = MINE_M.EvidencePlane()
        self.auth = MINE_M.Authority()
        self.ttl = ttl
        self.pull_interval = pull_interval
        self.max_request_age = MINE_M.MAX_REQUEST_AGE
        self._now = 1.0
        self.peps = {}
        self.grants = {}
        self.root_tokens = {}
        self.partitioned = set()
        self.revoked_subjects = set()
        self._tokens = {}
        self._next_pull = self._now + pull_interval
        self._pending_revoked = set()
        self._pending_key_epochs = {}
        self._ctr = 0

    # -- 结构 ---------------------------------------------------------------
    def add_agent(self, sid, role, scope):
        g = self.auth.issue_root_grant(sid, list(scope), now=self._now,
                                       ttl=self.ttl)
        p = MINE_M.PEP(sid, self.world, self.evidence, self.auth)
        self.grants[sid] = g
        self.peps[sid] = p
        for q in self.peps.values():
            q.peers = self.peps
        # 实测：参考实现中新加入的主体 PEP 初始即带权威当前的撤销状态
        # （在此之后新发生的撤销仍需等下一次拉取）。
        p.revoked_tokens |= set(self._pending_revoked)
        p.revoked_key_epochs.update(self._pending_key_epochs)
        p.revoked_subjects |= set(self.revoked_subjects)
        p.install_grant(g, self._now)      # §5：本级持有的根令牌由刷新建立
        rt = p.root_token
        self.root_tokens[sid] = rt
        self._tokens[rt.token_id] = rt

    def has_agent(self, sid):
        return sid in self.peps

    def advance(self, n):
        self._now += n
        while self._now >= self._next_pull:
            self._pull()
            self._next_pull += self.pull_interval

    def _pull(self):
        for sid, p in self.peps.items():
            if p.partitioned:
                continue
            if sid in self.revoked_subjects:
                p.revoked_subjects.add(sid)
            for tid, t in list(p.store.items()):
                if tid in self._pending_revoked or t.holder_id in self.revoked_subjects:
                    p.revoked_tokens.add(tid)
            for sid, upto in self._pending_key_epochs.items():
                p.revoked_key_epochs[sid] = max(p.revoked_key_epochs.get(sid, 0), upto)

    @property
    def now(self):
        return self._now

    @property
    def n_effects(self):
        return len(self.world.effects)

    @property
    def n_receipts(self):
        return len(self.evidence.receipts)

    def effects(self):
        return [(e.get("capability"), e.get("resource"), e.get("from_id"))
                for e in self.world.effects]

    def set_partition(self, sids):
        # 实测：参考实现的 set_partition 只作用于**已存在的 PEP**；之后才 add_agent 的主体
        # 不带分区标记（§2.12 把 partitioned 定义为 PEP 的属性）。
        # 同时它是**替换**而非追加（set_partition([]) 即恢复）。
        self.partitioned = set(sids)
        for sid, p in self.peps.items():
            p.partitioned = sid in self.partitioned

    # -- 令牌 ---------------------------------------------------------------
    def delegate(self, frm, to, scope, task_id, ttl=None, parent_token_id=None,
                 redelegatable=True):
        if to not in self.peps:
            raise Denied("TOKEN_INVALID", "接收方不存在")
        if parent_token_id is None:
            parent = self.peps[frm].root_token      # §5：本级持有的根令牌
        else:
            parent = self._tokens.get(parent_token_id)
        if parent is None:
            # §2.3 派生规则 1：派生者必须持有父令牌。参考实现改抛 Deny(TOKEN_INVALID)。
            raise Denied("TOKEN_INVALID", "父令牌不在本地库")
        grant = self.auth.grant_for_root_id(parent.root_grant_id)
        ttl = self.ttl if ttl is None else ttl
        try:
            t = MINE_M.attenuate(parent, to, set(scope), task_id, ttl,
                                 self.peps[frm], self._now, grant)
        except MINE_M.DerivationRejected as e:
            raise Denied(e.code) from None
        if not redelegatable:
            t.redelegatable = False
            t.token_id = t.recompute_id()
        self._tokens[t.token_id] = t
        ok, why = self.peps[to].receive_token(t, self._now)
        if not ok:
            raise Denied(why)
        return t.token_id

    def token_info(self, tid):
        t = self._tokens[tid]
        return {"scope": tuple(sorted(t.scope)), "depth": t.depth,
                "holder_id": t.holder_id, "redelegatable": t.redelegatable,
                "not_after": t.not_after, "task_id": t.task_id,
                "chain_len": len(t.chain)}

    def root_token_id(self, sid):
        return self.peps[sid].root_token.token_id

    # -- 请求 ---------------------------------------------------------------
    def _build(self, frm, to, token_id, cap, res, task_id, nonce, ts, bad_sig,
               required=()):
        req = MINE_M.ActionRequest(request_id=f"force-{nonce}", from_id=frm,
                                   to_id=to, task_id=task_id, token_id=token_id,
                                   capability=cap, resource=res, nonce=nonce, ts=ts,
                                   required=tuple(required))
        req.sig_from_pep = (b"" if bad_sig else
                            MINE_M.sign(self.peps[frm].sk, MINE_M._canon(req.body())))
        return req

    def force_request(self, frm, to, token_id, cap, res, task_id, nonce, ts,
                      bad_sig=False, required=()):
        n0 = self.n_effects
        req = self._build(frm, to, token_id, cap, res, task_id, nonce, ts,
                          bad_sig, required)
        self._last_req = req
        return Res(*self._handle(req, to, token_id, frm), self.n_effects - n0)

    def request(self, frm, to, token_id, cap, res, task_id, text="", required=(),
                nonce=None, ts=None, bad_sig=False, replay_last=False):
        if replay_last:
            n0 = self.n_effects
            return Res(*self._handle(self._last_req, to, token_id, frm),
                       self.n_effects - n0)
        return self.force_request(frm, to, token_id, cap, res, task_id,
                                  nonce or self._auto_nonce(),
                                  self._now if ts is None else ts, bad_sig,
                                  required)

    def _handle(self, req, to, token_id, frm):
        rec = self.peps[to].handle(req, self._now)
        return rec.decision, rec.reason_code

    def _auto_nonce(self):
        self._ctr += 1
        return f"n{self._ctr}"

    # -- 撤销 / 凭证 --------------------------------------------------------
    def revoke_token(self, tid):
        self._pending_revoked.add(tid)

    def revoke_subject(self, sid):
        self.revoked_subjects.add(sid)

    def revoke_key_epoch(self, sid, upto):
        # 作废上界只增不减（§2.3 规则 6 的语义是"上限"）
        self._pending_key_epochs[sid] = max(self._pending_key_epochs.get(sid, 0), upto)

    def set_clock_skew(self, k):
        # §3.2 钉死的公式是 `0 ≤ now - req.ts ≤ max_request_age`，**没有时钟偏移项**。
        # 本侧照规格实现，故 clock_skew 不参与判定（见 REPORT-r2.md「规格仍不够清楚」）。
        self.clock_skew = k

    def issue_grant(self, sid, scope, ttl=None):
        # §2.2：cred_epoch 单调递增。签发的授权进入权威的历史，但**不自动分发**——
        # 各方按 §5 自行刷新。
        return self.auth.issue_grant(sid, list(scope), now=self._now,
                                     ttl=self.ttl if ttl is None else ttl)

    def refresh_grant(self, sid, grant):
        # §5：验证方装入该授权；若为本级自己的授权，同时更新本级根令牌。
        return self.peps[sid].install_grant(grant, self._now)

    def current_grant(self, sid):
        return self.auth.latest.get(sid)

    def rollback_credential(self, sid, grant):
        self.peps[sid].install_grant(grant, self._now)
        return True


# ---------------------------------------------------------------- 模式谓词 -
def ref_pattern_matches(p, r):
    return bool(ref_patterns.matches(p, r))


def ref_pattern_subsumes(c, p):
    return bool(ref_patterns.subsumes(c, p))


def mine_pattern_matches(p, r):
    return bool(MINE_P.matches(p, r))


def mine_pattern_subsumes(c, p):
    return bool(MINE_P.subsumes(c, p))


def new_driver(which, **kw):
    return RefDriver(**kw) if which == "ref" else MyDriver(**kw)
