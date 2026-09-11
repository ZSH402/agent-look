"""场景族生成器。每个用例 = 一个函数 `(driver) -> dict[str, value]`。

用例的**输入**由 `spec/spec.md` 的条文推出（§2.8 语法、§2.3 派生规则、
§3.2 判定顺序、§2.12 复合动作与分区）；用例的**期望**写在 oracle.py。
本文件不引用任何参考实现的行为来决定输入。
"""
from __future__ import annotations

import itertools
import random

import oracle
from drivers import Denied

CAP = "order.read"
CAP2 = "order.write"


def safe(fn, *a, **kw):
    """把抛出的异常变成可比对的值，而不是中断整个用例。"""
    try:
        return fn(*a, **kw), None
    except Exception as e:                                    # noqa: BLE001
        return None, f"EXC:{type(e).__name__}"


# ============================================================ 族 1：模式包含 =
def gen_patterns():
    """§2.8 语法的穷举：PATTERN := segment('/'segment)* [ '**' ]，segment ∈ {字面量,'*'}。"""
    pats = []
    for L in range(4):
        for combo in itertools.product(["a", "b", "*"], repeat=L):
            base = "/".join(combo)
            pats.append(base)                 # 无 '**' 尾巴（L=0 时即空模式 "")
            pats.append(base + ("/" if base else "") + "**")
    # 去重保序
    seen, out = set(), []
    for p in pats:
        if p not in seen:
            seen.add(p)
            out.append(p)
    return out


def gen_resources():
    """资源串：段 ∈ {a,b,''}，长度 0..3。空资源对应 §8.2「工具无字符串参数」。"""
    res = []
    for L in range(4):
        for combo in itertools.product(["a", "b", ""], repeat=L):
            res.append("/".join(combo))
    seen, out = set(), []
    for r in res:
        if r not in seen:
            seen.add(r)
            out.append(r)
    return out


def family_pattern_matches(drv_kind):
    """用例由 `run_minmax` 统一跑；这里只给 (输入, 双侧取值函数)。"""
    raise NotImplementedError


# ------------------------------------------------------- 系统级 matches 探针
def sys_matches(drv, pattern, resource, setup=None):
    """把 `cap@pattern` 放进令牌范围，观察一次 (cap,resource) 请求是否放行。"""
    drv.add_agent("A", "c", [f"{CAP}@{pattern}"])
    drv.add_agent("B", "w", [])
    tid = drv.delegate("A", "B", [f"{CAP}@{pattern}"], "T1")
    r = drv.force_request("A", "B", tid, CAP, resource, "T1", "nm", drv.now)
    return r


# ---------------------------------------------------- 系统级 subsumes 探针
def sys_subsumes(drv, child_pat, parent_pat):
    drv.add_agent("A", "c", [f"{CAP}@{parent_pat}"])
    drv.add_agent("B", "w", [])
    try:
        drv.delegate("A", "B", [f"{CAP}@{child_pat}"], "T1")
        return "ACCEPT", None
    except Exception as e:                                    # noqa: BLE001
        return "DENY", type(e).__name__


# ============================================================ 族 2：衰减链 =
SCOPE_VOCAB = [
    "order.read@orders/*", "order.read@orders/**", "order.read@orders/7",
    "order.read@orders/9", "order.read@**", "order.read@orders/7/x",
    "order.write@orders/*", "db.export@reports/**", "db.export@reports/q3",
    "mail.send@**", "order.read", "order.write",
]


def random_scope(rng, n=None):
    k = rng.randint(1, 3) if n is None else n
    return rng.sample(SCOPE_VOCAB, k)


def family_attenuation(rng, n=60):
    """多级委托 / 封条 / 越权派生。"""
    cases = []
    for i in range(n):
        root_scope = random_scope(rng, 3)
        chain_len = rng.randint(2, 4)
        hops = [rng.choice(["B", "C", "D", "E"]) for _ in range(chain_len)]
        attempts = [random_scope(rng, rng.randint(1, 2)) for _ in range(chain_len)]
        seal_at = rng.choice([None] + list(range(chain_len)))
        over = random_scope(rng, 1)
        badparent = rng.random() < 0.25

        def run(d, root_scope=root_scope, hops=hops, attempts=attempts,
                seal_at=seal_at, over=over, badparent=badparent):

            d.add_agent("A", "c", root_scope)
            for h in set(hops) | {"F"}:
                d.add_agent(h, "w", [])
            out = {}
            parent, holder = None, "A"
            for k, (h, sc) in enumerate(zip(hops, attempts)):
                sealed = (seal_at == k)
                res, exc = safe(d.delegate, holder, h, sc, "T1",
                                None, parent, not sealed)
                if exc or res is None:
                    out[f"hop{k}"] = f"DENY/{exc}"
                    break
                info = d.token_info(res)
                out[f"hop{k}"] = (info["scope"], info["depth"],
                                  info["holder_id"], info["redelegatable"])
                parent, holder = res, h
            # 越权派生：三种构造，均必须被拒（§2.3 派生规则 2 / §5 P1）
            if parent is not None:
                pscope = set(d.token_info(parent)["scope"])
                pcaps = {e.split("@")[0] for e in pscope}
                foreign = next((e for e in SCOPE_VOCAB
                                if e.split("@")[0] not in pcaps), "zzz.none@**")
                first = sorted(pscope)[0] if pscope else "order.read@orders/7"
                over_cases = {
                    "over_foreign_cap": [foreign],
                    "over_widen": [first.split("@")[0] + "@**"],
                    "over_superset": sorted(pscope | {foreign}),
                }
                for tag, osc in over_cases.items():
                    # 只有**规格判据判定为不包含**的构造才算"越权派生尝试"，
                    # 否则接受它是正确的，不构成分歧。
                    if oracle.scope_subset(osc, pscope):
                        out[tag] = "skip(合法)"
                        continue
                    res, exc = safe(d.delegate, holder, "F", osc, "T1", None,
                                    parent, True)
                    out[tag] = "ACCEPT" if res else f"DENY/{exc}"
                    if res:
                        out[tag + "_scope"] = d.token_info(res)["scope"]
            # 非持有者派生
            if parent is not None:
                res, exc = safe(d.delegate, "F", "A", attempts[0], "T1", None,
                                parent, True)
                out["nonholder"] = f"ACCEPT" if res else f"DENY/{exc}"
            # 封条后再派生
            if parent is not None:
                res, exc = safe(d.delegate, holder, "F", ["order.read@orders/7"],
                                "T1", None, parent, True)
                out["seal_after"] = f"ACCEPT" if res else f"DENY/{exc}"
            return out

        cases.append((f"atten-{i}", run))
    return cases


# ==================================================== 族 3：判定顺序（多重违反）
def family_order(rng, n=None):
    """同一请求同时违反多条规则，看两侧报哪一条。"""
    variants = [
        # (过期?, 越权cap?, 任务不符?, 撤销?, 非签发者?, 备注)
        (True, True, True, False, False, "expired+scope+task"),
        (True, False, False, False, False, "expired"),
        (True, True, False, False, False, "expired+scope"),
        (True, False, True, False, False, "expired+task"),
        (True, True, True, True, False, "expired+scope+task+revoked"),
        (False, True, True, False, False, "scope+task"),
        (False, False, False, True, False, "revoked"),
        (False, False, False, False, True, "issuer_mismatch"),
        (False, False, False, True, True, "revoked+issuer"),
        (True, False, False, True, False, "expired+revoked"),
    ]
    cases = []
    for exp, oosc, task, rev, issuer, label in variants:
        def run(d, exp=exp, oosc=oosc, task=task, rev=rev, issuer=issuer):
            d.add_agent("A", "c", [f"{CAP}@orders/7", f"{CAP2}@orders/*"])
            for h in ("B", "C"):
                d.add_agent(h, "w", [])
            ttl = 5 if exp else 1000
            tid = d.delegate("A", "B", [f"{CAP}@orders/7"], "T1", ttl=ttl)
            if exp:
                d.advance(50)
            if rev:
                d.revoke_token(tid)
                d.advance(10)
            frm = "C" if issuer else "A"
            cap = CAP2 if oosc else CAP
            task_id = "T9" if task else "T1"
            r = d.force_request(frm, "B", tid, cap, "orders/7", task_id, "no", d.now)
            return {"key": r.reason_code, "dec": r.decision}
        cases.append((f"order-{label}", run))
    # 随机补充：随机叠加多个违规
    for i in range(n or 40):
        flags = [rng.random() < 0.5 for _ in range(5)]
        if not any(flags):
            flags[rng.randrange(5)] = True

        def run(d, flags=flags):
            d.add_agent("A", "c", [f"{CAP}@orders/7", f"{CAP2}@orders/*"])
            for h in ("B", "C"):
                d.add_agent(h, "w", [])
            exp, oosc, task, rev, issuer = flags
            ttl = 5 if exp else 1000
            tid = d.delegate("A", "B", [f"{CAP}@orders/7"], "T1", ttl=ttl)
            if exp:
                d.advance(50)
            if rev:
                d.revoke_token(tid)
                d.advance(10)
            r = d.force_request("C" if issuer else "A", "B", tid,
                                CAP2 if oosc else CAP, "orders/7",
                                "T9" if task else "T1", "no", d.now)
            return {"key": r.reason_code, "dec": r.decision}
        cases.append((f"order-rnd-{i}", run))
    return cases


# ==================================================== 族 4：重放与时效 =
def family_replay(rng, n=60):
    cases = []

    def run_basic(d):
        d.add_agent("A", "c", [f"{CAP}@orders/*"])
        d.add_agent("B", "w", [])
        tid = d.delegate("A", "B", [f"{CAP}@orders/*"], "T1")
        r1 = d.force_request("A", "B", tid, CAP, "orders/1", "T1", "dup", d.now)
        r2 = d.force_request("A", "B", tid, CAP, "orders/1", "T1", "dup", d.now)
        return {"first": r1.reason_code, "second": r2.reason_code,
                "eff1": r1.effects_delta, "eff2": r2.effects_delta}
    cases.append(("replay-samenonce", run_basic))

    def run_replay_obj(d):
        d.add_agent("A", "c", [f"{CAP}@orders/*"])
        d.add_agent("B", "w", [])
        tid = d.delegate("A", "B", [f"{CAP}@orders/*"], "T1")
        r1 = d.force_request("A", "B", tid, CAP, "orders/1", "T1", "obj", d.now)
        r2 = d.request("A", "B", tid, CAP, "orders/1", "T1", replay_last=True)
        return {"first": r1.reason_code, "second": r2.reason_code,
                "eff2": r2.effects_delta}
    cases.append(("replay-sameobject", run_replay_obj))

    def run_nonce_per_from(d):
        """不同发送方用同一 nonce：§3.2 步骤 1b 的键是 (from_id, nonce)。"""
        d.add_agent("A", "c", [f"{CAP}@orders/*"])
        for h in ("B", "C"):
            d.add_agent(h, "w", [])
        t1 = d.delegate("A", "B", [f"{CAP}@orders/*"], "T1")
        t2 = d.delegate("A", "C", [f"{CAP}@orders/*"], "T1")
        r1 = d.force_request("A", "B", t1, CAP, "orders/1", "T1", "same", d.now)
        r2 = d.force_request("A", "C", t2, CAP, "orders/1", "T1", "same", d.now)
        return {"b": r1.reason_code, "c": r2.reason_code}
    cases.append(("replay-crossfrom", run_nonce_per_from))

    # 时窗：ts 落后 now 多少仍被接受
    for age in (0, 1, 5, 10, 30, 49, 50, 51, 60, 100, 200, 301, 1000):
        def run(d, age=age):
            d.add_agent("A", "c", [f"{CAP}@orders/*"])
            d.add_agent("B", "w", [])
            tid = d.delegate("A", "B", [f"{CAP}@orders/*"], "T1")
            r = d.force_request("A", "B", tid, CAP, "orders/1", "T1",
                                f"age{age}", d.now - age)
            return {"key": r.reason_code}
        cases.append((f"window-age{age}", run))

    # 未来 ts（now - ts 为负）
    def run_future(d):
        d.add_agent("A", "c", [f"{CAP}@orders/*"])
        d.add_agent("B", "w", [])
        tid = d.delegate("A", "B", [f"{CAP}@orders/*"], "T1")
        r = d.force_request("A", "B", tid, CAP, "orders/1", "T1", "fut", d.now + 500)
        return {"key": r.reason_code}
    cases.append(("window-future", run_future))

    # 重放 + 时窗叠加：老 ts 的新 nonce
    def run_oldnew(d):
        d.add_agent("A", "c", [f"{CAP}@orders/*"])
        d.add_agent("B", "w", [])
        tid = d.delegate("A", "B", [f"{CAP}@orders/*"], "T1")
        r = d.force_request("A", "B", tid, CAP, "orders/1", "T1", "fresh", d.now - 10000)
        return {"key": r.reason_code}
    cases.append(("window-stale", run_oldnew))

    # 坏签名
    def run_badsig(d):
        d.add_agent("A", "c", [f"{CAP}@orders/*"])
        d.add_agent("B", "w", [])
        tid = d.delegate("A", "B", [f"{CAP}@orders/*"], "T1")
        r = d.force_request("A", "B", tid, CAP, "orders/1", "T1", "bs", d.now,
                            bad_sig=True)
        return {"key": r.reason_code, "eff": r.effects_delta}
    cases.append(("unsigned", run_badsig))

    for i in range(n):
        ages = rng.choice([0, 5, 40, 60, 300, 1000])
        dup = rng.random() < 0.5

        def run(d, ages=ages, dup=dup):
            d.add_agent("A", "c", [f"{CAP}@orders/*"])
            d.add_agent("B", "w", [])
            tid = d.delegate("A", "B", [f"{CAP}@orders/*"], "T1")
            r1 = d.force_request("A", "B", tid, CAP, "orders/1", "T1", "x", d.now - ages)
            n2 = "x" if dup else "y"
            r2 = d.force_request("A", "B", tid, CAP, "orders/1", "T1", n2, d.now - ages)
            return {"r1": r1.reason_code, "r2": r2.reason_code}
        cases.append((f"replay-rnd-{i}", run))
    return cases


# ==================================================== 族 5：撤销与凭证 =
def family_revocation(rng, n=40):
    cases = []

    def run_token(d):
        d.add_agent("A", "c", [f"{CAP}@orders/*"])
        d.add_agent("B", "w", [])
        tid = d.delegate("A", "B", [f"{CAP}@orders/*"], "T1")
        d.revoke_token(tid)
        r0 = d.force_request("A", "B", tid, CAP, "orders/1", "T1", "p0", d.now)
        d.advance(10)
        r1 = d.force_request("A", "B", tid, CAP, "orders/1", "T1", "p1", d.now)
        return {"pre": r0.reason_code, "post": r1.reason_code}
    cases.append(("revoke-token", run_token))

    def run_token_partition(d):
        d.add_agent("A", "c", [f"{CAP}@orders/*"])
        d.add_agent("B", "w", [])
        tid = d.delegate("A", "B", [f"{CAP}@orders/*"], "T1")
        d.set_partition(["B"])
        d.revoke_token(tid)
        out = {}
        for k in (10, 20, 40, 80):
            d.advance(10)
            out[f"t{int(d.now)}"] = d.force_request("A", "B", tid, CAP, "orders/1",
                                           "T1", f"q{k}", d.now).reason_code
        d.set_partition([])
        d.advance(10)
        out["after_rejoin"] = d.force_request("A", "B", tid, CAP, "orders/1",
                                              "T1", "qr", d.now).reason_code
        return out
    cases.append(("revoke-partition", run_token_partition))

    def run_ttl_cap(d):
        """分区下撤销拉不到，凭证最多再活 TTL（§3.3 / P3）。"""
        d.add_agent("A", "c", [f"{CAP}@orders/*"])
        d.add_agent("B", "w", [])
        tid = d.delegate("A", "B", [f"{CAP}@orders/*"], "T1", ttl=25)
        d.set_partition(["B"])
        d.revoke_token(tid)
        out = {}
        for k in (10, 10, 10, 10, 10):
            d.advance(k)
            out[f"t{int(d.now)}"] = d.force_request("A", "B", tid, CAP, "orders/1",
                                               "T1", f"z{d.now}", d.now).reason_code
        return out
    cases.append(("revoke-partition-ttl", run_ttl_cap))

    def run_subject(d):
        d.add_agent("A", "c", [f"{CAP}@orders/*"])
        for h in ("B", "C"):
            d.add_agent(h, "w", [])
        t1 = d.delegate("A", "B", [f"{CAP}@orders/*"], "T1")
        t2 = d.delegate("B", "C", [f"{CAP}@orders/*"], "T1", parent_token_id=t1)
        d.revoke_subject("B")
        d.advance(10)
        r1 = d.force_request("A", "B", t1, CAP, "orders/1", "T1", "s1", d.now)
        r2 = d.force_request("B", "C", t2, CAP, "orders/1", "T1", "s2", d.now)
        return {"to_B": r1.reason_code, "from_B": r2.reason_code}
    cases.append(("revoke-subject-B", run_subject))

    def run_subject_root(d):
        d.add_agent("A", "c", [f"{CAP}@orders/*"])
        d.add_agent("B", "w", [])
        t1 = d.delegate("A", "B", [f"{CAP}@orders/*"], "T1")
        d.revoke_subject("A")
        d.advance(10)
        return {"to_B": d.force_request("A", "B", t1, CAP, "orders/1",
                                        "T1", "r1", d.now).reason_code}
    cases.append(("revoke-subject-A", run_subject_root))

    def run_parent_revoked(d):
        d.add_agent("A", "c", [f"{CAP}@orders/*"])
        for h in ("B", "C"):
            d.add_agent(h, "w", [])
        t1 = d.delegate("A", "B", [f"{CAP}@orders/*"], "T1")
        t2 = d.delegate("B", "C", [f"{CAP}@orders/*"], "T1", parent_token_id=t1)
        d.revoke_token(t1)
        d.advance(10)
        r1 = d.force_request("A", "B", t1, CAP, "orders/1", "T1", "p1", d.now)
        r2 = d.force_request("B", "C", t2, CAP, "orders/1", "T1", "p2", d.now)
        return {"parent": r1.reason_code, "child": r2.reason_code}
    cases.append(("revoke-parent-child", run_parent_revoked))

    def run_ttl_expiry(d):
        d.add_agent("A", "c", [f"{CAP}@orders/*"])
        d.add_agent("B", "w", [])
        tid = d.delegate("A", "B", [f"{CAP}@orders/*"], "T1", ttl=20)
        out = {}
        for k in (10, 9, 1, 1, 1):
            d.advance(k)
            out[f"t{int(d.now)}"] = d.force_request("A", "B", tid, CAP, "orders/1",
                                               "T1", f"e{d.now}", d.now).reason_code
        return out
    cases.append(("ttl-expiry", run_ttl_expiry))

    # 凭证轮换 / 回滚
    def run_issue_grant(d):
        d.add_agent("A", "c", [f"{CAP}@orders/*"])
        d.add_agent("B", "w", [])
        tid = d.delegate("A", "B", [f"{CAP}@orders/*"], "T1")
        before = d.force_request("A", "B", tid, CAP, "orders/1", "T1", "g0", d.now)
        g = d.issue_grant("A", [f"{CAP}@orders/*"])
        after = d.force_request("A", "B", tid, CAP, "orders/1", "T1", "g1", d.now)
        return {"before": before.reason_code, "after_issue_grant": after.reason_code,
                "new_cred": g.cred_epoch}
    cases.append(("cred-issue-grant", run_issue_grant))

    def run_refresh_same(d):
        d.add_agent("A", "c", [f"{CAP}@orders/*"])
        d.add_agent("B", "w", [])
        tid = d.delegate("A", "B", [f"{CAP}@orders/*"], "T1")
        g = d.current_grant("A")
        ok, exc = safe(d.refresh_grant, "B", g)
        r = d.force_request("A", "B", tid, CAP, "orders/1", "T1", "g2", d.now)
        return {"refresh_ok": ok if exc is None else exc, "after": r.reason_code}
    cases.append(("cred-refresh-same", run_refresh_same))

    # 随机补充：撤销目标 × 推进量 × 分区 × ttl 的组合
    for i in range(45):
        rv = rng.choice(["token", "subject_holder", "subject_root", "none"])
        part = rng.random() < 0.4
        adv = rng.choice([0, 1, 5, 10, 11, 20, 30])
        ttl = rng.choice([50, 200, 1000])

        def run(d, rv=rv, part=part, adv=adv, ttl=ttl):
            d.add_agent("A", "c", [f"{CAP}@orders/*"])
            for h in ("B", "C"):
                d.add_agent(h, "w", [])
            t1 = d.delegate("A", "B", [f"{CAP}@orders/*"], "T1", ttl=ttl)
            t2 = d.delegate("B", "C", [f"{CAP}@orders/*"], "T1",
                            parent_token_id=t1, ttl=ttl)
            if part:
                d.set_partition(["B", "C"])
            if rv == "token":
                d.revoke_token(t1)
            elif rv == "subject_holder":
                d.revoke_subject("B")
            elif rv == "subject_root":
                d.revoke_subject("A")
            if adv:
                d.advance(adv)
            a = d.force_request("A", "B", t1, CAP, "orders/1", "T1", "ra", d.now)
            b = d.force_request("B", "C", t2, CAP, "orders/1", "T1", "rb", d.now)
            return {"t1": a.reason_code, "t2": b.reason_code,
                    "eff": a.effects_delta + b.effects_delta}
        cases.append((f"rev-rnd-{i}", run))
    return cases


# ==================================================== 族 6：复合动作 required =
def family_composite(rng, n=60):
    base_scope = [f"{CAP}@orders/*", f"{CAP2}@orders/*", "db.export@reports/**"]
    cases = []

    def run_all_in(d):
        d.add_agent("A", "c", base_scope)
        d.add_agent("B", "w", [])
        tid = d.delegate("A", "B", base_scope, "T1")
        r = d.force_request("A", "B", tid, CAP, "orders/1", "T1", "c1", d.now,
                            required=(f"{CAP2}@orders/1",))
        return {"key": r.reason_code, "eff": r.effects_delta}
    cases.append(("req-all-in", run_all_in))

    def run_partly_out(d):
        d.add_agent("A", "c", base_scope)
        d.add_agent("B", "w", [])
        tid = d.delegate("A", "B", [f"{CAP}@orders/*"], "T1")
        r = d.force_request("A", "B", tid, CAP, "orders/1", "T1", "c2", d.now,
                            required=(f"{CAP2}@orders/1",))
        return {"key": r.reason_code, "eff": r.effects_delta}
    cases.append(("req-partly-out", run_partly_out))

    def run_all_out(d):
        d.add_agent("A", "c", base_scope)
        d.add_agent("B", "w", [])
        tid = d.delegate("A", "B", [f"{CAP}@orders/*"], "T1")
        r = d.force_request("A", "B", tid, CAP, "orders/1", "T1", "c3", d.now,
                            required=("db.export@x/y",))
        return {"key": r.reason_code, "eff": r.effects_delta}
    cases.append(("req-all-out", run_all_out))

    def run_empty(d):
        d.add_agent("A", "c", base_scope)
        d.add_agent("B", "w", [])
        tid = d.delegate("A", "B", base_scope, "T1")
        r = d.force_request("A", "B", tid, CAP, "orders/1", "T1", "c4", d.now)
        return {"key": r.reason_code}
    cases.append(("req-empty", run_empty))

    def run_resource_wildcard(d):
        d.add_agent("A", "c", base_scope)
        d.add_agent("B", "w", [])
        tid = d.delegate("A", "B", base_scope, "T1")
        r = d.force_request("A", "B", tid, CAP, "orders/*", "T1", "c5", d.now)
        return {"key": r.reason_code}
    cases.append(("req-resource-star", run_resource_wildcard))

    for i in range(n):
        nreq = rng.randint(0, 4)
        reqs = tuple(rng.choice([f"{CAP}@orders/1", f"{CAP2}@orders/1",
                                 "db.export@reports/q3", "mail.send@x@y"])
                     for _ in range(nreq))
        tscope = rng.choice([base_scope, [f"{CAP}@orders/*"]])

        def run(d, reqs=reqs, tscope=tscope):
            d.add_agent("A", "c", base_scope)
            d.add_agent("B", "w", [])
            tid = d.delegate("A", "B", tscope, "T1")
            r = d.force_request("A", "B", tid, CAP, "orders/1", "T1", "cr",
                                d.now, required=reqs)
            return {"key": r.reason_code, "eff": r.effects_delta}
        cases.append((f"req-rnd-{i}", run))
    return cases


# ==================================================== 族 7：任务绑定 =
def family_task(rng, n=40):
    cases = []

    def run_mismatch(d):
        d.add_agent("A", "c", [f"{CAP}@orders/*"])
        d.add_agent("B", "w", [])
        tid = d.delegate("A", "B", [f"{CAP}@orders/*"], "T1")
        r = d.force_request("A", "B", tid, CAP, "orders/1", "T2", "t1", d.now)
        return {"key": r.reason_code, "eff": r.effects_delta}
    cases.append(("task-mismatch", run_mismatch))

    def run_match(d):
        d.add_agent("A", "c", [f"{CAP}@orders/*"])
        d.add_agent("B", "w", [])
        tid = d.delegate("A", "B", [f"{CAP}@orders/*"], "T1")
        r = d.force_request("A", "B", tid, CAP, "orders/1", "T1", "t2", d.now)
        return {"key": r.reason_code}
    cases.append(("task-match", run_match))

    def run_chain_task(d):
        d.add_agent("A", "c", [f"{CAP}@orders/*"])
        for h in ("B", "C"):
            d.add_agent(h, "w", [])
        t1 = d.delegate("A", "B", [f"{CAP}@orders/*"], "T1")
        t2 = d.delegate("B", "C", [f"{CAP}@orders/*"], "T2", parent_token_id=t1)
        a = d.force_request("A", "B", t1, CAP, "orders/1", "T1", "t3", d.now)
        b = d.force_request("B", "C", t2, CAP, "orders/1", "T1", "t4", d.now)
        c = d.force_request("B", "C", t2, CAP, "orders/1", "T2", "t5", d.now)
        return {"t1_T1": a.reason_code, "t2_T1": b.reason_code,
                "t2_T2": c.reason_code}
    cases.append(("task-chain", run_chain_task))

    def run_empty_task(d):
        d.add_agent("A", "c", [f"{CAP}@orders/*"])
        d.add_agent("B", "w", [])
        tid = d.delegate("A", "B", [f"{CAP}@orders/*"], "T1")
        r = d.force_request("A", "B", tid, CAP, "orders/1", "", "t6", d.now)
        return {"key": r.reason_code}
    cases.append(("task-empty", run_empty_task))

    for i in range(n):
        tok_task = rng.choice(["T1", "T2", ""])
        req_task = rng.choice(["T1", "T2", ""])

        def run(d, tok_task=tok_task, req_task=req_task):
            d.add_agent("A", "c", [f"{CAP}@orders/*"])
            d.add_agent("B", "w", [])
            tid = d.delegate("A", "B", [f"{CAP}@orders/*"], tok_task)
            r = d.force_request("A", "B", tid, CAP, "orders/1", req_task, "tr",
                                d.now)
            return {"key": r.reason_code}
        cases.append((f"task-rnd-{i}", run))
    return cases


ALL_FAMILIES = {
    "F2-attenuation": lambda rng: family_attenuation(rng, 60),
    "F3-order": lambda rng: family_order(rng, 40),
    "F4-replay": lambda rng: family_replay(rng, 60),
    "F5-revocation": lambda rng: family_revocation(rng, 20),
    "F6-composite": lambda rng: family_composite(rng, 60),
    "F7-task": lambda rng: family_task(rng, 40),
    # 第二轮新增：专测四条新钉死的规则
    "F8-empty-segment": lambda rng: family_empty_segment(rng, 60),
    "F9-window": lambda rng: family_window(rng, 60),
    "F10-refresh": lambda rng: family_refresh(rng, 40),
    "F11-verify-order": lambda rng: family_verify_order(rng, 30),
    "F12-random-walk": lambda rng: family_random_walk(rng, 240, 50),
    "F13-clock-skew": lambda rng: family_clock_skew(rng),
}


# ============================================ 族 8：§2.8 段不得为空 + 自洽性 =
# 规格 §2.8（差分测试后钉死）的边界清单：前导 /、尾随 /、连续 //、空串。
DEGENERATE_CASES = [
    ("a", "a"), ("a", "a/"), ("a", "/a"), ("a", "a//"), ("a", "/a/"), ("a", "//a"),
    ("a/*", "a/"), ("a/*", "a/b"), ("a/*", "a//b"), ("a/*", "a/b/"),
    ("*", ""), ("*", "/"), ("*", "a"), ("*", "a/"),
    ("", ""), ("", "/"), ("", "a/"), ("**", ""), ("**", "//"), ("**", "a//b"),
    ("a/**", "a"), ("a/**", "a/"), ("a/**", "a/b"), ("a/**", "a//b"),
    ("*/**", "a"), ("*/**", "a/"), ("*/**", "/a"),
    ("a/b", "a//b"), ("a/b", "a/b/"), ("a/b", "a/b"),
    ("*/*", "a/"), ("*/*", "a/b"), ("*/*", "/a"),
]


def family_empty_segment(rng, n=60):
    """§2.8「段不得为空」：穷举 + 自洽性 + 系统级三路交叉。"""
    cases = []

    # (a) 逐条边界
    for i, (pat, res) in enumerate(DEGENERATE_CASES):
        def run(d, pat=pat, res=res):
            return {"k": S_sys_matches(d, pat, res).decision}
        cases.append((f"empty-edge-{i}", run))

    # (b) 随机组合（含退化资源）
    pats = gen_patterns()
    degen = ["", "/", "//", "a/", "/a", "a//", "/a/", "a//b", "a/b/"]
    for i in range(n):
        pat = rng.choice(pats)
        res = rng.choice(degen + ["a", "b", "a/b", "a/b/c", "A"])

        def run(d, pat=pat, res=res):
            return {"k": S_sys_matches(d, pat, res).decision}
        cases.append((f"empty-rnd-{i}", run))

    # (c) 无条件模式下退化资源必须放行
    for i in range(20):
        res = rng.choice(degen)

        def run(d, res=res):
            out = {}
            for pat in ("", "**"):
                out[pat] = S_sys_matches(d, pat, res).decision
            return out
        cases.append((f"empty-uncond-{i}", run))
    return cases


def S_sys_matches(d, pattern, resource):
    """系统级 matches 探针：把 `cap@pattern` 放进令牌范围，观察请求判定。"""
    d.add_agent("A", "c", [f"{CAP}@{pattern}"])
    d.add_agent("B", "w", [])
    tid = d.delegate("A", "B", [f"{CAP}@{pattern}"], "T1")
    return d.force_request("A", "B", tid, CAP, resource, "T1", "nm", d.now)


# ================================================ 族 9：§3.2 双向时效窗口 =
WINDOW_OFFSETS = [0, 1, 25, 49, 50, 51, 60, 100, 300, 1000,
                  -1, -5, -49, -50, -100, -500, -1_000_000]


def family_window(rng, n=60):
    cases = []
    for off in WINDOW_OFFSETS:
        def run(d, off=off):
            d.add_agent("A", "c", [f"{CAP}@orders/*"])
            d.add_agent("B", "w", [])
            tid = d.delegate("A", "B", [f"{CAP}@orders/*"], "T1")
            r = d.force_request("A", "B", tid, CAP, "orders/1", "T1",
                                f"w{off}", d.now - off)
            return {"key": r.reason_code, "eff": r.effects_delta}
        cases.append((f"win-{off}", run))
    for i in range(n):
        off = rng.choice(WINDOW_OFFSETS)

        def run(d, off=off):
            d.add_agent("A", "c", [f"{CAP}@orders/*"])
            d.add_agent("B", "w", [])
            tid = d.delegate("A", "B", [f"{CAP}@orders/*"], "T1")
            r = d.force_request("A", "B", tid, CAP, "orders/1", "T1",
                                f"r{off}", d.now - off)
            return {"key": r.reason_code, "eff": r.effects_delta}
        cases.append((f"win-rnd-{i}", run))
    # 时钟推进后再看窗口：ts 固定为签发时刻
    def run_adv(d):
        d.add_agent("A", "c", [f"{CAP}@orders/*"])
        d.add_agent("B", "w", [])
        tid = d.delegate("A", "B", [f"{CAP}@orders/*"], "T1")
        ts = d.now
        out = {}
        for k in (10, 20, 20, 10):
            d.advance(k)
            out[f"t{int(d.now)}"] = d.force_request(
                "A", "B", tid, CAP, "orders/1", "T1", f"a{d.now}", ts).reason_code
        return out
    cases.append(("win-advance", run_adv))
    return cases


# ============================================ 族 10：§5 凭证刷新语义全序列 =
def family_refresh(rng, n=40):
    cases = []

    def run_seq(d):
        d.add_agent("A", "c", [f"{CAP}@orders/*"])
        d.add_agent("B", "w", [])
        t1 = d.delegate("A", "B", [f"{CAP}@orders/*"], "T1")
        out = {}
        out["s0_oldtok_none_refreshed"] = d.force_request(
            "A", "B", t1, CAP, "orders/1", "T1", "a", d.now).reason_code
        g2 = d.issue_grant("A", [f"{CAP}@orders/*"])
        out["s1_oldtok_issued_not_refreshed"] = d.force_request(
            "A", "B", t1, CAP, "orders/1", "T1", "b", d.now).reason_code
        r, exc = safe(d.delegate, "A", "B", [f"{CAP}@orders/*"], "T1")
        out["s1b_A_derives_old_root"] = "ACCEPT" if r else f"DENY/{exc}"
        out["s2_refresh_B"] = d.refresh_grant("B", g2)
        out["s2_oldtok_at_B"] = d.force_request(
            "A", "B", t1, CAP, "orders/1", "T1", "c", d.now).reason_code
        r, exc = safe(d.delegate, "A", "B", [f"{CAP}@orders/*"], "T1")
        out["s2b_A_derives_after_B_refresh"] = "ACCEPT" if r else f"DENY/{exc}"
        out["s3_A_refresh_own"] = d.refresh_grant("A", g2)
        r, exc = safe(d.delegate, "A", "B", [f"{CAP}@orders/*"], "T2")
        out["s3b_A_derives_new_root"] = "ACCEPT" if r else f"DENY/{exc}"
        if r:
            out["s3c_newtok"] = d.force_request(
                "A", "B", r, CAP, "orders/1", "T2", "d", d.now).reason_code
        out["s3d_oldtok_still_stale"] = d.force_request(
            "A", "B", t1, CAP, "orders/1", "T1", "e", d.now).reason_code
        return out
    cases.append(("refresh-seq-AB", run_seq))

    # 只刷新 A（B 未刷新）：旧根令牌在 B 仍有效
    def run_only_A(d):
        d.add_agent("A", "c", [f"{CAP}@orders/*"])
        d.add_agent("B", "w", [])
        t1 = d.delegate("A", "B", [f"{CAP}@orders/*"], "T1")
        g2 = d.issue_grant("A", [f"{CAP}@orders/*"])
        d.refresh_grant("A", g2)
        out = {"oldtok_at_B": d.force_request(
            "A", "B", t1, CAP, "orders/1", "T1", "a", d.now).reason_code}
        tid, exc = safe(d.delegate, "A", "B", [f"{CAP}@orders/*"], "T1")
        out["A_derive"] = "ACCEPT" if tid else f"DENY/{exc}"
        if tid:
            out["newtok_at_B"] = d.force_request(
                "A", "B", tid, CAP, "orders/1", "T1", "b", d.now).reason_code
        return out
    cases.append(("refresh-only-A", run_only_A))

    # 只刷新 B
    def run_only_B(d):
        d.add_agent("A", "c", [f"{CAP}@orders/*"])
        d.add_agent("B", "w", [])
        t1 = d.delegate("A", "B", [f"{CAP}@orders/*"], "T1")
        g2 = d.issue_grant("A", [f"{CAP}@orders/*"])
        d.refresh_grant("B", g2)
        out = {"oldtok_at_B": d.force_request(
            "A", "B", t1, CAP, "orders/1", "T1", "a", d.now).reason_code}
        tid, exc = safe(d.delegate, "A", "B", [f"{CAP}@orders/*"], "T1")
        out["A_derive_old_root"] = "ACCEPT" if tid else f"DENY/{exc}"
        return out
    cases.append(("refresh-only-B", run_only_B))

    # 三跳：C 刷新后拒绝锚在旧根的令牌
    def run_three_hop(d):
        d.add_agent("A", "c", [f"{CAP}@orders/*"])
        for h in ("B", "C"):
            d.add_agent(h, "w", [])
        t1 = d.delegate("A", "B", [f"{CAP}@orders/*"], "T1")
        t2 = d.delegate("B", "C", [f"{CAP}@orders/*"], "T1", parent_token_id=t1)
        g2 = d.issue_grant("A", [f"{CAP}@orders/*"])
        out = {"before": d.force_request(
            "B", "C", t2, CAP, "orders/1", "T1", "a", d.now).reason_code}
        d.refresh_grant("C", g2)
        out["after_C_refresh"] = d.force_request(
            "B", "C", t2, CAP, "orders/1", "T1", "b", d.now).reason_code
        d.refresh_grant("B", g2)
        out["after_B_refresh"] = d.force_request(
            "B", "C", t2, CAP, "orders/1", "T1", "c", d.now).reason_code
        return out
    cases.append(("refresh-three-hop", run_three_hop))

    # 随机：刷新顺序 × 是否刷新
    for i in range(n):
        ra = rng.random() < 0.5
        rb = rng.random() < 0.5
        adv = rng.choice([0, 1, 10])

        def run(d, ra=ra, rb=rb, adv=adv):
            d.add_agent("A", "c", [f"{CAP}@orders/*"])
            d.add_agent("B", "w", [])
            t1 = d.delegate("A", "B", [f"{CAP}@orders/*"], "T1")
            g2 = d.issue_grant("A", [f"{CAP}@orders/*"])
            if ra:
                d.refresh_grant("A", g2)
            if rb:
                d.refresh_grant("B", g2)
            if adv:
                d.advance(adv)
            out = {"oldtok": d.force_request(
                "A", "B", t1, CAP, "orders/1", "T1", "a", d.now).reason_code}
            tid, exc = safe(d.delegate, "A", "B", [f"{CAP}@orders/*"], "T1")
            out["derive"] = "ACCEPT" if tid else f"DENY/{exc}"
            if tid:
                out["newtok"] = d.force_request(
                    "A", "B", tid, CAP, "orders/1", "T1", "b", d.now).reason_code
            return out
        cases.append((f"refresh-rnd-{i}", run))
    return cases


# =================================== 族 11：撤销 / 过期 / 密钥作废的优先级矩阵 =
def family_verify_order(rng, n=None):
    cases = []
    for rev in (False, True):
        for exp in (False, True):
            for key in (False, True):
                def run(d, rev=rev, exp=exp, key=key):
                    d.add_agent("A", "c", [f"{CAP}@orders/*"])
                    d.add_agent("B", "w", [])
                    ttl = 5 if exp else 1000
                    tid = d.delegate("A", "B", [f"{CAP}@orders/*"], "T1", ttl=ttl)
                    if rev:
                        d.revoke_token(tid)
                    if key:
                        d.revoke_key_epoch("A", 1)
                    if rev or exp:
                        d.advance(50)
                    r = d.force_request("A", "B", tid, CAP, "orders/1", "T1",
                                        "k", d.now)
                    return {"key": r.reason_code, "dec": r.decision}
                cases.append((f"order-rev{int(rev)}-exp{int(exp)}-key{int(key)}",
                              run))
    # 撤销与过期叠加在更复杂的违规上
    for i in range(30):
        exp = rng.random() < 0.7
        task = rng.random() < 0.5
        scope = rng.random() < 0.5

        def run(d, exp=exp, task=task, scope=scope):
            d.add_agent("A", "c", [f"{CAP}@orders/*", f"{CAP2}@orders/*"])
            d.add_agent("B", "w", [])
            ttl = 5 if exp else 1000
            tid = d.delegate("A", "B", [f"{CAP}@orders/*"], "T1", ttl=ttl)
            d.revoke_token(tid)
            d.advance(50)
            r = d.force_request("A", "B", tid, CAP2 if scope else CAP, "orders/1",
                                "T9" if task else "T1", "m", d.now)
            return {"key": r.reason_code}
        cases.append((f"order-mix-{i}", run))
    return cases


# ===================== 族 12：随机操作序列（状态机差分，用于发现未编入的规则）=
WALK_SCOPE_VOCAB = [
    "order.read@orders/*", "order.read@orders/**", "order.read@orders/7",
    "order.read@**", "order.write@orders/*", "db.export@reports/**",
    "order.read@orders/7/x", "order.read",
]
WALK_CAPS = [("order.read", "orders/1"), ("order.read", "orders/7"),
             ("order.write", "orders/1"), ("db.export", "reports/q3"),
             ("order.read", "orders/7/x"), ("order.read", "orders/")]


def _gen_ops(rng, steps):
    ops = []
    agents = ["A", "B", "C"]
    toknames = []
    grantnames = []
    for _ in range(steps):
        choice = rng.random()
        if choice < 0.10:
            ops.append(("add", rng.choice(agents), random_scope(rng)))
        elif choice < 0.30:
            to = rng.choice(agents)
            parent = rng.choice([None] + toknames) if toknames else None
            frm = rng.choice(agents)
            ops.append(("delegate", frm, to, random_scope(rng),
                        rng.choice(["T1", "T2"]),
                        rng.choice([None, 50, 200, 1000]), parent,
                        rng.random() < 0.85))
            toknames.append(f"t{len(toknames)}")
        elif choice < 0.52:
            if not toknames:
                continue
            cap, res = rng.choice(WALK_CAPS)
            ops.append(("request", rng.choice(agents), rng.choice(agents),
                        rng.choice(toknames), cap, res,
                        rng.choice(["T1", "T2"]),
                        rng.choice([0, 1, 25, 50, 51, 100, -1, -50, -500])))
        elif choice < 0.60:
            if toknames:
                ops.append(("revoke_token", rng.choice(toknames)))
        elif choice < 0.66:
            ops.append(("revoke_subject", rng.choice(agents)))
        elif choice < 0.72:
            ops.append(("revoke_key", rng.choice(agents), rng.choice([0, 1, 2])))
        elif choice < 0.80:
            ops.append(("issue_grant", rng.choice(agents), random_scope(rng)))
            grantnames.append(f"g{len(grantnames)}")
        elif choice < 0.88:
            if grantnames:
                ops.append(("refresh", rng.choice(agents),
                            rng.choice(grantnames)))
        elif choice < 0.95:
            ops.append(("advance", rng.choice([1, 5, 10, 11, 20, 50])))
        else:
            ops.append(("partition", rng.sample(agents, rng.randint(0, 2))))
    return ops


def _exec_ops(d, ops):
    trace = {}
    tokens = {}
    root_of = {}
    tctr = 0
    grants = {}
    for k, op in enumerate(ops):
        try:
            kind = op[0]
            if kind == "add":
                _, sid, scope = op
                if d.has_agent(sid):
                    trace[k] = "skip"
                    continue
                d.add_agent(sid, "w", scope)
                trace[k] = "ok"
            elif kind == "delegate":
                _, frm, to, scope, task, ttl, parent, redel = op
                if not (d.has_agent(to) and d.has_agent(frm)):
                    trace[k] = "skip"
                    continue
                pid = tokens.get(parent) if parent else None
                try:
                    tid = d.delegate(frm, to, scope, task, ttl, pid, redel)
                    if parent:
                        root_of[tid] = root_of.get(parent, None)
                    tokens[f"t{tctr}"] = tid
                    tctr += 1
                    info = d.token_info(tid)
                    trace[k] = (info["scope"], info["depth"],
                                info["holder_id"], info["redelegatable"])
                except Denied as e:
                    trace[k] = f"DENY/{e.reason_code}"
            elif kind == "request":
                _, frm, to, tok, cap, res, task, off = op
                if not (d.has_agent(to) and d.has_agent(frm)) or tok not in tokens:
                    trace[k] = "skip"
                    continue
                r = d.force_request(frm, to, tokens[tok], cap, res, task,
                                    f"w{k}", d.now - off)
                trace[k] = (r.decision, r.reason_code, r.effects_delta)
            elif kind == "revoke_token":
                if op[1] in tokens:
                    d.revoke_token(tokens[op[1]])
                trace[k] = "ok"
            elif kind == "revoke_subject":
                if not d.has_agent(op[1]):
                    trace[k] = "skip"
                    continue
                d.revoke_subject(op[1])
                trace[k] = "ok"
            elif kind == "revoke_key":
                if not d.has_agent(op[1]):
                    trace[k] = "skip"
                    continue
                d.revoke_key_epoch(op[1], op[2])
                trace[k] = "ok"
            elif kind == "issue_grant":
                _, sid, scope = op
                if not d.has_agent(sid):
                    trace[k] = "skip"
                    continue
                grants[f"g{len(grants)}"] = d.issue_grant(sid, scope)
                trace[k] = "ok"
            elif kind == "refresh":
                _, sid, gname = op
                if gname not in grants or not d.has_agent(sid):
                    trace[k] = "skip"
                    continue
                trace[k] = bool(d.refresh_grant(sid, grants[gname]))
            elif kind == "advance":
                d.advance(op[1])
                trace[k] = int(d.now)
            elif kind == "partition":
                d.set_partition(op[1])
                trace[k] = "ok"
        except Denied as e:
            trace[k] = f"DENY/{e.reason_code}"
        except Exception as e:                                # noqa: BLE001
            trace[k] = f"EXC:{type(e).__name__}"
    trace["n_effects"] = d.n_effects
    trace["n_receipts"] = d.n_receipts
    trace["effects"] = sorted(d.effects())
    return trace


def family_random_walk(rng, n=60, steps=40):
    cases = []
    for i in range(n):
        ops = _gen_ops(rng, steps)

        def run(d, ops=ops):
            return _exec_ops(d, ops)
        cases.append((f"walk-{i}", run))
    return cases


# ============================= 族 13：§3.2 双向窗口与 clock_skew（规格未提）=
def family_clock_skew(rng, n=60):
    """规格 §3.2 钉死 `0 ≤ now - ts ≤ max_request_age`，未提时钟偏移。
    参考实现的窗口是 `-clock_skew ≤ now - ts ≤ max_request_age`。"""
    cases = []
    for skew in (0, 1, 5, 30):
        for off in (0, -1, -5, -30, -31, 50, 51):
            def run(d, skew=skew, off=off):
                d.add_agent("A", "c", [f"{CAP}@orders/*"])
                d.add_agent("B", "w", [])
                tid = d.delegate("A", "B", [f"{CAP}@orders/*"], "T1")
                d.set_clock_skew(skew)
                r = d.force_request("A", "B", tid, CAP, "orders/1", "T1",
                                    f"k{skew}_{off}", d.now - off)
                return {"key": r.reason_code}
            cases.append((f"skew{skew}-off{off}", run))
    for i in range(n):
        skew = rng.choice([0, 1, 5, 30])
        off = rng.choice([0, -1, -5, -30, -31, 25, 50, 51])

        def run(d, skew=skew, off=off):
            d.add_agent("A", "c", [f"{CAP}@orders/*"])
            d.add_agent("B", "w", [])
            tid = d.delegate("A", "B", [f"{CAP}@orders/*"], "T1")
            d.set_clock_skew(skew)
            r = d.force_request("A", "B", tid, CAP, "orders/1", "T1",
                                f"r{skew}_{off}", d.now - off)
            return {"key": r.reason_code}
        cases.append((f"skew-rnd-{i}", run))
    return cases
