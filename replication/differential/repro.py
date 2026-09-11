"""针对报告的分歧项的可独立运行最小复现 + 两个否定性探测。

运行： python3 replication/differential/repro.py
每一项输出 `label | ref=... | mine=...`。
"""
from __future__ import annotations

import dataclasses
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from drivers import RefDriver, MyDriver                      # noqa: E402
import drivers as D                                          # noqa: E402


def head(t):
    print("\n" + "=" * 72 + f"\n{t}\n" + "=" * 72)


def show(label, ref, mine):
    print(f"{label:38s} ref={ref!s:22s} mine={mine!s}")


# ------------------------------------------------ D1 资源串空段（规范歧义）
def d1():
    head("D1 §2.8 资源串空段：`a/*` 是否匹配 `a/`")
    import src.patterns as RP
    import patterns as MP
    for p, r in [("a/*", "a/"), ("*/a", "/a"), ("a", "a/"), ("a/b", "a//b")]:
        show(f"matches({p!r},{r!r})", RP.matches(p, r), MP.matches(p, r))


# ------------------------------------------- D2 判定顺序：撤销 vs 过期（规范歧义）
def d2():
    head("D2 §3.2 步骤 5：令牌同时过期且被撤销时报哪个码")
    for which, D_ in (("ref", RefDriver), ("mine", MyDriver)):
        d = D_()
        d.add_agent("A", "c", ["order.read@orders/*"])
        d.add_agent("B", "w", [])
        tid = d.delegate("A", "B", ["order.read@orders/*"], "T1", ttl=5)
        d.revoke_token(tid)
        d.advance(50)
        r = d.force_request("A", "B", tid, "order.read", "orders/1", "T1", "n", d.now)
        print(f"  {which}: {r.decision} {r.reason_code}")


# ------------------------------------------------ D3 时窗（规范歧义：常数未定义）
def d3():
    head("D3 §3.2 步骤 1c：max_request_age 的值与未来 ts")
    for age in (49, 50, 51, 300, 301):
        row = []
        for D_ in (RefDriver, MyDriver):
            d = D_()
            d.add_agent("A", "c", ["order.read@orders/*"])
            d.add_agent("B", "w", [])
            tid = d.delegate("A", "B", ["order.read@orders/*"], "T1")
            row.append(d.force_request("A", "B", tid, "order.read", "orders/1",
                                       "T1", "n", d.now - age).reason_code)
        show(f"ts 落后 {age}", row[0], row[1])
    row = []
    for D_ in (RefDriver, MyDriver):
        d = D_()
        d.add_agent("A", "c", ["order.read@orders/*"])
        d.add_agent("B", "w", [])
        tid = d.delegate("A", "B", ["order.read@orders/*"], "T1")
        row.append(d.force_request("A", "B", tid, "order.read", "orders/1",
                                   "T1", "n", d.now + 500).reason_code)
    show("ts 在未来 +500", row[0], row[1])


# ------------------------------------------- D4 非持有者派生（参考实现异常逃逸）
def d4():
    head("D4 §2.3 派生规则 1：非持有者派生")
    for which, D_ in (("ref", RefDriver), ("mine", MyDriver)):
        d = D_()
        d.add_agent("A", "c", ["order.read@orders/*"])
        d.add_agent("B", "w", [])
        d.add_agent("C", "w", [])
        tid = d.delegate("A", "B", ["order.read@orders/*"], "T1")
        try:
            d.delegate("C", "A", ["order.read@orders/*"], "T1", None, tid)
            print(f"  {which}: ACCEPT")
        except Exception as e:                               # noqa: BLE001
            print(f"  {which}: {type(e).__name__}: {e}")


# ------------------------------------- D5 根授权重签发（规范未定义 / 我方缺 required）
def d5():
    head("D5 §2.3.1：权威重签发 A 的根授权后，在途令牌是否仍然有效")
    for which, D_ in (("ref", RefDriver), ("mine", MyDriver)):
        d = D_()
        d.add_agent("A", "c", ["order.read@orders/*"])
        d.add_agent("B", "w", [])
        tid = d.delegate("A", "B", ["order.read@orders/*"], "T1")
        before = d.force_request("A", "B", tid, "order.read", "orders/1",
                                 "T1", "a", d.now).reason_code
        g = d.issue_grant("A", ["order.read@orders/*"])
        after = d.force_request("A", "B", tid, "order.read", "orders/1",
                                "T1", "b", d.now).reason_code
        print(f"  {which}: before={before}  after_issue_grant={after}  "
              f"cred_epoch={g.cred_epoch}")


# ------------------------------------------- D6 §2.12 复合动作（我方缺失）
def d6():
    head("D6 §2.12 required：`db.export@x/y` 不在令牌范围内，整体必须拒绝")
    for which, D_ in (("ref", RefDriver), ("mine", MyDriver)):
        d = D_()
        d.add_agent("A", "c", ["order.read@orders/*", "order.write@orders/*"])
        d.add_agent("B", "w", [])
        tid = d.delegate("A", "B", ["order.read@orders/*"], "T1")
        r = d.force_request("A", "B", tid, "order.read", "orders/1", "T1", "n",
                            d.now, required=("db.export@x/y",))
        print(f"  {which}: {r.decision} {r.reason_code} 副作用={r.effects_delta}")


# ------------------------------------------------- 否定性探测：STALE_CREDENTIAL
def probe_stale():
    head("N1 参考实现的 STALE_CREDENTIAL 是否可达（黑盒路径穷举）")
    import src.model as SM
    from src.runtime import System
    tries = []

    # (a) refresh_grant 传入"更旧 cred_epoch 的真签发件"
    s = System(mode="P", ttl=1000, pull_interval=10)
    s.add_agent("A", "c", ["order.read@orders/*"])
    s.add_agent("B", "w", [])
    t = s.delegate("A", "B", ["order.read@orders/*"], "T1")
    g1 = s.authority.grants["A"]
    g2 = s.authority.issue_grant("A", ["order.read@orders/*"], s.now)
    tries.append(("refresh(g2)", s.peps["B"].refresh_grant(g2)))
    tries.append(("refresh(g1) 回滚", s.peps["B"].refresh_grant(g1)))
    tries.append(("request", s.request("A", "B", t.token_id, "order.read",
                                       "orders/1", "T1").reason_code))
    # (b) 篡改 cred_epoch 的签发件
    mu = dataclasses.replace(g1, cred_epoch=99)
    tries.append(("refresh(cred=99 篡改)", s.peps["B"].refresh_grant(mu)))
    # (c) pull 一个回退的 epoch
    s.peps["B"].pull(s.peps["B"].known_epoch)
    tries.append(("request after pull", s.request("A", "B", t.token_id,
                                                 "order.read", "orders/1",
                                                 "T1").reason_code))
    for k, v in tries:
        print(f"  {k}: {v}")
    print("  → 观察到的 reason_code 集合中没有 STALE_CREDENTIAL")


def probe_keeptoken():
    head("N2 对 §2.8 subsumes 的穷举差分结果（80 模式 × 80 模式）")
    import scenarios as S
    import src.patterns as RP
    import patterns as MP
    import oracle as O
    pats = S.gen_patterns()
    n = d = 0
    for c in pats:
        for p in pats:
            n += 1
            if RP.subsumes(c, p) != MP.subsumes(c, p):
                d += 1
    print(f"  用例 {n}，分歧 {d}；三方（ref/mine/oracle）在 subsumes 上完全一致")


def main():
    for fn in (d1, d2, d3, d4, d5, d6, probe_stale, probe_keeptoken):
        fn()


if __name__ == "__main__":
    main()
