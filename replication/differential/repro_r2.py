"""第二轮差分：剩余分歧的最小复现 + 已消除分歧的回归确认。

运行： python3 replication/differential/repro_r2.py
"""
from __future__ import annotations

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from drivers import RefDriver, MyDriver, Denied                # noqa: E402
import scenarios as S                                          # noqa: E402


def head(t):
    print("\n" + "=" * 74 + f"\n{t}\n" + "=" * 74)


def show(label, ref, mine, width=34):
    mark = "  " if ref == mine else "**"
    print(f"{mark}{label:{width}s} ref={ref!s:24s} mine={mine}")


# ------------------------------------------------- E1 密钥作废 与 过期 的优先级
def e1():
    head("E1 §2.3「撤销→过期→密钥作废」：令牌同时密钥作废且过期时报哪个码")
    for rev in (0, 1):
        for exp in (0, 1):
            for key in (0, 1):
                row = []
                for D in (RefDriver, MyDriver):
                    d = D()
                    d.add_agent("A", "c", ["order.read@orders/*"])
                    d.add_agent("B", "w", [])
                    ttl = 5 if exp else 1000
                    t = d.delegate("A", "B", ["order.read@orders/*"], "T1", ttl=ttl)
                    if rev:
                        d.revoke_token(t)
                    if key:
                        d.revoke_key_epoch("A", 1)
                    if rev or exp or key:
                        d.advance(50)
                    row.append(d.force_request("A", "B", t, "order.read",
                                               "orders/1", "T1", "n",
                                               d.now).reason_code)
                show(f"rev={rev} exp={exp} key={key}", row[0], row[1])


# --------------------------------------------- E2 派生拒绝的优先级（规格未规定）
def e2():
    head("E2 §2.3 派生规则：父令牌已封条 且 子范围越界，报哪个码")
    row = []
    for D in (RefDriver, MyDriver):
        d = D()
        d.add_agent("A", "c", ["order.read@orders/*"])
        for h in ("B", "C"):
            d.add_agent(h, "w", [])
        tid = d.delegate("A", "B", ["order.read@orders/*"], "T1", None, None, False)
        try:
            d.delegate("B", "C", ["order.write@orders/*"], "T1", None, tid, True)
            row.append("ACCEPT")
        except Denied as e:
            row.append(f"DENY/{e.reason_code}")
    show("封条 + 越界范围", row[0], row[1])


# ------------------------------------- E3 派生者是否保留自己所授令牌的副本
def e3():
    head("E3 §3.1/§2.3.1：派生者（issuer）本地是否留有该令牌的副本")
    for D in (RefDriver, MyDriver):
        d = D()
        d.add_agent("A", "c", ["order.read@orders/*"])
        for h in ("B", "C"):
            d.add_agent(h, "w", [])
        t = d.delegate("A", "B", ["order.read@orders/*"], "T1")
        # A 是 issuer；A→A 用该令牌请求自己
        r = d.force_request("A", "A", t, "order.read", "orders/1", "T1", "n", d.now)
        print(f"  {D.__name__}: A→A(自身) 用 A 授给 B 的令牌 -> {r.decision} {r.reason_code}")
    # 语义等价的显式探针：A 是否 hold t
    for D in (RefDriver, MyDriver):
        d = D()
        d.add_agent("A", "c", ["order.read@orders/*"])
        d.add_agent("B", "w", [])
        t = d.delegate("A", "B", ["order.read@orders/*"], "T1")
        holds = None
        if hasattr(d, "s"):
            holds = t in d.s.peps["A"].tokens
        else:
            holds = t in d.peps["A"].store
        print(f"  {D.__name__}: 派生者 A 的本地令牌库含该令牌 = {holds}")


# ------------------------------------------- E4/E5/E6 已消除分歧的回归确认
def e4_removed():
    head("E4 已消除：§2.8 空段规则（含 subsumes 自洽性）")
    import src.patterns as RP
    import patterns as MP
    cases = [("a", "a/"), ("a", "/a"), ("a", "a//"), ("a/*", "a/"), ("*", ""),
             ("", "/"), ("**", "a//b"), ("a/**", "a/")]
    bad = 0
    for p, r in cases:
        a, b = RP.matches(p, r), MP.matches(p, r)
        if a != b:
            bad += 1
        show(f"matches({p!r},{r!r})", a, b)
    print(f"  不一致 {bad} 条")


def e5_removed():
    head("E5 已消除：判定顺序（撤销优先于过期）与双向时效窗口")
    row = []
    for D in (RefDriver, MyDriver):
        d = D()
        d.add_agent("A", "c", ["order.read@orders/*"])
        d.add_agent("B", "w", [])
        t = d.delegate("A", "B", ["order.read@orders/*"], "T1", ttl=5)
        d.revoke_token(t)
        d.advance(50)
        row.append(d.force_request("A", "B", t, "order.read", "orders/1",
                                   "T1", "n", d.now).reason_code)
    show("撤销 + 过期", row[0], row[1])
    for off in (50, 51, 300, -1, -500):
        row = []
        for D in (RefDriver, MyDriver):
            d = D()
            d.add_agent("A", "c", ["order.read@orders/*"])
            d.add_agent("B", "w", [])
            t = d.delegate("A", "B", ["order.read@orders/*"], "T1")
            row.append(d.force_request("A", "B", t, "order.read", "orders/1",
                                       "T1", f"w{off}", d.now - off).reason_code)
        show(f"now-ts={off}", row[0], row[1])


def e6_removed():
    head("E6 已消除：§5 凭证刷新语义全序列")
    def seq(D):
        d = D()
        d.add_agent("A", "c", ["order.read@orders/*"])
        d.add_agent("B", "w", [])
        t1 = d.delegate("A", "B", ["order.read@orders/*"], "T1")
        out = [d.force_request("A", "B", t1, "order.read", "orders/1",
                               "T1", "a", d.now).reason_code]
        g2 = d.issue_grant("A", ["order.read@orders/*"])
        out.append(d.force_request("A", "B", t1, "order.read", "orders/1",
                                   "T1", "b", d.now).reason_code)
        out.append(bool(d.refresh_grant("B", g2)))
        out.append(d.force_request("A", "B", t1, "order.read", "orders/1",
                                   "T1", "c", d.now).reason_code)
        out.append(bool(d.refresh_grant("A", g2)))
        t2 = d.delegate("A", "B", ["order.read@orders/*"], "T2")
        out.append(d.force_request("A", "B", t2, "order.read", "orders/1",
                                   "T2", "d", d.now).reason_code)
        out.append(d.force_request("A", "B", t1, "order.read", "orders/1",
                                   "T1", "e", d.now).reason_code)
        return out
    a, b = seq(RefDriver), seq(MyDriver)
    labels = ["未刷新时旧令牌", "issue 后旧令牌", "B 刷新返回值", "B 刷新后旧令牌",
              "A 刷新返回值", "A 刷新后新令牌", "旧令牌仍被拒"]
    for l, x, y in zip(labels, a, b):
        show(l, x, y)


def main():
    for fn in (e1, e2, e3, e4_removed, e5_removed, e6_removed):
        fn()


if __name__ == "__main__":
    main()
