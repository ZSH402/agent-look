"""§2.8 性质测试：subsumption 健全性 + 衰减不放大权限。

健全性按定义判定：subsumes(p,q) 为真时，抽样资源空间内所有匹配 p 的资源必须匹配 q。
"""
from __future__ import annotations

import itertools
import random

import patterns as P

SEG_POOL = ["a", "b", "*", "x-y"]


def random_pattern(rng):
    n = rng.randint(1, 3)
    segs = [rng.choice(SEG_POOL) for _ in range(n)]
    if rng.random() < 0.4:
        segs.append("**")
    return "/".join(segs)


def sample_resources(max_len=3):
    res = [""]
    for n in range(1, max_len + 1):
        for combo in itertools.product(["a", "b", "x-y"], repeat=n):
            res.append("/".join(combo))
    return res


def main():
    rng = random.Random(20240607)
    resources = sample_resources()
    bad = []
    for _ in range(4000):
        p, q = random_pattern(rng), random_pattern(rng)
        if not P.subsumes(p, q):
            continue
        for r in resources:
            if P.matches(p, r) and not P.matches(q, r):
                bad.append((p, q, r))
    print(f"subsumption 抽样: 4000 对模式 × {len(resources)} 资源, 反例 = {len(bad)}")
    if bad:
        print(bad[:5])

    # 衰减不放大权限：子范围允许的请求，父范围必须也允许
    caps = ["a.b", "c.d"]
    bad2 = []
    for _ in range(4000):
        parent = {f"{rng.choice(caps)}@{random_pattern(rng)}" for _ in range(rng.randint(1, 3))}
        child = {f"{rng.choice(caps)}@{random_pattern(rng)}" for _ in range(rng.randint(1, 3))}
        if not P.scope_subset(child, parent):
            continue
        for cap in caps:
            for r in resources:
                if P.scope_allows(child, cap, r) and not P.scope_allows(parent, cap, r):
                    bad2.append((sorted(child), sorted(parent), cap, r))
    print(f"衰减不放大: 4000 组, 反例 = {len(bad2)}")
    if bad2:
        print(bad2[:5])

    # 非平凡性检查
    trivial = (
        len(bad) == 0
        and all(not P.subsumes(p, q) or True for p, q in [])
    )
    print("非平凡性: 存在 subsumes 为真的模式对 =", any(
        P.subsumes(a, b) for a in ["a", "a/*", "a/**"] for b in ["a", "a/*", "a/**", "**"]
    ))
    assert not bad and not bad2


if __name__ == "__main__":
    main()
