"""差分装置入口：把同一批用例喂给两侧实现，逐键比对。

用法： python3 replication/differential/run_diff.py
产出： replication/differential/results.json
"""
from __future__ import annotations

import json
import os
import random
import sys
import traceback

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import oracle                                   # noqa: E402
import scenarios as S                           # noqa: E402
from drivers import new_driver, ref_pattern_matches, mine_pattern_matches, \
    ref_pattern_subsumes, mine_pattern_subsumes, Denied   # noqa: E402

OUT = os.path.join(HERE, "results.json")
SEED = 20240911


def run_case(fn, which):
    d = None
    try:
        if which == "ref":
            d = new_driver("ref")
        else:
            d = new_driver("mine")
        return fn(d)
    except Exception as e:                                   # noqa: BLE001
        return {"__fatal__": f"{type(e).__name__}: {e}",
                "__tb__": traceback.format_exc().splitlines()[-3:]}


def diff_dicts(a, b):
    keys = sorted(set(a) | set(b), key=lambda k: (str(type(k)), k))
    return {str(k): (a.get(k, "<missing>"), b.get(k, "<missing>"))
            for k in keys if a.get(k, "<missing>") != b.get(k, "<missing>")}


# ------------------------------------------------------------------ 族 1 ---
def family1_patterns(rec):
    pats = S.gen_patterns()
    ress = S.gen_resources()
    m_div, m_tot = [], 0
    for p in pats:
        for r in ress:
            m_tot += 1
            ref = ref_pattern_matches(p, r)
            mine = mine_pattern_matches(p, r)
            orc = oracle.matches(p, r)
            if ref != mine:
                m_div.append({"pattern": p, "resource": r, "ref": ref,
                              "mine": mine, "oracle": orc})
    sub_div, sub_tot = [], 0
    for c in pats:
        for p in pats:
            sub_tot += 1
            ref = ref_pattern_subsumes(c, p)
            mine = mine_pattern_subsumes(c, p)
            orc = oracle.subsumes(c, p)
            if ref != mine:
                sub_div.append({"child": c, "parent": p, "ref": ref,
                                "mine": mine, "oracle": orc})
    rec["F1a-matches"] = {"cases": m_tot, "divergences": len(m_div),
                          "detail": m_div[:80]}
    rec["F1b-subsumes"] = {"cases": sub_tot, "divergences": len(sub_div),
                           "detail": sub_div[:80]}

    # 系统级交叉验证（把模式放进真实令牌/请求路径）
    rng = random.Random(SEED)
    sys_div, sys_tot = [], 0
    sample = []
    for _ in range(240):
        sample.append((rng.choice(pats), rng.choice(ress)))
    # 保证覆盖所有 matches 分歧点
    for dv in m_div[:40]:
        sample.append((dv["pattern"], dv["resource"]))
    for p, r in sample:
        sys_tot += 1
        a = run_case(lambda d, p=p, r=r: {"k": S.sys_matches(d, p, r).decision},
                     "ref")
        b = run_case(lambda d, p=p, r=r: {"k": S.sys_matches(d, p, r).decision},
                     "mine")
        if a != b:
            sys_div.append({"pattern": p, "resource": r, "ref": a, "mine": b,
                            "oracle": oracle.matches(p, r)})
    rec["F1c-system-matches"] = {"cases": sys_tot, "divergences": len(sys_div),
                                 "detail": sys_div[:40]}

    # 系统级 scope_subset 交叉验证（经 delegate 的衰减检查）
    sys2_div, sys2_tot = [], 0
    pairs = [(rng.choice(pats), rng.choice(pats)) for _ in range(200)]
    for dv in sub_div[:40]:
        pairs.append((dv["child"], dv["parent"]))
    for c, p in pairs:
        sys2_tot += 1
        a = run_case(lambda d, c=c, p=p: {"k": S.sys_subsumes(d, c, p)[0]}, "ref")
        b = run_case(lambda d, c=c, p=p: {"k": S.sys_subsumes(d, c, p)[0]}, "mine")
        if a != b:
            sys2_div.append({"child": c, "parent": p, "ref": a, "mine": b,
                             "oracle": oracle.subsumes(c, p)})
    rec["F1d-system-subsumes"] = {"cases": sys2_tot,
                                  "divergences": len(sys2_div),
                                  "detail": sys2_div[:40]}

    # §2.8 健全性要求：subsumes(p,q) 为真 ⇒ 任何匹配 p 的资源必须匹配 q
    sound = {}
    for tag, sub, mat in (("ref", ref_pattern_subsumes, ref_pattern_matches),
                          ("mine", mine_pattern_subsumes, mine_pattern_matches),
                          ("oracle", oracle.subsumes, oracle.matches)):
        bad = []
        for c in pats:
            for p in pats:
                if not sub(c, p):
                    continue
                for r in ress:
                    if mat(c, r) and not mat(p, r):
                        bad.append((c, p, r))
        sound[tag] = {"violations": len(bad), "detail": bad[:20]}
    rec["F1e-soundness"] = sound


# ------------------------------------------------------------------ 族 2-7 -
def run_families(rec):
    rng = random.Random(SEED)
    for fam, gen in S.ALL_FAMILIES.items():
        cases = gen(rng)
        divs = []
        for cid, fn in cases:
            a = run_case(fn, "ref")
            b = run_case(fn, "mine")
            if a != b:
                divs.append({"case": cid, "diff": diff_dicts(a, b),
                             "ref": a, "mine": b})
        rec[fam] = {"cases": len(cases), "divergences": len(divs),
                    "detail": divs[:60]}


def main():
    rec = {}
    family1_patterns(rec)
    run_families(rec)
    rec["__meta__"] = {"seed": SEED,
                       "ref_max_request_age": 50,
                       "mine_max_request_age": 300,
                       "ref_pull_interval": 10, "ttl": 1000}
    with open(OUT, "w") as f:
        json.dump(rec, f, ensure_ascii=False, indent=2, default=str)
    for k, v in rec.items():
        if isinstance(v, dict) and "cases" in v:
            print(f"{k:28s} cases={v['cases']:6d}  divergences={v['divergences']}")
    print("written:", OUT)


if __name__ == "__main__":
    main()
