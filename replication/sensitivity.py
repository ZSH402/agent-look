"""敏感性：规格未规定处的备选取舍对 R2 数字的影响（仅供 REPORT 引用）。"""
from __future__ import annotations

import json

import patterns as P
import staircase as ST

LEVELS = ["L0_exact", "L1_family", "L2_drop_object", "L3_over_verb", "L4_no_derivation"]


def run(calls, M, R, tools, banking, harm_set):
    res = {}
    for lvl in LEVELS:
        S = ST.coarsen(lvl, M, R, tools)
        sur = ST.surplus_of(S, M)
        res[lvl] = {
            "surplus": len(sur),
            "mean_radius": (sum(ST.radius(e, S) for _, e in sur) / len(sur)) if sur else 0.0,
            "harm": sum(1 for _, e in sur if P.parse_entry(e)[0] in harm_set),
        }
    return res


def main():
    d = ST.load()
    banking = d["suites"]["banking"]
    tools = {n: d["tools"][n] for n in banking["tools"]}
    U = set(banking["tools"])
    R = {f"{c}@**" for c in U}
    harm = set(d["extraction"]["harm_set_from_injection_ground_truth"])
    task = ST.pick_task(banking)

    # 变体 A：resource 取实参中"键名字典序最小"的字符串值
    calls_a = []
    for i, gt in enumerate(task["ground_truth"]):
        strs = [v for _, v in sorted(gt["args"].items()) if isinstance(v, str)]
        calls_a.append({"index": i, "hop": i % 4, "capability": gt["function"],
                        "resource": strs[0] if strs else "", "raw_args": gt["args"]})
    M_a = ST.compute_M(calls_a)

    # 变体 B：跨级别过滤（S_i^L 过滤到 ⊆ S_i^(L-1)）—— 用 W 代替
    # 变体 C：1-based 跳映射（第 i 个调用 → 跳 ((i+1) mod 4)）
    calls_c = []
    for i, gt in enumerate(task["ground_truth"]):
        s = ST.first_string_value(gt["args"])
        calls_c.append({"index": i, "hop": (i + 1) % 4, "capability": gt["function"],
                        "resource": "" if s is None else s, "raw_args": gt["args"]})
    M_c = ST.compute_M(calls_c)

    out = {
        "baseline_task": task["id"],
        "variant_A_resource_first_str_by_key_order": {
            "calls": [(c["hop"], c["capability"], c["resource"]) for c in calls_a],
            "M": [sorted(m) for m in M_a],
            **run(calls_a, M_a, R, tools, banking, harm),
        },
        "variant_C_hop_offset_1": {
            "calls": [(c["hop"], c["capability"], c["resource"]) for c in calls_c],
            "M": [sorted(m) for m in M_c],
            **run(calls_c, M_c, R, tools, banking, harm),
        },
    }

    # 变体 B：跨级别过滤（S_i^L 过滤到 ⊆ S_i^(L-1)，而非 ⊆ 上一跳）
    prev = None
    vb = {}
    MB = ST.compute_M(ST.map_calls(task))
    for lvl in LEVELS:
        raw = []
        for i in range(4):
            acc = set()
            for e in MB[i]:
                cap, pat = P.parse_entry(e)
                if lvl == "L0_exact":
                    acc.add(e)
                elif lvl == "L1_family":
                    acc.add(f"{cap}@{ST._widen_last_segment(pat)}")
                elif lvl == "L2_drop_object":
                    acc.add(f"{cap}@**")
                elif lvl == "L3_over_verb":
                    acc.add(e)
                    anchor = ST.first_non_ambient_param(tools.get(cap, {}))
                    if anchor is not None:
                        for other, meta in tools.items():
                            if ST.first_non_ambient_param(meta) == anchor:
                                acc.add(f"{other}@{pat}")
                else:
                    acc |= R
            raw.append(acc)
        if prev is None:
            S = raw
        else:
            S = [{e for e in raw[i] if any(P.entry_subsumes(e, pe) for pe in prev[i])}
                 for i in range(4)]
        sur = ST.surplus_of(S, MB)
        vb[lvl] = {"surplus": len(sur),
                   "mean_radius": (sum(ST.radius(e, S) for _, e in sur) / len(sur)) if sur else 0.0,
                   "harm": sum(1 for _, e in sur if P.parse_entry(e)[0] in harm)}
        prev = S
    out["variant_B_cross_level_filter"] = vb

    # 变体 D：半径的 w 取"该能力在任务轨迹中的实资源"（若匹配），否则退回合成
    calls = ST.map_calls(task)
    M = ST.compute_M(calls)
    obs = {}
    for c in calls:
        obs.setdefault(c["capability"], []).append(c["resource"])
    for lvl in LEVELS:
        S = ST.coarsen(lvl, M, R, tools)
        sur = ST.surplus_of(S, M)
        rads = []
        for _, e in sur:
            cap, pat = P.parse_entry(e)
            w = next(
                (r for r in obs.get(cap, []) if r != "" and P.matches(pat, r)),
                ST.witness(pat),
            )
            rads.append(sum(1 for j in range(4) if P.scope_allows(S[j], cap, w)))
        out.setdefault("variant_D_radius_witness_observed", {})[lvl] = {
            "surplus": len(sur),
            "mean_radius": (sum(rads) / len(rads)) if rads else 0.0,
        }

    print(json.dumps(out, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
