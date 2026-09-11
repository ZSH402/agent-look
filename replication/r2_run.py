"""R2 运行入口：banking 基底上的五级过近似阶梯。"""
from __future__ import annotations

import json

import patterns as P
import staircase as ST

LEVELS = ["L0_exact", "L1_family", "L2_drop_object", "L3_over_verb", "L4_no_derivation"]


def main():
    d = ST.load()
    banking = d["suites"]["banking"]
    tools = {name: d["tools"][name] for name in banking["tools"]}
    U = set(banking["tools"])
    R = {f"{cap}@**" for cap in U}
    harm_set = set(d["extraction"]["harm_set_from_injection_ground_truth"])

    task = ST.pick_task(banking)
    calls = ST.map_calls(task)

    # §8.2 第 1 条：宽松范围（每跳 = R）跑一遍，记录放行轨迹
    loose_trace = [
        (c["hop"], c["capability"], c["resource"])
        for c in calls
        if P.scope_allows(R, c["capability"], c["resource"])
    ]

    M = ST.compute_M(calls)

    # §8.2 第 5 条：一致性检查
    ok_m, total = ST.task_success(M, calls)

    report = {
        "universe_size": len(U),
        "universe": sorted(U),
        "R_entries": sorted(R),
        "task_id": task["id"],
        "task_prompt": task["prompt"],
        "calls": calls,
        "loose_trace_len": len(loose_trace),
        "M": [sorted(m) for m in M],
        "M_consistency": {"allowed": ok_m, "total": total, "pass": ok_m == total},
        "harm_set_banking_intersection": sorted(U & harm_set),
        "levels": {},
    }

    for lvl in LEVELS:
        S = ST.coarsen(lvl, M, R, tools)
        sur = ST.surplus_of(S, M)
        rads = [ST.radius(e, S) for _, e in sur]
        n_harm = sum(1 for _, e in sur if P.parse_entry(e)[0] in harm_set)
        a, t = ST.task_success(S, calls)
        report["levels"][lvl] = {
            "S": [sorted(s) for s in S],
            "surplus_count": len(sur),
            "surplus": [f"hop{i}:{e}" for i, e in sur],
            "mean_radius": (sum(rads) / len(rads)) if rads else 0.0,
            "radii": rads,
            "harm_count": n_harm,
            "task_success": f"{a}/{t}",
            "task_success_rate": a / t,
        }

    # L3 备选取舍（规格 §8.3 要求同时报告）：锚定参数名 = 首个类型含 str 的参数
    S_alt = ST.coarsen("L3_over_verb", M, R, tools, U, anchor_mode="str_typed")
    sur_alt = ST.surplus_of(S_alt, M)
    report["L3_alt_variant"] = {
        "note": "锚定参数名 = 首个类型含 str 的参数（备选读法）",
        "surplus_count": len(sur_alt),
        "mean_radius": (
            sum(ST.radius(e, S_alt) for _, e in sur_alt) / len(sur_alt) if sur_alt else 0.0
        ),
        "harm_count": sum(1 for _, e in sur_alt if P.parse_entry(e)[0] in harm_set),
        "surplus": [f"hop{i}:{e}" for i, e in sur_alt],
    }

    print(json.dumps(report, ensure_ascii=False, indent=2))
    return report


if __name__ == "__main__":
    main()
