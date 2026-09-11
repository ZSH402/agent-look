"""R3：四个 suite 的过近似阶梯差分运行（spec §8，钉死版）。

只读 spec/spec.md 与 data/agentdojo_bench.json。输出 all_suites.json。
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

import patterns as P  # noqa: E402
import staircase as ST  # noqa: E402

LEVELS = ["L0_exact", "L1_family", "L2_drop_object", "L3_over_verb", "L4_no_derivation"]
SUITES = ["banking", "slack", "travel", "workspace"]


def run_suite(name, d):
    su = d["suites"][name]
    U = set(su["tools"])
    tools = {n: d["tools"][n] for n in su["tools"]}
    R = {f"{c}@**" for c in U}
    harm_set = set(d["extraction"]["harm_set_from_injection_ground_truth"])

    max_calls = max(len(t["ground_truth"]) for t in su["user_tasks"])
    cands = [t["id"] for t in su["user_tasks"] if len(t["ground_truth"]) == max_calls]
    task = [t for t in su["user_tasks"] if t["id"] == min(cands)][0]
    calls = ST.map_calls(task)

    M = ST.compute_M(calls)
    a, t = ST.task_success(M, calls)

    out = {
        "suite": name,
        "universe_size": len(U),
        "task_id": task["id"],
        "task_calls": len(calls),
        "tie_candidates": cands,
        "calls": [(c["hop"], c["capability"], c["resource"]) for c in calls],
        "M": [sorted(m) for m in M],
        "M_consistency": {"allowed": a, "total": t, "pass": a == t},
        "harm_set_intersection": sorted(U & harm_set),
        "levels": {},
    }

    for mode in ("canonical", "str_typed"):
        for lvl in LEVELS:
            S = ST.coarsen(lvl, M, R, tools, U, anchor_mode=mode)
            sur = ST.surplus_of(S, M)
            harm = [e for _, e in sur if P.parse_entry(e)[0] in harm_set]
            ok, tot = ST.task_success(S, calls)
            key = f"{lvl}" + ("" if mode == "canonical" else "|str_typed")
            out["levels"][key] = {
                "surplus_count": len(sur),
                "harm_count": len(harm),
                "harm_entries": [f"hop{i}:{e}" for (i, e) in sur
                                 if P.parse_entry(e)[0] in harm_set],
                "mean_radius": (
                    sum(ST.radius(e, S) for _, e in sur) / len(sur) if sur else 0.0
                ),
                "task_success": f"{ok}/{tot}",
                "task_success_rate": (ok / tot) if tot else 1.0,
                "S_size": sum(len(s) for s in S),
            }
    return out


def main():
    d = ST.load()
    res = {s: run_suite(s, d) for s in SUITES}
    (HERE / "all_suites.json").write_text(json.dumps(res, ensure_ascii=False, indent=2))

    for s, r in res.items():
        print(f"== {s}  task={r['task_id']}  calls={r['task_calls']}  U={r['universe_size']}  "
              f"M一致={r['M_consistency']['pass']} ({r['M_consistency']['allowed']}/"
              f"{r['M_consistency']['total']})  harm∩U={len(r['harm_set_intersection'])}")
        for k, v in r["levels"].items():
            print(f"   {k:24s} surplus={v['surplus_count']:3d}  harm={v['harm_count']:3d}  "
                  f"半径={v['mean_radius']:.3f}  succ={v['task_success']}")


if __name__ == "__main__":
    main()
