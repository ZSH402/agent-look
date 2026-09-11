"""范围表达能力实验：过近似的来源、代价，以及粒度选择。

方法（对应"支柱 B"）：
  1. 用宽松范围跑一遍脚本化任务，记录**实际执行的 (跳, 能力, 资源) 轨迹**；
  2. 从轨迹用最具体公共前缀泛化反推**最小必要范围 M**（不是理论最优最小集，最小集是 NP-hard）；
  3. 把 M 按四级粗化阶梯放大，模拟 NL→范围 推导的四类失败模式；
  4. 用**可达性**而不是集合大小来度量代价。

选定这一路线而非"窄起步+按需加宽"的理由：后者的证据来自被怀疑方本身，校准价值低。
"""
from __future__ import annotations

import random

from collections import Counter

from src.harm import DEFAULT_MODEL, VARIANTS, HarmModel, perturbed_models
from src.model import CAP_UNIVERSE, Deny
from src.patterns import (
    ANY,
    least_general_pattern,
    scope_allows,
    scope_subset,
    split_grant,
    witness,
)
from src.runtime import System

from .run_all import CHAIN, ROOT_SCOPE, SENSITIVE

# --- 任务：处理 2024 年订单。每跳是"签发者 → 持有者"的实际动作 ---
HOP_TASK: dict[int, list[tuple[str, str]]] = {
    0: [("order.read", "orders/2024-001"), ("order.update", "orders/2024-001"),
        ("order.read", "orders/2024-002"), ("order.update", "orders/2024-002"),
        ("service.execute", "service/2024-001"), ("inventory.read", "inventory/widgets")],
    1: [("service.execute", "service/2024-001"), ("service.execute", "service/2024-002"),
        ("inventory.read", "inventory/widgets"), ("inventory.read", "inventory/gadgets")],
    2: [("inventory.read", "inventory/widgets"), ("inventory.read", "inventory/gadgets")],
    3: [("inventory.read", "inventory/widgets")],
}
HOPS = len(CHAIN) - 1

# 动词过泛：语义相邻但任务不需要的能力
ADJACENT = {"order.read": ["order.update"], "order.update": ["payment.read"],
            "service.execute": ["kitchen.execute"], "inventory.read": ["inventory.update"]}


def build(system: System, hop_scopes: list[list[str]]):
    """按给定的逐跳范围建立委托链。"""
    toks, parent = [], None
    for i in range(HOPS):
        tok = system.delegate(CHAIN[i], CHAIN[i + 1], hop_scopes[i], f"scope-task-{i}",
                              parent_token_id=(parent.token_id if parent else None))
        toks.append(tok)
        parent = tok
    return toks


def new_system(root_scope=None) -> System:
    s = System(mode="P", ttl=1000, pull_interval=10)
    s.add_agent("A", "Coordinator", list(root_scope or ROOT_SCOPE))
    for sid in CHAIN[1:]:
        s.add_agent(sid, "Worker", ["order.read"])
    return s


def run_task(s, toks) -> list[tuple[int, str, str, str]]:
    """执行脚本化任务，返回实际被放行的 (跳, 能力, 资源, 决策)。"""
    trace = []
    for hop, actions in HOP_TASK.items():
        for cap, res in actions:
            r = s.request(CHAIN[hop], CHAIN[hop + 1], toks[hop].token_id, cap, res,
                          toks[hop].task_id, text="process order")
            trace.append((hop, cap, res, r.decision))
    return trace


def observe_minimal(root_scope=None) -> list[list[str]]:
    """宽松范围跑一遍 → 从轨迹反推最小必要范围 M（每跳一个 grant 列表）。

    注意：第 i 跳的令牌是第 i+1 跳令牌的父令牌，因此 hop i 的范围必须覆盖
    "本跳自身需求 ∪ 全部下游需求"。否则下游无法合法派生。
    """
    root = list(root_scope or ROOT_SCOPE)
    s = new_system(root)
    toks = build(s, [root] * HOPS)
    trace = run_task(s, toks)
    assert all(d == "ALLOW" for _, _, _, d in trace), "宽松范围下任务必须全部成功"

    own: dict[int, dict[str, list[str]]] = {i: {} for i in range(HOPS)}
    for hop, cap, res, _ in trace:
        own[hop].setdefault(cap, []).append(res)

    cum: dict[int, dict[str, list[str]]] = {}
    for i in reversed(range(HOPS)):
        merged = {c: list(rs) for c, rs in own[i].items()}
        if i + 1 < HOPS:
            for c, rs in cum[i + 1].items():
                merged.setdefault(c, []).extend(rs)
        cum[i] = merged

    return [sorted(f"{cap}@{least_general_pattern(rs)}"
                   for cap, rs in sorted(cum[i].items())) for i in range(HOPS)]


def _filter_to_parent(scope: list[str], parent_scope: list[str]) -> list[str]:
    """衰减约束：不能委托超过自己持有的部分。"""
    return [g for g in scope if scope_subset([g], parent_scope)]



def _widen(p: str) -> str:
    """对象族放宽：**只能变宽，绝不能变窄**。

    对已经是"任意资源"（`**` 或带 `**` 后缀）的模式，放宽就是去掉前缀约束；
    早先版本对 `**` 做"最后一段换成 *"，把它收窄成只匹配单段资源，
    反而让任务失败——粗化不该产生这种反向效果。
    """
    from src.patterns import parse

    segs, dstar = parse(p)
    if dstar:
        return ANY
    if not segs:
        return ANY
    return "/".join(list(segs[:-1]) + ["*"])

def coarsen(M: list[list[str]], level: str, root_scope=None) -> list[list[str]]:
    """把最小必要范围按粗化阶梯放大，并逐跳做父范围过滤以维持衰减合法性。"""
    out = []
    for i in range(HOPS):
        if level == "L0_exact":
            cur = list(M[i])
        elif level == "L1_family":
            cur = [f"{c}@{_widen(p)}" for c, p in (split_grant(g) for g in M[i])]
        elif level == "L2_drop_object":
            cur = [split_grant(g)[0] for g in M[i]]
        elif level == "L3_over_verb":
            cur = list(M[i]) + [f"{adj}@{split_grant(g)[1]}"
                                for g in M[i]
                                for adj in ADJACENT.get(split_grant(g)[0], [])]
        elif level == "L4_no_derivation":
            cur = [f"{c}@{ANY}" for c in (root_scope or ROOT_SCOPE)]
        else:
            raise ValueError(level)
        cur = sorted(set(cur))
        # 第 0 跳也要对根授权做过滤：无法委托超出自己根授权的范围
        parent = out[i - 1] if i else [f"{c}@{ANY}" for c in (root_scope or ROOT_SCOPE)]
        out.append(_filter_to_parent(cur, parent))
    return out


def evaluate(S: list[list[str]], M: list[list[str]], model: HarmModel = DEFAULT_MODEL,
             root_scope=None) -> dict:
    """在给定逐跳范围下重建系统，度量任务成功率与 surplus 的可达性代价。"""
    s = new_system(root_scope)
    toks = build(s, S)
    trace = run_task(s, toks)
    ok = sum(1 for *_, d in trace if d == "ALLOW")

    # surplus = 不在 M 覆盖范围内的授权
    surplus = []
    for i in range(HOPS):
        for g in S[i]:
            if not scope_subset([g], M[i]):
                surplus.append((i, g))

    radii, critical = [], 0
    profiles = []
    for hop, g in surplus:
        cap, pat = split_grant(g)
        res = witness(pat or ANY)
        radii.append(sum(1 for j in range(HOPS) if scope_allows(S[j], cap, res)))
        profiles.append(model.profile(g))
        if cap in SENSITIVE:
            critical += 1
    return {
        "harmful": {v: sum(1 for pr in profiles if model.is_harmful(pr["grant"], v))
                    for v in VARIANTS},
        "surplus_effects": dict(Counter(pr["effect"] for pr in profiles)),
        "irreversible_surplus": sum(1 for pr in profiles
                                    if pr["reversibility"] == "IRREVERSIBLE"),
        "boundary_surplus": sum(1 for pr in profiles if pr["crosses_boundary"]),
        "max_reachable_sensitivity": max(
            (pr["max_sensitivity"] for pr in profiles),
            key=lambda n: {"PUBLIC": 0, "INTERNAL": 1, "PERSONAL": 2, "SECRET": 3}[n],
            default="—"),
        "task_success": f"{ok}/{len(trace)}",
        "task_ok": ok == len(trace),
        "surplus_grants": len(surplus),
        "surplus_mean_radius": round(sum(radii) / len(radii), 3) if radii else 0.0,
        "surplus_max_radius": max(radii) if radii else 0,
        "full_reach_fraction": round(
            sum(1 for r in radii if r == HOPS) / len(radii), 3) if radii else 0.0,
        "critical_surplus": critical,
    }


# ------------------------------------------------------------------ E11
def e11_coarsening_ladder(root_scope=None, model: HarmModel = DEFAULT_MODEL) -> dict:
    M = observe_minimal(root_scope)
    s = new_system(root_scope)
    toks = build(s, M)
    verify = run_task(s, toks)
    exact_ok = all(d == "ALLOW" for _, _, _, d in verify)

    levels = ["L0_exact", "L1_family", "L2_drop_object", "L3_over_verb", "L4_no_derivation"]
    rows = [{"level": lv, **evaluate(coarsen(M, lv, root_scope), M, model, root_scope)}
            for lv in levels]
    root = list(root_scope or ROOT_SCOPE)
    return {"minimal_scope": M, "minimal_reproduces_task": exact_ok, "ladder": rows,
            "root_scope_size": len(root),
            "root_has_critical": len(set(root) & set(SENSITIVE))}


# ------------------------------------------------------------------ E12
def e12_granularity(M: list[list[str]] | None = None) -> dict:
    """同一意图覆盖下，裸动词集合 vs 资源模式化范围。"""
    M = M or observe_minimal()
    bare = coarsen(M, "L2_drop_object")
    patterned = coarsen(M, "L1_family")
    return {"patterned_L1": evaluate(patterned, M), "bare_L2": evaluate(bare, M),
            "note": "裸动词集合 = 当前实现；资源模式化 = 本实验新增"}


# ------------------------------------------------------------------ E13
def e13_independent_surplus(k: int, harm_class: str, trials: int = 30) -> dict:
    """逐跳**独立**采样 surplus（修正 E2 的嵌套前缀相关性缺陷）。

    harm_class: 'family' = 同能力的更宽资源模式；'cross' = 换个能力，同/任意资源。
    """
    M = observe_minimal()
    rnd = random.Random(1000 + k)
    need_caps = sorted({split_grant(g)[0] for hop in M for g in hop})
    cross_pool = [c for c in ROOT_SCOPE if c not in need_caps]

    all_radii, harmful_total, ok_all = [], 0, True
    for _ in range(trials):
        S = []
        for i in range(HOPS):
            extra = []
            for _ in range(k):
                if harm_class == "family":
                    base = rnd.choice(M[i])
                    c, p = split_grant(base)
                    extra.append(f"{c}@{ANY}")
                else:
                    extra.append(f"{rnd.choice(cross_pool)}@{ANY}")
            cur = sorted(set(list(M[i]) + extra))
            S.append(_filter_to_parent(cur, S[-1]) if i else cur)
        res = evaluate(S, M)
        ok_all &= res["task_ok"]
        harmful_total += res["harmful"]["moderate"]
        if res["surplus_grants"]:
            all_radii.append(res["surplus_mean_radius"])
    return {"k": k, "harm_class": harm_class, "trials": trials,
            "harm_variant": "moderate",
            "mean_radius": round(sum(all_radii) / len(all_radii), 3) if all_radii else 0.0,
            "task_ok_all_trials": ok_all,
            "harmful_per_trial": round(harmful_total / trials, 3)}


# ------------------------------------------------------------------ E14
def e14_harm_robustness(ladder: list[dict]) -> dict:
    """危害定义变体的稳健性扫描。

    回答两个问题，两个都必须逐变体回答，不允许只报一个变体：
      Q1 用 surplus 条数代理危害是否可靠？——统计"序反例对"的个数。
      Q2 "动词过泛（L3）比丢掉对象约束（L2）更危险"这一结论是否稳健？
    """
    per_variant = {}
    for v in VARIANTS:
        seq = [(r["level"], r["surplus_grants"], r["harmful"][v]) for r in ladder]
        inv = [(a[0], b[0]) for i, a in enumerate(seq) for b in seq[i + 1:]
               if (a[1] - b[1]) * (a[2] - b[2]) < 0]
        lv = {r["level"]: r for r in ladder}
        per_variant[v] = {
            "desc": VARIANTS[v],
            "sequence": seq,
            "inversion_pairs": inv,
            "size_predicts_harm": len(inv) == 0,
            "L3_minus_L2_harm": lv["L3_over_verb"]["harmful"][v]
                                - lv["L2_drop_object"]["harmful"][v],
            "any_harm_at_all": any(r["harmful"][v] > 0 for r in ladder),
        }
    stable = {k: len({per_variant[v][k] for v in VARIANTS}) == 1
              for k in ("size_predicts_harm", "any_harm_at_all")}
    l3_gt_l2 = {v: per_variant[v]["L3_minus_L2_harm"] > 0 for v in VARIANTS}
    return {"variants": VARIANTS, "per_variant": per_variant,
            "stable_across_variants": stable,
            "L3_worse_than_L2": l3_gt_l2}


# ------------------------------------------------------------------ E15
def root_levels() -> dict[str, list[str]]:
    """协调者根授权的若干档位：从"仅任务必需"到"全部能力"。"""
    need = sorted({cap for acts in HOP_TASK.values() for cap, _ in acts})
    adj = sorted({a for c in need for a in ADJACENT.get(c, [])})
    ops = ["inventory.update", "kitchen.manage", "db.read"]
    exports = ["db.export", "credential.read"]
    return {
        "R0_仅任务必需": need,
        "R1_+相邻动词": sorted(set(need) | set(adj)),
        "R2_+运维读写": sorted(set(need) | set(adj) | set(ops)),
        "R3_+导出与凭据读": sorted(set(need) | set(adj) | set(ops) | set(exports)),
        "R4_全部能力": list(CAP_UNIVERSE),
    }


def e15_root_granularity() -> dict:
    """根授权粒度实验：检验"真正的安全参数是根授权本身"。

    E11 的这一结论此前只建立在单一根授权上，且 strict/lenient 下危害全为 0 恰恰是因为
    该根授权不含跨界能力。此处把根授权当作自变量扫描。
    """
    rows = []
    for name, scope in root_levels().items():
        root = [c for c in scope]
        lad = e11_coarsening_ladder(root)["ladder"]
        row = {"root": name, "root_size": len(root),
               "root_has_critical": len(set(root) & set(SENSITIVE)),
               "max_harm": {v: max(r["harmful"][v] for r in lad) for v in VARIANTS},
               "max_critical_surplus": max(r["critical_surplus"] for r in lad),
               "max_sensitivity": max(
                   (r["max_reachable_sensitivity"] for r in lad),
                   key=lambda n: {"—": -1, "PUBLIC": 0, "INTERNAL": 1,
                                  "PERSONAL": 2, "SECRET": 3}[n]),
               "task_ok_all_levels": all(r["task_ok"] for r in lad)}
        rows.append(row)
    # 结论：跨界危害是否只在根授权含跨界能力时出现
    trivial = [r["root"] for r in rows if r["max_harm"]["strict"] == 0]
    return {"ladder": rows,
            "root_scope_has_no_critical_implies_zero_strict_harm":
                all(r["root_has_critical"] > 0 or r["max_harm"]["strict"] == 0
                    for r in rows),
            "roots_with_zero_strict_harm": trivial}


# ------------------------------------------------------------------ E16
def e16_manifest_sensitivity() -> dict:
    """危害模型**输入**的敏感性分析：扰动工具清单与缺省数据分级。

    上一轮只把**聚合规则**做成了变体，输入仍是声明的。此项在有界区间内扰动输入，
    把"声明依赖"从一句免责声明变成可测区间。
    """
    rows = []
    for name, model in sorted(perturbed_models().items()):
        lad = e11_coarsening_ladder(model=model)["ladder"]
        entry = {"manifest": name, "default_sensitivity": model.default_sensitivity,
                 "contested_reading": ("high" if name.startswith("high")
                                       else "low" if name.startswith("low") else "base"),
                 "harm_by_level": {v: {r["level"]: r["harmful"][v] for r in lad}
                                   for v in VARIANTS}}
        for v in VARIANTS:
            seq = [(r["level"], r["surplus_grants"], r["harmful"][v]) for r in lad]
            inv = [(a[0], b[0]) for i, a in enumerate(seq) for b in seq[i + 1:]
                   if (a[1] - b[1]) * (a[2] - b[2]) < 0]
            lv = {r["level"]: r for r in lad}
            entry[v] = {"inversions": len(inv), "size_predicts_harm": len(inv) == 0,
                        "L3_minus_L2": (lv["L3_over_verb"]["harmful"][v]
                                        - lv["L2_drop_object"]["harmful"][v]),
                        "any_harm": any(r["harmful"][v] > 0 for r in lad),
                        "max_harm": max(r["harmful"][v] for r in lad)}
        rows.append(entry)

    summary = {}
    for v in VARIANTS:
        vals = [e[v]["max_harm"] for e in rows]
        summary[v] = {
            "max_harm_range": [min(vals), max(vals)],
            "manifest_count": len(rows),
            "size_predicts_harm_frac": round(
                sum(e[v]["size_predicts_harm"] for e in rows) / len(rows), 3),
            "any_harm_frac": round(sum(e[v]["any_harm"] for e in rows) / len(rows), 3),
            "L3_worse_than_L2_frac": round(
                sum(e[v]["L3_minus_L2"] > 0 for e in rows) / len(rows), 3)}
    invariant = {k: len({tuple(d[k]) if isinstance(d[k], list) else d[k]
                         for d in summary.values()}) == 1
                 for k in ("max_harm_range", "size_predicts_harm_frac", "any_harm_frac")}
    return {"manifests": rows, "summary": summary,
            "invariant_across_variants": invariant}
