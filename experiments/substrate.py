"""广义化基底：同一套过近似实验，可跑在**玩具宇宙**或**真实工具集**上。

存在理由：E11–E16 的全部结论都建立在自造的能力宇宙上。本模块把"基底"抽成参数，
先用玩具基底**复现 E11 的数字**（一致性检查），再换到 AgentDojo 的真实工具集上重跑——
只有在复现通过时，真实基底上的新数字才可信。

真实基底的锚定方式（全部机械可复现，见 tools/build_agentdojo_bench.py）：
  - capability = 真实工具函数名
  - 真实任务 = 用户任务 `ground_truth()` 里的 `FunctionCall(function=..., args=...)`
  - 危害集合 = 注入任务 `ground_truth()` 调用的工具（**基准自己定义的恶意动作**）
  - 相邻动词 = 首个非环境参数名相同的工具（"同一个对象、换个动词"）
"""
from __future__ import annotations

import json
import os
import random
from dataclasses import dataclass, field

from contextlib import contextmanager

from src.model import (CAP_UNIVERSE, current_universe, is_toy_universe,
                       reset_cap_universe, set_cap_universe)
from src.patterns import ANY, least_general_pattern, scope_allows, scope_subset, split_grant, witness
from src.runtime import System

from .rules import (adjacency as rule_adjacency, drop_object,
                    observational_surplus, resource_universe, widen_family)

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BENCH = os.path.join(HERE, "data", "agentdojo_bench.json")
HOPS = 4
CHAIN = ["A", "B", "C", "D", "E"]


# ------------------------------------------------------------------ 基底
@dataclass
class Substrate:
    name: str
    universe: list[str]
    hop_task: dict[int, list[tuple[str, str]]]
    root_scope: list[str]
    adjacent: dict[str, list[str]]
    harm_variants: dict[str, set[str]] = field(default_factory=dict)
    note: str = ""

    def harm(self, grant: str) -> dict[str, bool]:
        cap = split_grant(grant)[0]
        return {v: cap in s for v, s in self.harm_variants.items()}


def toy_substrate() -> Substrate:
    """玩具基底：与 E11 完全相同，用于一致性检查。"""
    from src.harm import DEFAULT_MODEL
    from .scope_experiments import ADJACENT, HOP_TASK, ROOT_SCOPE

    class _Toy(Substrate):
        def harm(self, grant: str) -> dict[str, bool]:
            return {v: DEFAULT_MODEL.is_harmful(grant, v) for v in
                    ("strict", "moderate", "lenient")}

    return _Toy(name="toy", universe=list(CAP_UNIVERSE), hop_task=dict(HOP_TASK),
                root_scope=list(ROOT_SCOPE), adjacent=dict(ADJACENT),
                harm_variants={}, note="与 E11 相同，用于复现校验")


def real_substrate(suite: str = "banking", adjacency: str = "param") -> Substrate:
    """真实基底：AgentDojo 某一 suite 的工具集与真实用户任务。"""
    with open(BENCH, encoding="utf-8") as f:
        bench = json.load(f)
    s = bench["suites"][suite]
    tools = s["tools"]
    tool_meta = bench["tools"]

    # 相邻动词：首个非环境参数名相同。
    # **规格未定义「非环境参数」**——本实现取「提取后参数表的第一个」（提取时已排除 Depends 参数），
    # 而独立复现者取「第一个类型含 str 的参数」。两种读法都通，结果差 8 倍（L3 surplus 1 vs 8）。
    # 通过环境变量 L3_ANCHOR 可切换，用于度量该歧义对结论的影响。
    _ANCHOR_MODE = os.environ.get("L3_ANCHOR", "positional")

    def first_param(t):
        ps = tool_meta[t]["params"]
        if not ps:
            return None
        if _ANCHOR_MODE == "typed":
            for q in ps:
                if "str" in (q.get("type") or ""):
                    return q["name"]
            return None
        return ps[0]["name"]

    adjacent = rule_adjacency(suite, adjacency)

    # 真实任务：取 ground_truth 调用最多者（并列取任务编号最小）
    def ncalls(ut):
        return len(ut["ground_truth"])

    task = sorted(s["user_tasks"], key=lambda u: (-ncalls(u), u["id"]))[0]

    hop_task: dict[int, list[tuple[str, str]]] = {}
    for i, call in enumerate(task["ground_truth"]):
        t = call["function"]
        prim = next((v for p in tool_meta.get(t, {}).get("params", [])
                     for v in [call["args"].get(p["name"])] if isinstance(v, str)), "")
        hop_task.setdefault(i % HOPS, []).append((t, prim))

    harm = set(bench["extraction"]["harm_set_from_injection_ground_truth"])
    mutating = set(bench["extraction"]["mutating_tools"])
    return Substrate(
        name=f"agentdojo/{suite}", universe=list(tools), hop_task=hop_task,
        root_scope=list(tools), adjacent=adjacent,
        harm_variants={"benchmark_injection_gt": harm, "static_mutating": mutating},
        note=f"真实任务 {task['id']}: {task['prompt'][:70]}")


# ------------------------------------------------------------------ 机制
@contextmanager
def universe(names):
    """能力宇宙是**进程级全局状态**。用上下文管理器保证异常路径也复位——
    E26 在 run_all 中排在 E25 之前，一旦残留，后续实验会静默跑在错误的宇宙上。"""
    prev = current_universe()
    set_cap_universe(names)
    try:
        yield
    finally:
        set_cap_universe(prev)
        assert current_universe() == prev, "能力宇宙复位失败"


def _new_system(universe, root_scope) -> System:
    set_cap_universe(universe)
    s = System(mode="P", ttl=1000, pull_interval=10)
    s.add_agent("A", "Coordinator", list(root_scope))
    for sid in CHAIN[1:]:
        s.add_agent(sid, "Worker", list(root_scope)[:1])
    return s


def _build(s, hop_scopes):
    toks, parent = [], None
    for i in range(HOPS):
        if not hop_scopes[i]:
            break
        from src.tokens import attenuate
        tok = attenuate(parent or s.peps["A"].root, CHAIN[i + 1], hop_scopes[i],
                        f"rt-{i}", s.now + 1000, s.authority.registry[CHAIN[i]],
                        s.peps[CHAIN[i]].sk, s.now)
        s.peps[CHAIN[i + 1]].accept_token(tok)
        s.peps[CHAIN[i]].tokens[tok.token_id] = tok
        toks.append(tok)
        parent = tok
    return toks


def _run_task(s, toks, hop_task):
    trace = []
    for hop, calls in sorted(hop_task.items()):
        if hop >= len(toks):
            continue
        for cap, res in calls:
            r = s.request(CHAIN[hop], CHAIN[hop + 1], toks[hop].token_id, cap,
                          res or "res/x", toks[hop].task_id, text="task")
            trace.append((hop, cap, res, r.decision))
    return trace


def observe_minimal(sub: Substrate) -> list[list[str]]:
    """宽松跑一遍 → 从轨迹反推最小必要范围（第 i 跳须覆盖本跳 ∪ 全部下游）。"""
    s = _new_system(sub.universe, sub.root_scope)
    toks = _build(s, [list(sub.root_scope)] * HOPS)
    trace = _run_task(s, toks, sub.hop_task)
    # 需求记录：**没有字符串参数的工具调用意味着"无对象约束"**（该工具在任务里
    # 并未指定对象），此时模式必须是 `**`，而不是从空字符串泛化出的单段 `*`。
    # 早先版本在这里从 "" 泛化，得到一个只匹配单段资源的 `*`，与实际请求用的
    # 占位资源不一致，导致反推出的 M 无法复现任务——这是实验框架的缺陷，已修正。
    own: dict[int, dict[str, dict]] = {i: {} for i in range(HOPS)}
    for hop, cap, res, _ in trace:
        e = own[hop].setdefault(cap, {"res": [], "unconstrained": False})
        if res:
            if res not in e["res"]:
                e["res"].append(res)
        else:
            e["unconstrained"] = True
    cum: dict[int, dict[str, dict]] = {}
    for i in reversed(range(HOPS)):
        merged = {c: {"res": list(v["res"]), "unconstrained": v["unconstrained"]}
                  for c, v in own[i].items()}
        if i + 1 < HOPS:
            for c, v in cum[i + 1].items():
                m = merged.setdefault(c, {"res": [], "unconstrained": False})
                m["res"] = m["res"] + [r for r in v["res"] if r not in m["res"]]
                m["unconstrained"] = m["unconstrained"] or v["unconstrained"]
        cum[i] = merged
    return [sorted(f"{cap}@{ANY}" if v["unconstrained"]
                   else f"{cap}@{least_general_pattern(v['res'])}"
                   for cap, v in sorted(cum[i].items())) for i in range(HOPS)]


def _filter(scope, parent):
    return [g for g in scope if scope_subset([g], parent)]



def coarsen(sub: Substrate, M: list[list[str]], level: str) -> list[list[str]]:
    out = []
    for i in range(HOPS):
        if level == "L0_exact":
            cur = list(M[i])
        elif level == "L1_family":
            cur = [f"{c}@{widen_family(p)}" for c, p in (split_grant(g) for g in M[i])]
        elif level == "L2_drop_object":
            cur = [drop_object(g) for g in M[i]]
        elif level == "L3_over_verb":
            cur = list(M[i]) + [f"{adj}@{split_grant(g)[1]}" for g in M[i]
                                for adj in sub.adjacent.get(split_grant(g)[0], [])]
        elif level == "L4_no_derivation":
            # 常量算子（spec §8.3 钉死）：与 M_i 无关；空跳也有定义。
            # 环境变量可切换为"逐条施加"读法以量化该缺口的影响。
            if os.environ.get("L4_READING") == "per_grant" and not M[i]:
                cur = []
            else:
                cur = [f"{c}@{ANY}" for c in sub.root_scope]
        else:
            raise ValueError(level)
        cur = sorted(set(cur))
        parent = out[i - 1] if i else [f"{c}@{ANY}" for c in sub.root_scope]
        out.append(_filter(cur, parent))
    return out


def evaluate(sub: Substrate, S: list[list[str]], M: list[list[str]]) -> dict:
    s = _new_system(sub.universe, sub.root_scope)
    toks = _build(s, S)
    trace = _run_task(s, toks, sub.hop_task)
    ok = sum(1 for *_, d in trace if d == "ALLOW")
    surplus = [(i, g) for i in range(HOPS) for g in S[i]
               if not scope_subset([g], M[i])]
    # **可观察 surplus（增量指标，不替换原字段）**：以该 suite 全部用户任务出现过的资源为域，
    # 只有真的多许可了某个资源才算 surplus。原字段按模式格判定，会把
    # `cap@**` 相对 `cap@*` 记为 surplus——而单段命名空间下二者匹配同一批资源。
    suite_name = sub.name.split("/")[-1]
    # 玩具基底不是基准里的 suite，没有"出现过资源全集"可依——此时不做可观察口径
    uni_res = resource_universe(suite_name) if "/" in sub.name else []
    surplus_obs = [g for i, g in surplus
                   for g in observational_surplus([g], M[i], uni_res)]

    radii = []
    variants = {k: 0 for k in sub.harm("__probe__@**")}
    for hop, g in surplus:
        cap, pat = split_grant(g)
        res = witness(pat or ANY)
        radii.append(sum(1 for j in range(HOPS) if scope_allows(S[j], cap, res)))
        for v, hit in sub.harm(g).items():
            variants[v] = variants.get(v, 0) + int(hit)
    return {"task_success": f"{ok}/{len(trace)}", "task_ok": ok == len(trace),
            "surplus_grants": len(surplus),
        "surplus_observational": len(surplus_obs),
        "harmful_observational": len({split_grant(g)[0] for g in surplus_obs}),
            "surplus_mean_radius": round(sum(radii) / len(radii), 3) if radii else 0.0,
            "harmful": variants}


LEVELS = ["L0_exact", "L1_family", "L2_drop_object", "L3_over_verb", "L4_no_derivation"]


def ladder(sub: Substrate) -> dict:
    """M 必须能复现任务——这是整个阶梯的前提，因此作为一等输出而不是隐含假设。

    能力宇宙是进程级全局状态，因此本函数**自己负责复位**：任何调用者都不应因调用它
    而让后续实验跑在错误的宇宙上。（这条修正是因为新增的粗化单调性检查泄漏了宇宙，
    污染了后续模式——由 `universe_restored` 检查抓到。）
    """
    with universe(sub.universe):
        M = observe_minimal(sub)
        exact = evaluate(sub, M, M)
        rows = [{"level": lv, **evaluate(sub, coarsen(sub, M, lv), M)} for lv in LEVELS]
        ok_all = all(r["task_ok"] for r in rows)
        return {"substrate": sub.name, "note": sub.note, "minimal_scope": M,
                "minimal_reproduces_task": exact["task_ok"],
                "minimal_task_success": exact["task_success"],
                "coarsening_preserves_task": bool(exact["task_ok"] and ok_all),
                "ladder": rows}


# ------------------------------------------------------------------ 实验
def _resource_depth(sub: Substrate) -> dict:
    """真实资源的段数分布 —— 解释 L1（族放宽）与 L2（丢对象）为何可能重合。"""
    depths: dict[int, int] = {}
    for calls in sub.hop_task.values():
        for _cap, res in calls:
            d = len([x for x in (res or "").split("/") if x])
            depths[d] = depths.get(d, 0) + 1
    return depths


def _surplus_detail(sub: Substrate, level: str) -> dict:
    """某一级 surplus 里，被基准判为恶意的具体工具。"""
    M = observe_minimal(sub)
    S = coarsen(sub, M, level)
    surplus = [g for i in range(HOPS) for g in S[i] if not scope_subset([g], M[i])]
    harmful = sorted({split_grant(g)[0] for g in surplus
                      if any(sub.harm(g).values())})
    return {"level": level, "surplus": sorted(set(surplus)), "harmful_tools": harmful}


def e26_l4_reading_sensitivity(suites=("banking", "slack", "travel", "workspace")) -> dict:
    """L4 在空跳上的两读法差异（spec §8.3 已钉死为常量读法，此处量化另一读法）。"""
    out = {}
    for mode in ("constant", "per_grant"):
        if mode == "constant":
            os.environ.pop("L4_READING", None)
        else:
            os.environ["L4_READING"] = mode
        rows = {}
        for suite in suites:
            try:
                lad = ladder(real_substrate(suite))
                rows[suite] = [r["harmful"].get("benchmark_injection_gt", 0)
                               for r in lad["ladder"]]
            except Exception as e:
                rows[suite] = f"error: {type(e).__name__}"
        out[mode] = rows
    os.environ.pop("L4_READING", None)
    diff = [s for s in out["constant"] if out["constant"][s] != out["per_grant"][s]]
    return {"constant": out["constant"], "per_grant": out["per_grant"],
            "suites_where_reading_matters": diff}


def e26_l3_reading_sensitivity(suites=("banking", "slack", "travel", "workspace")) -> dict:
    """L3 的锚定读法未在规格中定义过两种可辩护解读。此函数量化其对结论的影响，
    并强制它作为一等输出——一个定义未定而效应量差 8 倍的处置，不应单独承载结论。"""
    import os as _os
    out = {}
    for mode in ("positional", "typed"):
        _os.environ["L3_ANCHOR"] = mode
        rows = {}
        for suite in suites:
            try:
                lad = ladder(real_substrate(suite))
                rows[suite] = [r["harmful"].get("benchmark_injection_gt", 0)
                               for r in lad["ladder"]]
            except Exception as e:
                rows[suite] = f"error: {type(e).__name__}"
        out[mode] = rows
    _os.environ.pop("L3_ANCHOR", None)
    diffs = {s: (out["positional"][s] != out["typed"][s]) for s in out["positional"]}
    return {"positional": out["positional"], "typed": out["typed"],
            "suites_where_reading_matters": [s for s, d in diffs.items() if d]}


def e26_real_substrate(suites=("banking", "slack", "travel", "workspace"),
                       adjacency: str = "param") -> dict:
    """先在玩具基底复现 E11，再换真实工具集。复现不通过则新数字不可信。"""
    toy = ladder(toy_substrate())
    reset_cap_universe()
    toy_surplus = [r["surplus_grants"] for r in toy["ladder"]]
    expected = [0, 1, 8, 7, 48]

    reals = {}
    for suite in suites:
        try:
            sub = real_substrate(suite, adjacency)
            with universe(sub.universe):
                lad = ladder(sub)
            reals[suite] = {
                "adjacency_rule": adjacency,
                "universe_restored": is_toy_universe(),
                "ladder": lad["ladder"], "minimal_scope": lad["minimal_scope"],
                "minimal_reproduces_task": lad["minimal_reproduces_task"],
                "minimal_task_success": lad["minimal_task_success"],
                "note": sub.note, "resource_depth": _resource_depth(sub),
                "harm_set_size": len(sub.harm_variants["benchmark_injection_gt"]),
                "L1_detail": _surplus_detail(sub, "L1_family"),
                "L3_detail": _surplus_detail(sub, "L3_over_verb"),
            }
        except Exception as e:                      # 单 suite 失败不应拖垮整体
            reals[suite] = {"error": f"{type(e).__name__}: {e}"}
        finally:
            reset_cap_universe()
    def _inversions(rows, variant):
        seq = [(r["level"], r["surplus_grants"], r["harmful"].get(variant, 0))
               for r in rows]
        return [(a[0], b[0]) for i, a in enumerate(seq) for b in seq[i + 1:]
                if (a[1] - b[1]) * (a[2] - b[2]) < 0]

    for d in reals.values():
        if "ladder" not in d:
            continue
        d["inversions_benchmark_harm"] = _inversions(d["ladder"],
                                                     "benchmark_injection_gt")
        d["size_predicts_harm"] = not d["inversions_benchmark_harm"]
        d["worst_level"] = max(d["ladder"],
                               key=lambda r: r["harmful"].get("benchmark_injection_gt", 0)
                               )["level"]
    toy_rows = toy["ladder"]
    return {
        "l3_reading_sensitivity": e26_l3_reading_sensitivity(suites),
        "l4_reading_sensitivity": e26_l4_reading_sensitivity(suites),
        "toy_reproduction": {"surplus": toy_surplus, "expected_E11": expected,
                             "matches": toy_surplus == expected,
                             "inversions_moderate": _inversions(toy_rows, "moderate"),
                             "worst_level": max(
                                 toy_rows,
                                 key=lambda r: r["harmful"].get("moderate", 0))["level"],
                             "ladder": toy_rows},
        "real": reals}
