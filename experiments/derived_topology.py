"""E28：把委托**拓扑**从"研究者发明"换成"基准自身的环境对象分解"。

存在理由：支柱 B 剩下最大的未锚定输入是拓扑。E26 的真实基底里，任务调用是
**我按 `i % 4` 摊到 4 跳链**上的，下游根范围也是我取的——登记表因此把 `task_real`
标为 `mixed` 而非 `external`。

但 AgentDojo 的 `TaskEnvironment` **本身就给出了环境对象分解**
（banking: `bank_account` / `filesystem` / `user_account`；workspace: `inbox` / `calendar` / `cloud_drive`），
而每个工具的 `Depends("对象")` 说明了它操作哪个对象。于是：

> **一个环境对象一个 Agent；工具按其 `Depends` 归属；协调者向各对象 Agent 分派。**

拓扑成为**基准的函数**，而不是我的发明。与 E26 的 4 跳链相比，这里是**星形、深度 1**。

E26 的结论（L1/L2/L3 排序不可跨基底迁移、最危险级恒为 L4）是否在这个导出拓扑上仍成立，
正是本模块要回答的问题。
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field

from src.model import CAP_UNIVERSE, Deny, reset_cap_universe
from src.patterns import ANY, least_general_pattern, scope_allows, scope_subset, split_grant, witness
from src.runtime import System
from src.tokens import attenuate, root_token

from .rules import (L3_READINGS, adjacency, drop_object, l3_adjacency,
                    observational_surplus, resource_universe, widen_family)

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BENCH = os.path.join(HERE, "data", "agentdojo_bench.json")
COORD = "COORD"


def _bench() -> dict:
    with open(BENCH, encoding="utf-8") as f:
        return json.load(f)


def derived_roles(suite: str) -> dict[str, list[str]]:
    """由基准的环境对象分解导出角色：一个环境对象一个 Agent。"""
    b = _bench()
    roles: dict[str, list[str]] = {}
    for t in b["suites"][suite]["tools"]:
        obj = b["tools"][t].get("depends_on")
        if obj:
            roles.setdefault(obj, []).append(t)
    return {k: sorted(v) for k, v in sorted(roles.items())}


def pick_task(suite: str) -> dict:
    b = _bench()
    tasks = b["suites"][suite]["user_tasks"]
    return sorted(tasks, key=lambda u: (-len(u["ground_truth"]), u["id"]))[0]


def routed_calls(suite: str, roles: dict[str, list[str]]) -> tuple[dict, list[str]]:
    """把任务的 ground_truth 调用按**工具归属对象**路由到各 Agent。"""
    b = _bench()
    task = pick_task(suite)
    owner = {t: a for a, ts in roles.items() for t in ts}
    by_agent: dict[str, list[tuple[str, str]]] = {}
    unrouted = []
    for call in task["ground_truth"]:
        fn = call["function"]
        a = owner.get(fn)
        if a is None:
            unrouted.append(fn)
            continue
        prim = next((v for p in b["tools"].get(fn, {}).get("params", [])
                     for v in [call["args"].get(p["name"])] if isinstance(v, str)), "")
        by_agent.setdefault(a, []).append((fn, prim))
    return {"task": task["id"], "by_agent": by_agent, "unrouted": unrouted}, unrouted


@dataclass
class Star:
    suite: str
    roles: dict[str, list[str]]
    agent_task: dict[str, list[tuple[str, str]]]
    task_id: str
    note: str = ""
    extra: dict = field(default_factory=dict)


def build_star(suite: str) -> Star:
    roles = derived_roles(suite)
    routed, unrouted = routed_calls(suite, roles)
    return Star(suite=suite, roles=roles, agent_task=routed["by_agent"],
                task_id=routed["task"],
                note=f"环境对象导出的星形拓扑：{list(roles)}；未路由 {unrouted}")


# ------------------------------------------------------------------ 机制
def _system_universe(suite: str) -> list[str]:
    a = sorted({c for ts in derived_roles(suite).values() for c in ts})
    root = _bench()["suites"][suite]["tools"]
    return sorted(set(a) | set(root))


def _build(s: System, roles: dict, per_agent_scope: dict) -> dict:
    """协调者向各对象 Agent 各建一条委托（星形，深度 1）。"""
    toks = {}
    for agent, scope in per_agent_scope.items():
        if not scope:
            continue
        try:
            toks[agent] = attenuate(s.peps[COORD].root, agent, scope, f"t-{agent}",
                                    s.now + 10_000, s.authority.registry[COORD],
                                    s.peps[COORD].sk, s.now)
            s.peps[agent].accept_token(toks[agent])
        except Deny:
            pass
    return toks


def _run_task(s: System, toks: dict, star: Star) -> list[tuple]:
    trace = []
    for agent, calls in star.agent_task.items():
        tok = toks.get(agent)
        for cap, res in calls:
            if tok is None:
                trace.append((agent, cap, res, "DENY", "NO_TOKEN"))
                continue
            r = s.request(COORD, agent, tok.token_id, cap, res or "x", tok.task_id)
            trace.append((agent, cap, res, r.decision, r.reason_code))
    return trace


def observe_minimal(star: Star) -> dict[str, list[str]]:
    """每个 Agent 的最小必要范围 = 它的任务调用（星形无下游累积）。"""
    out = {}
    for agent, calls in star.agent_task.items():
        per: dict[str, list[str]] = {}
        unconstrained = set()
        for cap, res in calls:
            if res:
                per.setdefault(cap, []).append(res)
            else:
                unconstrained.add(cap)
                per.setdefault(cap, [])
        out[agent] = sorted(
            f"{cap}@{ANY}" if cap in unconstrained else f"{cap}@{least_general_pattern(rs)}"
            for cap, rs in per.items())
    return out


def coarsen(star: Star, M: dict, level: str, root_caps: list[str],
            redundancy: dict, adjacency_kind: str = "object") -> dict:
    """四级粗化，逐 Agent 施加，再过滤到 ⊆ 协调者根授权。

    `adjacency` 决定 L3「动词过泛」的相邻集合如何取——它是 L3 结果的全部来源，
    因此必须与拓扑分开归因：
      - `object`：同一**环境对象**下的其它工具（由基准的归属导出）
      - `param`：首个**非环境参数名相同**的其它工具（E26 用的规则）
    """
    adj = (globals().get("_ADJ_OVERRIDE")
           or adjacency(star.suite, adjacency_kind))
    out = {}
    for agent, grants in M.items():
        if level == "L0_exact":
            cur = list(grants)
        elif level == "L1_family":
            cur = [f"{c}@{widen_family(p)}" for c, p in (split_grant(g) for g in grants)]
        elif level == "L2_drop_object":
            cur = [drop_object(g) for g in grants]
        elif level == "L3_over_verb":
            cur = list(grants) + [f"{x}@{split_grant(g)[1]}" for g in grants
                                  for x in adj.get(split_grant(g)[0], [])]
        elif level == "L4_no_derivation":
            cur = [f"{c}@{ANY}" for c in (redundancy.get(agent) or root_caps)]
        else:
            raise ValueError(level)
        cur = sorted(set(cur))
        parent = [f"{c}@{ANY}" for c in root_caps]
        out[agent] = [g for g in cur if scope_subset([g], parent)]
    return out


def evaluate(star: Star, S: dict, M: dict, harm: set) -> dict:
    uni = _system_universe(star.suite)
    with _universe(uni):
        s = System(mode="P", ttl=100_000, pull_interval=10)
        s.add_agent(COORD, "Coordinator", list(uni))
        for agent in star.roles:
            s.add_agent(agent, "Worker", [])
        toks = _build(s, star.roles, S)
        trace = _run_task(s, toks, star)
    ok = sum(1 for *_x, d, _r in trace if d == "ALLOW")
    surplus = [g for a in S for g in S[a] if not scope_subset([g], M.get(a, []))]
    # **可观察 surplus**：以基准导出的资源全集为域，只有真的多许可了某个资源才算 surplus。
    universe_res = resource_universe(star.suite)
    obs_surplus = [g for a in S
                   for g in observational_surplus(S[a], M.get(a, []), universe_res)]
    surplus = obs_surplus
    radii = []
    for g in surplus:
        cap, pat = split_grant(g)
        res = witness(pat or ANY)
        radii.append(sum(1 for a in S if scope_allows(S[a], cap, res)))
    return {"task_success": f"{ok}/{len(trace)}", "task_ok": ok == len(trace),
            "surplus_grants": len(surplus),
            "resource_universe_size": len(universe_res),
            "surplus_definition": "observational",
            "surplus_mean_radius": round(sum(radii) / len(radii), 3) if radii else 0.0,
            "harmful": len({split_grant(g)[0] for g in surplus
                            if split_grant(g)[0] in harm})}


from contextlib import contextmanager


@contextmanager
def _universe(names):
    from src.model import current_universe, set_cap_universe
    prev = current_universe()
    set_cap_universe(names)
    try:
        yield
    finally:
        set_cap_universe(prev)


LEVELS = ["L0_exact", "L1_family", "L2_drop_object", "L3_over_verb", "L4_no_derivation"]


def ladder(suite: str, adjacency: str = "object") -> dict:
    b = _bench()
    star = build_star(suite)
    harm = set(b["extraction"]["harm_set_from_injection_ground_truth"])
    M = observe_minimal(star)
    root_caps = _system_universe(suite)
    rows = []
    for lv in LEVELS:
        redundancy = {} if lv != "L4_no_derivation" else {}
        rows.append({"level": lv,
                     **evaluate(star, coarsen(star, M, lv, root_caps, redundancy,
                                              adjacency), M, harm)})
    return {"suite": suite, "roles": star.roles, "task": star.task_id,
            "routed": {k: [c for c, _ in v] for k, v in star.agent_task.items()},
            "note": star.note, "adjacency_rule": adjacency,
            "minimal_scope": M, "ladder": rows,
            "minimal_reproduces_task": rows[0]["task_ok"]}


def e28_derived_topology(suites=("banking", "workspace", "travel", "slack"),
                        adjacency: str = "object") -> dict:
    out = {}
    for suite in suites:
        try:
            out[suite] = ladder(suite, adjacency)
        except Exception as e:                      # noqa: BLE001
            out[suite] = {"error": f"{type(e).__name__}: {e}"}
        finally:
            reset_cap_universe()
    return out


# ------------------------------------------------------------------ E29
def all_resources(suite: str) -> list[str]:
    """该基底里**出现过的全部资源串**：任务实参 + 各模式的 witness。"""
    b = _bench()
    res: set[str] = set()
    for c in pick_task(suite)["ground_truth"]:
        for prm in b["tools"].get(c["function"], {}).get("params", []):
            v = c["args"].get(prm["name"])
            if isinstance(v, str) and v:
                res.add(v)
    star = build_star(suite)
    for grants in observe_minimal(star).values():
        for g in grants:
            res.add(witness(split_grant(g)[1] or ANY))
    return sorted(res)
    # （返回列表；上方 `res` 为集合，下面统一转列表）


def e29_level_definition_audit(suites=("banking", "slack", "travel", "workspace")) -> dict:
    """审计 L1 与 L2 的**规则本身**是否只是模式格上的差别、而非可观察差别。

    L1「对象族放宽 = 末段换成 `*`」的语义**完全依赖资源是分层的**。
    若基底里的资源串全是单段（银行 IBAN、地址；slack 频道名；travel 城市名），
    则 `*` 与 `**` 匹配的资源集合相同——两级在可观察层面等价。
    """
    from src.patterns import matches, parse
    out = {}
    for suite in suites:
        star = build_star(suite)
        M = observe_minimal(star)
        resources = all_resources(suite)
        depths: dict[int, int] = {}
        for r in resources:
            depths[len(r.split("/"))] = depths.get(len(r.split("/")), 0) + 1
        # 逐 grant 比较 L1 与 L2 模式在**全部出现过资源**上的匹配是否一致
        diff = []
        for a, grants in M.items():
            for g in grants:
                cap, pat = split_grant(g)
                p1, p2 = widen_family(pat), ANY
                if any(matches(p1, r) != matches(p2, r) for r in resources):
                    diff.append(f"{cap}@{pat}")
        out[suite] = {"resources": len(resources), "depth_hist": depths,
                      "L1_L2_observationally_equal": not diff,
                      "differing_grants": diff,
                      "hierarchical_resources": sum(v for k, v in depths.items() if k > 1)}
    return out


# ------------------------------------------------------------------ E30


def e30_l3_reading_sensitivity(suites=("banking", "slack", "travel", "workspace")) -> dict:
    """把 L3 的相邻集合在**可辩护读法**间扫描，看支柱 B 的结论是否稳健。"""
    res: dict = {}
    for suite in suites:
        b = _bench()
        harm = set(b["extraction"]["harm_set_from_injection_ground_truth"])
        star = build_star(suite)
        M = observe_minimal(star)
        rc = _system_universe(suite)
        base = {lv: {"harm": evaluate(star, coarsen(star, M, lv, rc, {}), M, harm)["harmful"]}
                for lv in ("L0_exact", "L1_family", "L2_drop_object")}
        row = {}
        for reading in L3_READINGS:
            globals()["_ADJ_OVERRIDE"] = l3_adjacency(suite, reading)
            try:
                S = coarsen(star, M, "L3_over_verb", rc, {})
            finally:
                globals().pop("_ADJ_OVERRIDE", None)
            ev = evaluate(star, S, M, harm)
            row[reading] = {
                "l3_surplus": ev["surplus_grants"], "l3_harm": ev["harmful"],
                "seq_L0L1L2L3": [base["L0_exact"]["harm"], base["L1_family"]["harm"],
                                 base["L2_drop_object"]["harm"], ev["harmful"]],
                "monotone_L1L2L3": (base["L1_family"]["harm"]
                                    <= base["L2_drop_object"]["harm"] <= ev["harmful"]),
                "L3_strictly_worse_than_L2": ev["harmful"] > base["L2_drop_object"]["harm"]}
        res[suite] = row
    return res
