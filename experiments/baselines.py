"""E27：换掉退化的基线集合——同等注入下的**可达损害**对比。

存在理由：此前的三个基线没有一个是现实中真有人会选的方案——
B1 共用本方案的判定函数（同义反复）、B0 根本不实现强制（放行是定义）、
B2 是一个 13 关键词正则。于是有一个实践者必然会问、而本项目从未回答的问题：

> **为什么不干脆用一个工具给得很少的 Agent，而要搞多 Agent 委托加令牌？**

本模块把它变成可测的对照：

| 代号 | 形态 |
|---|---|
| **B3** | **单 Agent + 最小工具集**（无委托结构；一个 Agent 拿任务所需的全部工具） |
| **B4** | **多 Agent 静态配置**（按角色配置各自工具集，**无令牌层**；接收方只查自己的能力表） |
| **P** | 多 Agent + 衰减令牌 + 接收端强制 |

度量：**某个 Agent 被完全攻破后，它能促成执行的全部 (能力, 资源)**，以及其中落在
基准危害集合内的条数。

**关键前提**：P 与 B4 的差别只在 `R ⊊ 工具并集` 时才存在。若协调者本就持有全部工具
（E26 的设定正是如此），则三种形态的可达范围相同、令牌层买不到任何东西。
本模块同时报告两种情形。
"""
from __future__ import annotations

import json
import os

from src.model import CAP_UNIVERSE, Deny
from src.runtime import System

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BENCH = os.path.join(HERE, "data", "agentdojo_bench.json")

# 真实工具集上的角色划分（banking suite 的 11 个工具）。
# **这是一处研究者的划分**，但工具本身来自基准；登记表已标注。
ROLES = {
    "A": ("Coordinator", ["get_iban", "get_balance", "get_most_recent_transactions",
                          "get_scheduled_transactions", "agent.delegate"]),
    "B": ("Payment", ["send_money", "schedule_transaction",
                      "update_scheduled_transaction", "agent.delegate"]),
    "C": ("Identity", ["get_user_info", "update_password", "update_user_info",
                       "agent.delegate"]),
    "D": ("Files", ["read_file", "agent.delegate"]),
    "E": ("Audit", ["get_most_recent_transactions", "get_user_info", "agent.delegate"]),
}
RESOURCES = ["payments/p-1", "customers/c-1", "db/credentials", "orders/2024-001"]


def banking_universe() -> list[str]:
    with open(BENCH, encoding="utf-8") as f:
        return list(json.load(f)["suites"]["banking"]["tools"])


def banking_harm() -> set[str]:
    with open(BENCH, encoding="utf-8") as f:
        ex = json.load(f)["extraction"]["harm_set_from_injection_ground_truth"]
    return set(ex) & set(banking_universe())


def _build(mode: str, roles: dict) -> System:
    s = System(mode=mode, ttl=100_000, pull_interval=10)
    for sid, (role, scope) in roles.items():
        s.add_agent(sid, role, scope)
    return s


def _try_all(s, frm: str, to: str, token_id: str, task: str, caps, reach: set) -> None:
    for cap in caps:
        for res in RESOURCES:
            try:
                r = s.request(frm, to, token_id, cap, res, task)
            except Deny:
                continue
            if r.decision == "ALLOW":
                reach.add((cap, res))


def reach_under_compromise(mode: str, roles: dict, universe: list[str],
                           attacker: str = "A") -> set:
    """攻破 `attacker` 后，它能促成执行的全部 (能力, 资源)。"""
    reach: set[tuple[str, str]] = set()
    a_scope = set(roles[attacker][1])
    target_caps = {"B4": lambda t: set(roles[t][1]),      # 接收方自己的能力表
                   "B0": lambda t: set(universe),          # 无任何强制
                   "B2": lambda t: set(universe),          # 只看文本
                   "P": lambda t: a_scope}                 # 只能在自己的范围内驱使他人

    for target, (_role, _scope) in roles.items():
        if target == attacker:
            continue
        s = _build(mode, roles)
        token_id = ""
        if mode == "P":
            # 被攻破的协调者可以**铸出自己权限内的全部令牌**——这是它应有的能力上限
            tok = s.delegate(attacker, target, sorted(a_scope - {"agent.delegate"}),
                             f"evil-{target}")
            token_id = tok.token_id
        else:
            token_id = s.peps[attacker].root.token_id
        _try_all(s, attacker, target, token_id, f"evil-{target}",
                 sorted(target_caps[mode](target)), reach)
    # 被攻破者对**自身**权限的直接使用
    for cap in sorted(a_scope):
        for res in RESOURCES:
            reach.add((cap, res))
    return reach


def task_minimal_scope(suite: str = "banking") -> list[str]:
    """任务必需的工具集：取该 suite 中 ground_truth 调用最多的用户任务。"""
    with open(BENCH, encoding="utf-8") as f:
        tasks = json.load(f)["suites"][suite]["user_tasks"]
    task = sorted(tasks, key=lambda u: (-len(u["ground_truth"]), u["id"]))[0]
    return task["id"], sorted({c["function"] for c in task["ground_truth"]})


def e27_scope_sweep(steps: int = 5) -> list[dict]:
    """**核心对照**：把协调者的常备权限从"任务最小"扫到"全部工具并集"，
    比较它与「单 Agent + 任务最小工具集」在被攻破后的可达范围。

    这回答的是"这个架构什么时候有用"——而不是"它有没有用"。
    """
    uni = banking_universe()
    harm = banking_harm()
    tid, minimal = task_minimal_scope()
    rows = []
    for i in range(steps + 1):
        extra = (len(uni) - len(minimal)) * i // steps
        # α=1.0 的端点：协调者恰好只持任务最小集（此时它无法委托，架构退化为单 Agent）
        scope = sorted(set(minimal) if i == 0 else
                       (set(minimal) | set(uni[:extra]) | {"agent.delegate"}))
        roles = {k: (v[0], list(scope) if k == "A" else [
            c for c in v[1] if c != "agent.delegate"]) for k, v in ROLES.items()}
        roles["A"] = ("Coordinator", scope)
        r_p = reach_under_compromise("P", roles, uni, "A")
        # P 的正当代价：**下游**被攻破时的可达范围（这是令牌层真正起作用的地方）
        r_p_leaf = reach_under_compromise("P", roles, uni, "D")
        r_b4_leaf = reach_under_compromise("B4", roles, uni, "D")
        reach_min = len(minimal) * len(RESOURCES)
        rows.append({
            "P_leaf_reach": len(r_p_leaf),
            "B4_leaf_reach": len(r_b4_leaf),
            "token_layer_helps_leaf": len(r_p_leaf) < len(r_b4_leaf),
            "coordinator_scope_size": len(scope),
            "alpha_over_task_minimal": round(len(scope) / len(minimal), 2),
            "P_reach": len(r_p),
            "P_reach_harm": len({c for c, _ in r_p} & harm),
            "B3_task_minimal_reach": reach_min,
            "B3_task_minimal_harm": len(set(minimal) & harm),
            "P_worse_than_B3": len(r_p) > reach_min,
        })
    return rows


def e27_baseline_reach(structured: bool = True) -> dict:
    """结构化（R ⊊ 并集）与协调者持全集两种情形下的可达范围对比。"""
    uni = banking_universe()
    harm = banking_harm()
    union = sorted({c for _r, sc in ROLES.values() for c in sc})

    out: dict = {"universe": uni, "union_size": len(union), "harm_set": sorted(harm),
                 "roles": {k: v[1] for k, v in ROLES.items()}}
    rows = []
    for mode in ("P", "B4", "B0"):
        r = reach_under_compromise(mode, ROLES, uni, "A")
        rows.append({"mode": mode, "reach": len(r),
                     "reach_harm": len({c for c, _ in r} & harm),
                     "reach_caps": sorted({c for c, _ in r})})
    # B3：单 Agent 持并集
    rows.append({"mode": "B3", "reach": len(union) * len(RESOURCES),
                 "reach_harm": len(set(union) & harm),
                 "reach_caps": union,
                 "note": "单 Agent 持任务所需的全部工具；无委托结构"})
    out["structured_R_subset_of_union"] = rows

    # 对照情形：协调者本就持有全部工具（E26 的设定）
    flat = {k: (v[0], list(uni) if k == "A" else v[1]) for k, v in ROLES.items()}
    rows2 = []
    for mode in ("P", "B4"):
        r = reach_under_compromise(mode, flat, uni, "A")
        rows2.append({"mode": mode, "reach": len(r),
                      "reach_harm": len({c for c, _ in r} & harm)})
    rows2.append({"mode": "B3", "reach": len(uni) * len(RESOURCES),
                  "reach_harm": len(set(uni) & harm)})
    out["flat_coordinator_holds_all"] = rows2
    tid, minimal = task_minimal_scope()
    out["task_minimal"] = {"task": tid, "tools": minimal}
    out["scope_sweep"] = e27_scope_sweep()
    out["note"] = ("可达 = 攻破 A 后能促成执行的 (能力, 资源) 对数；"
                   "reach_harm 为其能力落在基准危害集合内的条数")
    return out


# ------------------------------------------------------------------ E31
def e31_collusion_real() -> dict:
    """**真实串通演示**——取代此前的算术恒等式。

    旧版 E9 只对串通者的根授权求并集再比大小，**没有执行任何攻击**，
    因此"敏感能力不可达恒 0"由"该集合从未被签发"保证，是恒等式而非实验。

    这里演示**分时串通**：X 在自身范围内读、把数据交给 Y，Y 在自身范围内外传。
    **每一步都不越界，每一次判定都通过。** 结果是架构对串通零遏制——
    一个负面结论，但它是真的被演示出来的。
    """
    s = System(mode="P", ttl=100_000, pull_interval=10)
    s.add_agent("COORD", "Coordinator", ["read_orders", "read_customers", "net.external",
                                         "agent.delegate"])
    s.add_agent("X", "Reader", ["read_customers", "agent.delegate"])
    s.add_agent("Y", "Exporter", ["net.external", "agent.delegate"])
    tx = s.delegate("COORD", "X", ["read_customers"], "task-x")
    ty = s.delegate("COORD", "Y", ["net.external"], "task-y")

    # 步骤 1：X 在自身范围内读（合法）
    r1 = s.request("COORD", "X", tx.token_id, "read_customers", "customers/c-1", "task-x")
    # 步骤 2：X 把数据交给 Y —— 发生在能力体系之外，无请求、无判定
    handoff = {"from": "X", "to": "Y", "payload": "customers/c-1 的内容", "mediated": False}
    # 步骤 3：Y 在自身范围内外传（合法）
    r2 = s.request("COORD", "Y", ty.token_id, "net.external", "customers/c-1", "task-y")

    violations = [r for r in (r1, r2) if r.decision != "ALLOW"]
    # 对照：同一目标若由**单个**主体一次完成，需要两项能力落在同一令牌内
    s2 = System(mode="P", ttl=100_000, pull_interval=10)
    s2.add_agent("COORD", "C", ["read_customers", "net.external", "agent.delegate"])
    s2.add_agent("Z", "Z", ["read_customers", "agent.delegate"])
    tz = s2.delegate("COORD", "Z", ["read_customers"], "task-z")
    r3 = s2.request("COORD", "Z", tz.token_id, "read_customers", "customers/c-1", "task-z",
                    required=("net.external@customers/c-1",))
    return {
        "read_decision": r1.decision, "export_decision": r2.decision,
        "handoff_mediated_by_architecture": handoff["mediated"],
        "steps_that_violated_a_scope": len(violations),
        "collusion_achieved_exfiltration": (r1.decision == "ALLOW"
                                            and r2.decision == "ALLOW"),
        "single_agent_compound_decision": r3.decision,
        "single_agent_compound_reason": r3.reason_code,
        "note": "每一步都合法 ⇒ 判定链上没有任何一处能看见串通。"
                "单主体复合动作能被挡，只是因为两项能力必须落在同一令牌内——"
                "而串通者不需要同令牌，它们分时用各自的范围。",
    }
