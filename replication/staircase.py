"""R2：过近似阶梯（spec §8）。基底 = AgentDojo banking suite。"""
from __future__ import annotations

import json
from pathlib import Path

import patterns as P

DATA = Path(__file__).resolve().parent.parent / "data" / "agentdojo_bench.json"
HOPS = 4


def load():
    return json.loads(DATA.read_text())


# ------------------------------------------------------------------ §8.1 输入
def first_string_value(args: dict) -> str | None:
    for v in args.values():
        if isinstance(v, str):
            return v
    return None


def pick_task(suite: dict) -> dict:
    best = None
    for t in suite["user_tasks"]:
        k = len(t["ground_truth"])
        key = (-k, t["id"])
        if best is None or key < best[0]:
            best = (key, t)
    return best[1]


def map_calls(task: dict) -> list[dict]:
    calls = []
    for i, gt in enumerate(task["ground_truth"]):
        s = first_string_value(gt["args"])
        calls.append(
            {
                "index": i,
                "hop": i % HOPS,
                "capability": gt["function"],
                "resource": "" if s is None else s,
                "raw_args": gt["args"],
            }
        )
    return calls


# --------------------------------------------------------------- §8.2 M 的构造
def least_general_pattern(resources: list[str], has_ressourceless: bool) -> str:
    if has_ressourceless:
        return "**"
    segs = [r.split("/") if r != "" else [""] for r in resources]
    m = min(len(s) for s in segs)
    out = []
    for j in range(m):
        col = {s[j] for s in segs}
        out.append(col.pop() if len(col) == 1 else "*")
    if any(len(s) != m for s in segs):
        out.append("**")
    return "/".join(out)


def compute_M(calls: list[dict]) -> list[set[str]]:
    """M_i 覆盖第 i 跳自身与全部下游跳的需求（§8.2 第 2 条）。"""
    M = []
    for i in range(HOPS):
        subset = [c for c in calls if c["hop"] >= i]
        groups: dict[str, list[dict]] = {}
        for c in subset:
            groups.setdefault(c["capability"], []).append(c)
        scope = set()
        for cap, cs in groups.items():
            no_str = any(
                not any(isinstance(v, str) for v in c["raw_args"].values())
                for c in cs
            )
            pat = least_general_pattern([c["resource"] for c in cs], no_str)
            scope.add(f"{cap}@{pat}")
        M.append(scope)
    return M


# ------------------------------------------------------------------ §8.3 粗化
def _widen_last_segment(pat: str) -> str:
    """L1：末段换 '*'；已含 '**' 则保持 '**'（只许放宽）。"""
    if pat == "" or pat.split("/")[-1] == "**":
        return pat
    segs = pat.split("/")
    return "/".join(segs[:-1] + ["*"])


def anchor_param(tool_meta: dict, mode: str = "canonical") -> str | None:
    """§8.3 L3 的锚定参数名。

    canonical：提取后参数表中的第一个（Depends 参数已在提取阶段排除）；无参数则为 None。
    str_typed：备选读法——首个类型含 'str' 的参数（首轮复现所用；规格 §8.3 要求同时报告）。
    """
    params = tool_meta.get("params", [])
    if mode == "canonical":
        return params[0]["name"] if params else None
    for p in params:
        if isinstance(p.get("type"), str) and "str" in p["type"]:
            return p["name"]
    return None


def coarsen(
    level: str,
    M: list[set[str]],
    R: set[str],
    tools: dict,
    U: set[str] | None = None,
    anchor_mode: str = "canonical",
) -> list[set[str]]:
    universe = set(tools) if U is None else set(U)
    raw = []
    for i in range(HOPS):
        if level == "L4_no_derivation" and anchor_mode != "per_entry":
            # L4 是常量算子（"R 的全部能力，模式 **"），与 M_i 是否为空无关。
            raw.append(set(R))
            continue
        out = set()
        for e in M[i]:
            cap, pat = P.parse_entry(e)
            if level == "L0_exact":
                out.add(e)
            elif level == "L1_family":
                out.add(f"{cap}@{_widen_last_segment(pat)}")
            elif level == "L2_drop_object":
                out.add(f"{cap}@**")
            elif level == "L3_over_verb":
                out.add(e)
                anchor = anchor_param(tools.get(cap, {}), anchor_mode)
                if anchor is not None:
                    for other in universe:
                        if anchor_param(tools.get(other, {}), anchor_mode) == anchor:
                            out.add(f"{other}@{pat}")
            elif level == "L4_no_derivation":
                out |= R
        raw.append(out)

    # 逐跳过滤到 ⊆ 上一级（第 0 跳 ⊆ R），保证衰减合法
    S = []
    for i in range(HOPS):
        parent = R if i == 0 else S[i - 1]
        S.append({e for e in raw[i] if any(P.entry_subsumes(e, pe) for pe in parent)})
    return S


# ------------------------------------------------------------------ §8.4 度量
def surplus_of(S: list[set[str]], M: list[set[str]]) -> list[tuple[int, str]]:
    out = []
    for i in range(HOPS):
        flt = [e for e in S[i] if not any(P.entry_subsumes(e, m) for m in M[i])]
        out.extend((i, e) for e in sorted(flt))
    return out


def witness(pat: str) -> str:
    """pat 内取一个具体资源；pat 为 '**' 时取任一段资源。"""
    if pat == "" or pat == "**":
        return "w"
    segs = pat.split("/")
    if segs[-1] == "**":
        return "/".join(("w" if s == "*" else s) for s in segs[:-1]) + "/w"
    return "/".join("w" if s == "*" else s for s in segs)


def radius(entry: str, S: list[set[str]]) -> int:
    cap, pat = P.parse_entry(entry)
    w = witness(pat)
    return sum(1 for j in range(HOPS) if P.scope_allows(S[j], cap, w))


def task_success(S: list[set[str]], calls: list[dict]) -> tuple[int, int]:
    ok = sum(1 for c in calls if P.scope_allows(S[c["hop"]], c["capability"], c["resource"]))
    return ok, len(calls)
