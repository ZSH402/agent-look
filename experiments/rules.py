"""四级粗化所依赖的**规则**——单一实现，供两条基底路径共用。

存在理由：E28/E29/E30 证明这些规则**本身**就能翻转结论
（参数名相邻 → 假的"排序不可迁移"；族放宽末段 → 假的"四级阶梯"）。
但规则先前在 `substrate.py`（链形、E26 那一路）与 `derived_topology.py`（星形、E28 那一路）
里**各写了一份**——同一件被证明影响结论的东西有两份实现，本身就是风险。

本模块把规则收拢到一处。两条路径只允许从这里取规则，不得自带副本。

**这些规则没有外部真值可锚**（基准不定义"对象族"或"动词相邻"），因此每一条都必须
可被枚举成若干可辩护读法并逐一说清，见 `L3_READINGS` 与 `adjacency()` 的 `kind` 参数。
"""
from __future__ import annotations

import json
import os

from src.patterns import ANY, parse, scope_allows, split_grant

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BENCH = os.path.join(HERE, "data", "agentdojo_bench.json")

_CACHE: dict = {}


def bench() -> dict:
    if "b" not in _CACHE:
        with open(BENCH, encoding="utf-8") as f:
            _CACHE["b"] = json.load(f)
    return _CACHE["b"]


# ------------------------------------------------------------------ L1
def widen_family(pattern: str) -> str:
    """L1「对象族放宽」：把模式末段换成 `*`；已含 `**` 者取 `**`。

    **放宽只允许变宽**——早期实现对已是 `**` 的模式做"末段换 `*`"，把它收窄成只匹配
    单段资源，反而使任务失败。

    **注意（E29）**：该规则的全部语义依赖资源是分层的。四个 suite 的资源串**全为单段**，
    因此 `*` 与 `**` 匹配同一批资源，**L1 与 L2 在可观察层面等价**。
    本函数保留两个级别是为了不破坏已独立复现过的五级编号，但正文必须说明二者等价。
    """
    segs, dstar = parse(pattern)
    if dstar or not segs:
        return ANY
    return "/".join(list(segs[:-1]) + ["*"])


# ------------------------------------------------------------------ L2
def drop_object(grant: str) -> str:
    """L2「丢掉对象约束」：`cap@pat` → `cap`（即 `cap@**`）。"""
    return split_grant(grant)[0]


# ------------------------------------------------------------------ L3
def verb_token(tool: str) -> str:
    return tool.split("_")[0]


L3_READINGS = ("same_object_all", "same_object_same_effect",
               "same_object_diff_effect", "same_verb_other_object", "none")


def l3_adjacency(suite: str, reading: str) -> dict[str, list[str]]:
    """L3「动词过泛」的相邻集合。**方向本身是研究者选择，且改变结论（E30）**：

      - `same_object_all`：同对象的其它全部工具（最宽的同对象读法）
      - `same_object_same_effect`：同对象、且**可变性相同**的其它工具
      - `same_object_diff_effect`：同对象、**可变性不同**的工具
      - `same_verb_other_object`：**同动词类别、不同对象**（即 L2 的方向）
      - `none`：无相邻（L3 退化为 L0，已不是粗化）
    """
    b = bench()
    meta = b["tools"]
    uni = b["suites"][suite]["tools"]
    obj_of = object_of(suite)
    out: dict[str, list[str]] = {}
    for t in uni:
        o = obj_of.get(t)
        sib = [x for x in uni if obj_of.get(x) == o and x != t] if o else []
        if reading == "same_object_all":
            adj = sib
        elif reading == "same_object_same_effect":
            adj = [x for x in sib if meta[x]["mutates"] == meta[t]["mutates"]]
        elif reading == "same_object_diff_effect":
            adj = [x for x in sib if meta[x]["mutates"] != meta[t]["mutates"]]
        elif reading == "same_verb_other_object":
            adj = [x for x in uni if x != t and verb_token(x) == verb_token(t)]
        elif reading == "none":
            adj = []
        else:
            raise ValueError(reading)
        out[t] = sorted(set(adj))
    return out


# ------------------------------------------------------------------ 相邻（L1/L2 之外）与归属
def object_of(suite: str) -> dict[str, str]:
    """工具 → 它操作的环境对象（取自基准的 `Depends`）。"""
    b = bench()
    return {t: b["tools"][t]["depends_on"] for t in b["suites"][suite]["tools"]
            if b["tools"][t].get("depends_on")}


def adjacency_param(suite: str) -> dict[str, list[str]]:
    """参数名相邻规则（E26 用的）。

    **E28 证明它是错误代理**：它使 banking 在两种拓扑下都违反 L1≤L2≤L3，
    从而制造出「排序不可迁移」这一虚假结论。保留仅为对照。
    """
    b = bench()
    meta = b["tools"]

    def first(t):
        ps = meta.get(t, {}).get("params", [])
        return ps[0]["name"] if ps else None

    by: dict = {}
    for t in meta:
        k = first(t)
        if k:
            by.setdefault(k, []).append(t)
    return {t: [x for x in by.get(first(t), []) if x != t] for t in meta}


def adjacency_object(suite: str) -> dict[str, list[str]]:
    """环境对象相邻规则（由基准的 `Depends` 归属导出）。"""
    obj = object_of(suite)
    by: dict[str, list[str]] = {}
    for t, o in obj.items():
        by.setdefault(o, []).append(t)
    return {t: [x for x in by.get(o, []) if x != t] for t, o in obj.items()}


def adjacency(suite: str, kind: str = "object") -> dict[str, list[str]]:
    if kind == "object":
        return adjacency_object(suite)
    if kind == "param":
        return adjacency_param(suite)
    raise ValueError(kind)


# ------------------------------------------------------------------ 资源域与 surplus 口径
def resource_universe(suite: str) -> list[str]:
    """该 suite **全部用户任务**里出现过的资源串。用作可观察 surplus 的判定域。"""
    b = bench()
    res: set[str] = set()
    for t in b["suites"][suite]["user_tasks"]:
        for c in t["ground_truth"]:
            for prm in b["tools"].get(c["function"], {}).get("params", []):
                v = c["args"].get(prm["name"])
                if isinstance(v, str) and v:
                    res.add(v)
    return sorted(res)


def observational_surplus(scope, minimal, universe_res) -> list[str]:
    """**可就观察 surplus**：只有真的在 `universe_res` 上多许可了某资源才算。

    按**模式格**判 surplus 会把 `cap@**` 相对 `cap@*` 记为 surplus——
    而单段命名空间下二者许可同一批资源（E29 发现的虚增）。
    """
    out = []
    for g in scope:
        cap, _p = split_grant(g)
        if any(scope_allows([g], cap, r) and not scope_allows(minimal, cap, r)
               for r in universe_res):
            out.append(g)
    return out
