"""资源模式：受限语法，保证包含关系可判定。

语法（刻意受限，以便 subsumption 判定可证且廉价）：

    PATTERN := segment ( "/" segment )* [ "**" ]
    segment := 字面量 | "*"
    "**" 只能作为最后一段，表示"任意剩余段（含零段）"
    空模式 "" 等价于 "**"

scope 条目形如 `capability@pattern`；不含 `@` 的条目等价于 `capability@**`，
即"该能力作用于任意资源"（裸动词集合 = 本模块的最粗粒度情形）。

设计取舍：不做通用正则，因为通用正则的包含问题是 PSPACE 完全的，
而授权判定必须离线、常量时间量级完成。
"""
from __future__ import annotations

ANY = "**"


def parse(pattern: str) -> tuple[tuple[str, ...], bool]:
    """返回 (段列表, 是否以 ** 结尾)。"""
    # **不做斜杠归一化**：早期实现 `strip("/")` 会把 "a/"、"//a" 与 "a" 视为同一资源，
    # 属规格未授权的行为，且是路径归一化类授权绕过的经典来源（差分测试发现）。
    p = pattern or ""
    if p.strip() == "" or p.strip() == ANY:
        return (), True
    segs = p.split("/")
    if segs and segs[-1] == ANY:
        return tuple(segs[:-1]), True
    return tuple(segs), False


def _seg_sub(a: str, b: str) -> bool:
    """段 a 的语言 ⊆ 段 b 的语言。"""
    return b == "*" or a == b


EMPTY_SEG_MSG = "段不得为空"


def _has_empty_segment(parts) -> bool:
    return any(x == "" for x in parts)


def matches(pattern: str, resource: str) -> bool:
    """资源串是否落在模式的语言内。

    **段不得为空**：含空段（前导/尾随/连续斜杠）的资源串**不匹配任何有约束的模式**。
    这是差分测试后钉死的规则——早期实现静默 `strip("/")`，把 `a/` 与 `a` 视为同一资源，
    既无规格授权，又是路径归一化类授权绕过的经典来源。
    """
    segs, dstar = parse(pattern)
    if not segs and dstar:                 # 无条件模式：匹配一切，含退化资源
        return True
    rs = (resource or "").split("/")
    if _has_empty_segment(rs) or _has_empty_segment(segs):
        return False
    if dstar:
        if len(rs) < len(segs):
            return False
        return all(segs[i] == "*" or rs[i] == segs[i] for i in range(len(segs)))
    if len(rs) != len(segs):
        return False
    return all(segs[i] == "*" or rs[i] == segs[i] for i in range(len(segs)))


def subsumes(p: str, q: str) -> bool:
    """p 的语言 ⊆ q 的语言（p 比 q 更具体或相等）。

    与 `matches` 保持同一套空段规则，否则二者会不自洽——而那正是不健全的来源。
    """
    ps, pd = parse(p)
    qs, qd = parse(q)
    if qd and not qs:
        return True                      # q == "**"，覆盖一切
    # 含空段的模式：其语言为**空集**（`matches` 对它恒为假），空集包含于任何语言。
    # 因此 subsumes(退化, q) 恒真、subsumes(p, 退化) 仅当 p 也退化时为真。
    # 早期版本对两侧一律返回 False，破坏了**反身性**——`subsumes(p,p)` 对退化 p 为假，
    # 端到端表现为"父/子同为 `x@a//b` 时拒绝派生、且违规集合为空"，由全新读者的差分测试发现。
    p_deg, q_deg = _has_empty_segment(ps), _has_empty_segment(qs)
    if p_deg:
        return True
    if q_deg:
        return False
    if not pd and not qd:
        if len(ps) != len(qs):
            return False
        return all(_seg_sub(ps[i], qs[i]) for i in range(len(ps)))
    if not pd and qd:
        if len(ps) < len(qs):
            return False
        return all(_seg_sub(ps[i], qs[i]) for i in range(len(qs)))
    # p 以 ** 结尾（语言无限）
    if not qd:
        return False
    # p 覆盖长度 ≥ len(ps) 的全部路径；若 len(ps) < len(qs)，则 p 含 q 不接受的短路径
    if len(ps) < len(qs):
        return False
    return all(_seg_sub(ps[i], qs[i]) for i in range(len(qs)))


def split_grant(grant: str) -> tuple[str, str]:
    """把 `cap@pattern` 拆成 (capability, pattern)。无 @ 时 pattern = "**"。"""
    if "@" in grant:
        cap, pat = grant.split("@", 1)
        return cap, pat
    return grant, ""


def grant_allows(grant: str, capability: str, resource: str) -> bool:
    cap, pat = split_grant(grant)
    return cap == capability and matches(pat, resource)


def scope_allows(scope, capability: str, resource: str) -> bool:
    """授权判定：请求的 (能力, 资源) 是否被 scope 中某条授权覆盖。"""
    return any(grant_allows(g, capability, resource) for g in scope)


def scope_subset(child, parent) -> bool:
    """子范围 ⊆ 父范围：child 的每条授权都要被 parent 中同能力的某条授权包含。

    这是衰减的代数学核心——不是集合包含，而是模式语言的包含。
    """
    parent_by_cap: dict[str, list[str]] = {}
    for g in parent:
        cap, pat = split_grant(g)
        parent_by_cap.setdefault(cap, []).append(pat)
    for g in child:
        cap, pat = split_grant(g)
        if not any(subsumes(pat, q) for q in parent_by_cap.get(cap, ())):
            return False
    return True


def least_general_pattern(resources) -> str:
    """一组资源串的**最具体公共前缀泛化**。

    这是"最小必要范围"的可计算来源：从任务实际轨迹里观察到的资源集合反推模式。
    注意：不是理论最优最小集（最小集问题是 NP-hard），是最具体公共前缀。
    """
    rs = sorted({(r or "").strip("/") for r in resources if (r or "").strip()})
    if not rs:
        return ""
    parts = [r.split("/") for r in rs]
    if len({len(p) for p in parts}) != 1:
        # 段数不一致：取公共段前缀 + **
        n = min(len(p) for p in parts)
        out = []
        for i in range(n):
            segs = {p[i] for p in parts}
            out.append(segs.pop() if len(segs) == 1 else "*")
        return "/".join(out + [ANY]) if out else ANY
    out = []
    for i in range(len(parts[0])):
        segs = {p[i] for p in parts}
        out.append(segs.pop() if len(segs) == 1 else "*")
    return "/".join(out)


def witness(pattern: str, tag: str = "probe") -> str:
    """给出一个落在 pattern 语言内的具体资源串（用于"这条 surplus 能被用来做什么"）。"""
    segs, dstar = parse(pattern)
    out = [tag if s == "*" else s for s in segs]
    if dstar:
        out.append(tag)
    return "/".join(out) if out else tag


# 注：此处原有一个 `coarsen_levels()`，它对已经是 "**" 的模式做"末段换 *"，
# 反而把范围**收窄**——与 spec §2.15「粗化必须是单调的」冲突。
# 该函数无调用点，已删除；正确的实现见 experiments/scope_experiments.py 与
# experiments/substrate.py 中的 `_widen()`。
