"""§2.8 资源模式与范围包含。

PATTERN := segment ( "/" segment )* [ "**" ]
segment := 字面量 | "*"
空模式 "" 等价于 "**"。

§2.8「段不得为空（差分测试后钉死）」：资源串按 '/' **精确切分，不做任何归一化**。
含空段者（前导 '/'、尾随 '/'、连续 '//'）**不匹配任何有约束的模式**；
只有无条件模式（空串或 '**'）匹配一切，含退化资源串。
`matches` 与 `subsumes` 共用这一条规则。
"""
from __future__ import annotations

WILDCARD_TAIL = "**"


def is_unconditional(pattern: str) -> bool:
    """§2.8：无条件模式 —— 空串等价 '**'，匹配一切（含退化资源串）。"""
    return pattern is None or pattern == "" or pattern == WILDCARD_TAIL


def is_degenerate(resource: str) -> bool:
    """资源串是否含空段。"" -> ['']，同样是含空段。"""
    return "" in resource.split("/")


def parse(pattern: str) -> list[str]:
    """把模式串切成段列表。空模式等价于 '**'。"""
    if pattern is None or pattern == "":
        return [WILDCARD_TAIL]
    return pattern.split("/")


def matches(pattern: str, resource: str) -> bool:
    """资源串 resource 是否落在模式 pattern 的语言内。"""
    if is_unconditional(pattern):
        return True
    if is_degenerate(resource):
        # §2.8：含空段的资源串不匹配任何有约束的模式。
        return False
    segs = parse(pattern)
    parts = resource.split("/")
    if segs[-1] == WILDCARD_TAIL:
        prefix = segs[:-1]
        if len(parts) < len(prefix):
            return False
        return all(s == "*" or s == p for s, p in zip(prefix, parts[: len(prefix)]))
    if len(parts) != len(segs):
        return False
    return all(s == "*" or s == p for s, p in zip(segs, parts))


def _seg_subsumes(child: str, parent: str) -> bool:
    """单段包含：child 的语言 ⊆ parent 的语言。"""
    if parent == "*":
        return True
    return child == parent


def subsumes(child: str, parent: str) -> bool:
    """subsumes(p, q): 语言(p) ⊆ 语言(q)。健全但不完备：返回 False 只导致误拒。

    与 `matches` 共用 §2.8 的空段规则：无条件模式的语言包含退化资源串，
    有约束模式的语言不含，故「无条件 child ⊆ 有约束 parent」恒为假。
    """
    if is_unconditional(parent):
        return True
    if is_unconditional(child):
        return False
    cs = parse(child)
    ps = parse(parent)
    child_tail = cs[-1] == WILDCARD_TAIL
    parent_tail = ps[-1] == WILDCARD_TAIL
    cpre = cs[:-1] if child_tail else cs
    ppre = ps[:-1] if parent_tail else ps

    if parent_tail:
        # parent 允许 >= |ppre| 段的任意后缀。child 匹配的串必须至少 |ppre| 段，
        # 且前 |ppre| 段落在 ppre 内。
        if len(cpre) < len(ppre):
            return False
        return all(_seg_subsumes(c, p) for c, p in zip(cpre, ppre))
    # parent 定长：child 也必须定长且同长。
    if child_tail or len(cpre) != len(ppre):
        return False
    return all(_seg_subsumes(c, p) for c, p in zip(cpre, ppre))


def parse_entry(entry: str) -> tuple[str, str]:
    """'capability@PATTERN' -> (cap, pat)；裸标识符等价于任意资源 '**'。"""
    if "@" in entry:
        cap, pat = entry.split("@", 1)
        return cap, pat
    return entry, WILDCARD_TAIL


def entry_subsumes(child_entry: str, parent_entry: str) -> bool:
    ccap, cpat = parse_entry(child_entry)
    pcap, ppat = parse_entry(parent_entry)
    return ccap == pcap and subsumes(cpat, ppat)


def scope_subset(child: set[str], parent: set[str]) -> bool:
    """child 的每条授权都被 parent 中同能力的某条授权包含。"""
    for ce in child:
        if not any(entry_subsumes(ce, pe) for pe in parent):
            return False
    return True


def scope_allows(scope: set[str], capability: str, resource: str) -> bool:
    for e in scope:
        cap, pat = parse_entry(e)
        if cap == capability and matches(pat, resource):
            return True
    return False
