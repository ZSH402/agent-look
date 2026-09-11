"""独立实现：仅依据 spec/spec.md §2.8 的文本。

规格文本（逐字依据，行号为 spec/spec.md）：
  L128  PATTERN := segment ( "/" segment )* [ "**" ]
  L129  segment := 字面量 | "*"
  L130  "**" 只能作为最后一段，表示"任意剩余段（含零段）"；空模式 "" 等价于 "**"
  L149  资源串按 "/" 精确切分，不做任何归一化
  L150  含空段者（前导 /、尾随 /、连续 //）不匹配任何有约束的模式
  L151  只有无条件模式（空串或 **）匹配一切，含退化资源串
  L135  subsumes(p,q) 为真时，任何匹配 p 的资源必须匹配 q（健全性；反向不要求）
"""
from itertools import product

UNCONDITIONAL = ("", "**")


def _split_resource(r):
    """L149：精确切分，不归一化。"" 视为一个空段（Python 的 split 语义）。"""
    return r.split("/")


def _split_pattern(p):
    """返回 (fixed_segments, star_tail)。

    仅按 L128 的字面语法解析：末段为 "**" 时它是 star tail，其余段为 fixed。
    "**" 出现在非末位（语法不允许）时，我选择把它当作**字面量段**处理。
    """
    if p == "":
        return [], True          # L130：空模式等价 "**"
    segs = p.split("/")
    if segs and segs[-1] == "**":
        return segs[:-1], True
    return segs, False


def _is_unconditional(p):
    return p in UNCONDITIONAL


def _has_empty_segment(r):
    return any(s == "" for s in _split_resource(r))


def _match_wellformed(rs, fixed, star):
    """在"资源串无空段"这一前提下做逐段匹配。"""
    if len(rs) < len(fixed):
        return False
    for a, b in zip(rs, fixed):
        if b != "*" and a != b:
            return False
    rest = len(rs) - len(fixed)
    if star:
        return True                       # L130：含零段
    return rest == 0


def matches(p, r):
    """L134：资源串 r 是否落在模式 p 的语言内。"""
    # L150/L151：含空段的资源串只被无条件模式匹配。
    if _has_empty_segment(r):
        return _is_unconditional(p)
    fixed, star = _split_pattern(p)
    return _match_wellformed(_split_resource(r), fixed, star)


def _covers(ps, qs):
    """p 的固定段序列 ⊆ q 的固定段序列（逐段）。"""
    if len(ps) != len(qs):
        return False
    for a, b in zip(ps, qs):
        if b != "*" and a != b:
            return False
    return True


def subsumes(p, q):
    """L135：p 的语言 ⊆ q 的语言。我选择实现**精确**包含判定（规格只要求健全，
    未要求完备；精确是健全的一个特例，且可判定）。"""
    if _is_unconditional(q):
        return True                       # 无条件模式包含一切
    if _is_unconditional(p):
        return False
    pf, ps = _split_pattern(p)
    qf, qs = _split_pattern(q)
    if qs:                                # q 有 ** 尾巴
        if len(pf) < len(qf):
            return False
        if not _covers(pf[:len(qf)], qf):
            return False
        return True                       # p 的剩余部分（固定或 **）都被 q 的 ** 吸收
    # q 无 ** 尾巴：p 的语言必须恰好落在 q 的固定段数上
    if ps:
        return False
    return len(pf) == len(qf) and _covers(pf, qf)


def scope_allows(scope, cap, res):
    """L139。"""
    for entry in scope:
        c, _, pat = entry.partition("@")
        if not _:
            pat = "**"                    # L11-13：裸标识符等价"任意资源"
        if c == cap and matches(pat, res):
            return True
    return False


def scope_subset(child, parent):
    """L137：child 的每条授权都被 parent 中同能力的某条授权包含。"""
    def split(e):
        c, sep, pat = e.partition("@")
        return c, (pat if sep else "**")
    for e in child:
        c, cp = split(e)
        if not any(pc == c and subsumes(cp, pp) for pc, pp in map(split, parent)):
            return False
    return True
