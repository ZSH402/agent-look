"""§2.8 模式语言 + §3.2 判定顺序的**规格直译判据**。

本文件不导入 `replication/patterns.py`（我自己的实现），也不导入 `src/patterns.py`
（参考实现）。它的唯一依据是 `spec/spec.md` 的 §2.8 与 §3.2 条文，用于给两侧实现的
分歧做第三方裁决。

规格 §2.8 原文：
    PATTERN := segment ( "/" segment )* [ "**" ]
    segment := 字面量 | "*"
    "**" 只能作为最后一段，表示"任意剩余段（含零段）"；空模式 "" 等价于 "**"
    scope 条目 := "capability" | "capability@PATTERN"
    裸标识符等价于"任意资源"

规格 §3.2 原文给出的判定顺序：1 归因 → 1b 重放 → 1c 时窗 → 2 令牌查找 →
3 签发者绑定 → 4 回滚防护 → 5 离线验证 → 6 任务绑定 → 7 范围检查 → 8 副作用。
"""
from __future__ import annotations

ANY = "**"

# §3.2「时效窗口是双向的（差分测试后钉死）」：默认 50 tick。
MAX_REQUEST_AGE = 50

# §2.3「检查顺序（差分测试后钉死）」：规则 4–6 的触发优先级为 撤销 → 过期 → 密钥作废。
VERIFY_ORDER = ("TOKEN_REVOKED", "TOKEN_EXPIRED", "TOKEN_INVALID")


# ------------------------------------------------------------------ §2.8 模式
def is_unconditional(pattern: str) -> bool:
    """§2.8：无条件模式 —— 空串等价 '**'，匹配一切（含退化资源串）。"""
    return pattern == "" or pattern == ANY


def is_degenerate(resource: str) -> bool:
    """§2.8「段不得为空」：资源串按 '/' 精确切分，含空段者即退化。"" -> ['']。"""
    return "" in resource.split("/")


def _segs(pattern: str) -> tuple[tuple[str, ...], bool]:
    """规格直译：返回 (前缀段, 是否带 '**' 尾巴)。空模式等价于 '**'。"""
    if pattern == "":
        return (), True
    parts = tuple(pattern.split("/"))
    # 规格禁止 '*'+'**' 混用之外的形态；这里把 '**' 只当最后一段处理。
    if parts and parts[-1] == ANY:
        return parts[:-1], True
    return parts, False


def seg_lang(seg: str) -> frozenset:
    """单段的语言。'*' = 任意一段；字面量 = 该段自身。"""
    return frozenset(["*"]) if seg == "*" else frozenset([seg])


def matches(pattern: str, resource: str) -> bool:
    """资源串落在模式语言内？（规格直译，按段比较）"""
    if is_unconditional(pattern):
        return True
    if is_degenerate(resource):
        return False                      # §2.8：不匹配任何有约束的模式
    pre, star = _segs(pattern)
    rsegs = tuple(resource.split("/"))
    if star:
        if len(rsegs) < len(pre):
            return False
        return all(_seg_match(p, r) for p, r in zip(pre, rsegs))
    if len(rsegs) != len(pre):
        return False
    return all(_seg_match(p, r) for p, r in zip(pre, rsegs))


def _seg_match(p: str, r: str) -> bool:
    return p == "*" or p == r


def subsumes(child: str, parent: str) -> bool:
    """语言(child) ⊆ 语言(parent)？规格直译（按语言形状分类讨论）。

    §2.8 要求 `matches`/`subsumes` 共用空段规则：无条件模式的语言含退化资源串，
    有约束模式的语言不含，故「无条件 child ⊆ 有约束 parent」恒为假。
    """
    if is_unconditional(parent):
        return True
    if is_unconditional(child):
        return False
    cpre, cstar = _segs(child)
    ppre, pstar = _segs(parent)
    if not pstar:
        # 父语言长度恰为 |ppre|；子语言若含 '**' 则含任意长串 ⇒ 不可能被包含。
        if cstar or len(cpre) != len(ppre):
            return False
        return all(seg_sub(c, p) for c, p in zip(cpre, ppre))
    # 父语言 = 长度 >= |ppre| 且前 |ppre| 段匹配。
    if len(cpre) < len(ppre):
        return False
    return all(seg_sub(c, p) for c, p in zip(cpre, ppre))


def seg_sub(c: str, p: str) -> bool:
    """单段包含：{c 的语言} ⊆ {p 的语言}。"""
    if p == "*":
        return True
    return c == p


# --------------------------------------------------------------- §2.8 scope
def parse_entry(entry: str) -> tuple[str, str]:
    if "@" in entry:
        cap, pat = entry.split("@", 1)
        return cap, pat
    return entry, ANY


def entry_subsumes(child: str, parent: str) -> bool:
    ccap, cpat = parse_entry(child)
    pcap, ppat = parse_entry(parent)
    return ccap == pcap and subsumes(cpat, ppat)


def scope_subset(child, parent) -> bool:
    child, parent = list(child), list(parent)
    return all(any(entry_subsumes(c, p) for p in parent) for c in child)


def scope_allows(scope, cap: str, resource: str) -> bool:
    for e in scope:
        ecap, pat = parse_entry(e)
        if ecap == cap and matches(pat, resource):
            return True
    return False


# ------------------------------------------------------ §3.2 判定顺序判据
# reason_code 的顺序表：越小越先判。
ORDER = [
    ("REQUEST_UNSIGNED", 1),
    ("REPLAY", 1.5),
    ("TOKEN_INVALID_STORE", 2),
    ("TOKEN_INVALID_ISSUER", 3),
    ("STALE_CREDENTIAL", 4),
    # §2.3「检查顺序（差分测试后钉死）」：撤销 → 过期 → 密钥作废
    ("TOKEN_REVOKED", 5.0),
    ("TOKEN_EXPIRED", 5.1),
    ("TOKEN_INVALID_VERIFY", 5.2),
    ("TASK_MISMATCH", 6),
    ("SCOPE_VIOLATION", 7),
]


def window_ok(now, ts) -> bool:
    """§3.2 步骤 1c：0 ≤ now - ts ≤ max_request_age（双向）。"""
    age = now - ts
    return 0 <= age <= MAX_REQUEST_AGE


def order_of(code: str) -> float:
    for c, o in ORDER:
        if c == code:
            return o
    return 99.0
