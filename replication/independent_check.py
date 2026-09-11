"""独立复算：不复用 patterns.scope_allows 的判定路径（spec §2.16 第 4 条）。

把 scope 条目 cap@pat 编译成正则，用 Python re 判定；模式包含则用穷举抽样近似
（只用于交叉核对，不作为判定依据）。
"""
from __future__ import annotations

import re


def compile_pattern(pat: str) -> re.Pattern:
    if pat is None or pat == "":
        pat = "**"
    segs = pat.split("/")
    tail = segs[-1] == "**"
    prefix = segs[:-1] if tail else segs
    rx = []
    for s in prefix:
        rx.append("[^/]+" if s == "*" else re.escape(s))
    if tail:
        if prefix:
            return re.compile("^" + "/".join(rx) + "(/[^/]+)*$")
        return re.compile("^.*$", re.S)
    return re.compile("^" + "/".join(rx) + "$")


def split_entry(entry: str) -> tuple[str, str]:
    if "@" in entry:
        cap, pat = entry.split("@", 1)
        return cap, pat
    return entry, "**"


def allowed_entries_for(token, capability: str, resource: str) -> list[str]:
    hits = []
    for e in token.scope:
        cap, pat = split_entry(e)
        if cap != capability:
            continue
        if compile_pattern(pat).match(resource):
            hits.append(e)
    return hits


def token_scope_of(token) -> set[str]:
    return set(token.scope)
