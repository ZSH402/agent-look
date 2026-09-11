"""规则 1 差分测试：§2.8 分段规则。my implementation vs src.patterns（黑盒）。"""
import sys
sys.path.insert(0, "/root/ai监督")
sys.path.insert(0, "/root/ai监督/replication/round2_fresh")
from src.patterns import matches as r_matches, subsumes as r_subsumes
import mine_patterns as M

MATCH_CASES = [
    # (pattern, resource, 我的期望)
    ("a/b", "a/b", True),
    ("a/*", "a/b", True),
    ("a/*", "a/b/c", False),
    ("a/**", "a", True),            # L130 含零段
    ("a/**", "a/b", True),
    ("a/**", "a/b/c", True),
    ("a/*/**", "a", False),         # 至少两段 (L145-146)
    ("a/*/**", "a/b", True),
    ("**", "", True),               # L151
    ("", "", True),                 # L130
    ("", "a/b", True),
    ("**", "a//b", True),           # L151 无条件模式匹配一切
    ("a/**", "a//b", False),        # L150 含空段者不匹配任何有约束的模式
    ("a/**", "a/", False),          # 尾随 /
    ("a/**", "/a", False),          # 前导 /
    ("a/*", "a/", False),
    ("**", "a/", True),
    ("a/**", "ab", False),
    ("a/b/**", "a/b", True),
    ("a/b/**", "a", False),
]

SUB_CASES = [
    # (p, q, 我的期望: p ⊆ q)
    ("a/**", "a/*/**", False),      # L145 已修正的缺陷
    ("a/*/**", "a/**", True),
    ("a/**", "a/**", True),
    ("a/**", "**", True),
    ("**", "a/**", False),
    ("a", "**", True),
    ("a/*", "a/**", True),
    ("a/**", "a/*", False),
    ("a/b", "a/*", True),
    ("a/*", "a/b", False),
    ("a/*/**", "a/*/**", True),
    ("a/b/**", "a/*/**", True),
    ("a/*/**", "a/b/**", False),
    ("a/b", "a/b/**", True),
    ("a/b/**", "a/b", False),
    ("**", "", True),               # 两者互为等价（L130）
    ("", "**", True),
]

print("== matches ==")
bad = 0
for p, r, expect in MATCH_CASES:
    mine = M.matches(p, r)
    ref = r_matches(p, r)
    ok_m = "OK" if mine == expect else "MINE!=SPEC"
    ok_r = "OK" if ref == expect else "REF!=SPEC"
    flag = "" if mine == ref else "   <<< DIFF"
    if ref != expect or mine != expect:
        bad += 1
    print(f"matches({p!r},{r!r}) mine={mine} ref={ref} spec_expected={expect} [{ok_m}/{ok_r}]{flag}")

print("\n== subsumes ==")
for p, q, expect in SUB_CASES:
    mine = M.subsumes(p, q)
    ref = r_subsumes(p, q)
    ok_m = "OK" if mine == expect else "MINE!=SPEC"
    ok_r = "OK" if ref == expect else "REF!=SPEC"
    flag = "" if mine == ref else "   <<< DIFF"
    if ref != expect or mine != expect:
        bad += 1
    print(f"subsumes({p!r},{q!r}) mine={mine} ref={ref} spec_expected={expect} [{ok_m}/{ok_r}]{flag}")

print("\nmismatch/flag count:", bad)
