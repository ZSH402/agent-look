"""规则 1 的分歧探针：这些是规格文本**没有决定**的输入，我做了任意选择，
看参考实现是否做了同一个选择。"""
import sys
sys.path.insert(0, "/root/ai监督")
sys.path.insert(0, "/root/ai监督/replication/round2_fresh")
from src.patterns import matches as r_matches, subsumes as r_subsumes
import mine_patterns as M

PROBES = [
    # (kind, args, 我的选择说明)
    ("m", ("**/a", "a"), "非末位 ** ：我当字面量段"),
    ("m", ("a/**/b", "a/x/b"), "非末位 ** ：我当字面量段"),
    ("m", ("a/**/b", "a/**/b"), "非末位 ** 全字面"),
    ("m", ("*", "**"), "资源串本身是 '**' 时被 * 匹配？"),
    ("m", ("*", ""), "空资源串（一个空段）是否被 * 匹配"),
    ("m", ("a/*", "a//b"), "空段 + 有约束模式"),
    ("m", ("a//b", "a//b"), "模式自身含空段"),
    ("m", ("/a", "/a"), "模式前导斜杠"),
    ("m", ("a/", "a/"), "模式尾随斜杠"),
    ("m", ("a/*/", "a/b/"), "模式尾随斜杠 + *"),
    ("m", ("**/**", "a/b"), "重复 **"),
    ("s", ("a/b", "a"), "q 固定段更短"),
    ("s", ("a", "a/b"), "p 固定段更短"),
    ("s", ("a/*/**", "a/*"), "q 无尾 ** 但 p 有"),
    ("s", ("a//b", "a//b"), "含空段的模式之间"),
    ("s", ("a//b", "**"), "退化模式 vs 无条件"),
    ("s", ("**", "a//b"), "无条件 vs 退化模式"),
    ("s", ("a/**/**", "a/**"), "重复 ** 的包含"),
    ("s", ("a/**/b", "a/**/b"), "非末位 ** 的自包含"),
    ("m", ("a/b/c/**", "a/b/c"), "** 吃零段（三段前缀）"),
    ("m", ("a/b/c/**", "a/b/c/d/e"), "** 多吃"),
]

print(f"{'kind':4} {'args':28} {'mine':6} {'ref':6} diff  note")
for kind, args, note in PROBES:
    if kind == "m":
        mine, ref = M.matches(*args), r_matches(*args)
    else:
        mine, ref = M.subsumes(*args), r_subsumes(*args)
    d = "DIFF <<<" if mine != ref else ""
    print(f"{kind:4} {str(args):28} {str(mine):6} {str(ref):6} {d:8} {note}")
