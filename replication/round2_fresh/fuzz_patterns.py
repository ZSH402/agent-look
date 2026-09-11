"""规则 1 随机差分 + 健全性抽查。

A) 在语法内的（well-formed）模式/资源上随机抽样，比较 my 与 ref 的 matches/subsumes。
B) 对 ref 判为 subsumes(p,q)=True 的每一对，从 p 的语言里采样资源，检查是否也匹配 q
   （规格 L135 的健全性要求）。
C) 空段相关输入的定向探针。
"""
import random, sys
sys.path.insert(0, "/root/ai监督")
sys.path.insert(0, "/root/ai监督/replication/round2_fresh")
from src.patterns import matches as r_matches, subsumes as r_subsumes
import mine_patterns as M

random.seed(20240607)
LITS = ["a", "b", "ab", "x", "orders", "**x"]


def rand_pattern():
    n = random.randint(0, 3)
    segs = [random.choice(LITS + ["*"]) for _ in range(n)]
    if random.random() < 0.5:
        segs.append("**")
    return "/".join(segs)


def rand_resource():
    n = random.randint(0, 4)
    return "/".join(random.choice(LITS) for _ in range(n))


def sample_from(p, k=40):
    """从模式 p 的语言中采样资源（含空段资源不采样：规格已单独规定）。"""
    fixed, star = M._split_pattern(p)
    out = []
    for _ in range(k):
        tail = []
        if star:
            tail = [random.choice(LITS) for _ in range(random.randint(0, 2))]
        out.append("/".join([s if s != "*" else random.choice(LITS) for s in fixed] + tail))
    return out


diff_m = diff_s = 0
sound_viol = 0
sub_true = 0
for _ in range(3000):
    p, q = rand_pattern(), rand_pattern()
    r = rand_resource()
    if M.matches(p, r) != r_matches(p, r):
        diff_m += 1
        if diff_m <= 5:
            print("MATCH DIFF", (p, r), M.matches(p, r), r_matches(p, r))
    a, b = M.subsumes(p, q), r_subsumes(p, q)
    if a != b:
        diff_s += 1
        if diff_s <= 5:
            print("SUB DIFF", (p, q), "mine", a, "ref", b)
    if b:
        sub_true += 1
        for res in sample_from(p, 8):
            if not r_matches(q, res):
                sound_viol += 1
                print("REF UNSOUND", (p, q), res)
                break

print(f"random pairs=3000  matches_diff={diff_m}  subsumes_diff={diff_s}")
print(f"ref subsumes=True pairs={sub_true}  soundness_violations={sound_viol}")

print("\n== 空段定向探针（唯一发现 DIFF 的方向）==")
for p, q in [("a//b", "a//b"), ("a//b", "a/*"), ("a/*", "a//b"), ("a//b", "a//c"),
             ("**", "a//b"), ("a//b", "**"), ("a//**", "a/**"), ("a/**", "a//**"),
             ("a/b//c", "a/b//c"), ("a//b", "**/**"), ("//", "**")]:
    print(f"subsumes({p!r},{q!r}) mine={M.subsumes(p,q)} ref={r_subsumes(p,q)}"
          + ("   <<< DIFF" if M.subsumes(p, q) != r_subsumes(p, q) else ""))
