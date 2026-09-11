"""随机拓扑的性质测试：给 P1/P5 的定理声明上保险。

不变式 I1–I5 此前只在**一条固定链 A→B→C→D→E** 上验证过。本模块在随机委托图上重复验证，
并显式覆盖四种结构（链、扇出、菱形汇聚、环），以及"越权派生必须被拒"的结构性攻击。

运行：python3 -m experiments.topology_tests   （退出码 0 = 全部图通过）
"""
from __future__ import annotations

import random
import re
import sys
from collections import Counter

from src.harm import DEFAULT_MODEL  # noqa: F401  (保持与其余实验同样的导入面)
from src.model import CAP_UNIVERSE, Deny
from src.patterns import ANY, scope_allows, scope_subset
from src.runtime import System
from src.tokens import token_issuer

WIDE = [f"{c}@{ANY}" for c in CAP_UNIVERSE]


def independent_allows(scope, capability: str, resource: str) -> bool:
    """**独立重算**"该范围是否允许 (能力, 资源)"——不调用判定路径的谓词。

    存在理由：原先的断言写作 `scope_allows(...)`，而 `scope_allows` 正是 `_enforce`
    用的同一个函数（spec §2.16 第 4 条所禁的"断言调用被断言的同一函数"）。
    这里改用完全不同的代码路径：把模式**翻译成正则**再全匹配。

    语义须与 spec §2.8 一致：段按 `/` 精确切分、不做归一化；`*` 只匹配非空单段；
    含空段的模式语言为空集；空模式与 `**` 表示任意资源。
    """
    for grant in scope:
        cap, _, pat = grant.partition("@")
        if cap != capability:
            continue
        p = pat if "@" in grant else "**"
        if p.strip() in ("", "**"):
            return True                      # 无条件模式匹配一切（含退化资源）
        segs = p.split("/")
        rs = resource.split("/")
        if any(x == "" for x in segs) or any(x == "" for x in rs):
            continue                         # 含空段：语言为空集
        dstar = segs and segs[-1] == "**"
        core = segs[:-1] if dstar else segs
        rx = "/".join("[^/]+" if x == "*" else re.escape(x) for x in core)
        rx = rx + ("(/.*)?" if dstar else "")
        if re.fullmatch(rx, resource):
            return True
    return False


# ------------------------------------------------------------------ 构造
def make_system(agents: dict[str, list[str]]) -> System:
    s = System(mode="P", ttl=1000, pull_interval=10)
    for sid, scope in agents.items():
        s.add_agent(sid, "Worker", scope)
    return s


def held_tokens(s: System, sid: str):
    """该主体**持有**（可作为父令牌使用）的令牌。"""
    return [t for t in s.peps[sid].tokens.values() if t.holder_id == sid]


def delegate_edge(s: System, frm: str, to: str, rnd: random.Random,
                  task: str, narrow: bool = False):
    held = held_tokens(s, frm)
    if not held:
        return None
    parent = rnd.choice(held)
    grants = list(parent.scope)
    if not grants:
        return None
    k = rnd.randint(1, len(grants))
    picked = sorted(rnd.sample(grants, k))
    if narrow:
        picked = sorted({f"{g.split('@')[0]}@{'/'.join(list(g.split('@')[1].split('/'))[:-1] + ['*']) if '@' in g and g.split('@')[1] else ANY}"
                         for g in picked})
        picked = [g for g in picked if scope_subset([g], parent.scope)] or sorted(grants[:1])
    try:
        return s.delegate(frm, to, picked, task, parent_token_id=parent.token_id)
    except Deny:
        return None


def shape_chain(n: int):
    return {f"n{i}": (list(CAP_UNIVERSE) if i == 0 else CAP_UNIVERSE[:4])
            for i in range(n)}


def shape_fanout(n: int):
    return {**{"root": list(CAP_UNIVERSE)},
            **{f"l{i}": CAP_UNIVERSE[:4] for i in range(n)}}


def shape_diamond():
    return {"root": list(CAP_UNIVERSE), "b": CAP_UNIVERSE[:4], "c": CAP_UNIVERSE[:4],
            "d": CAP_UNIVERSE[:4]}


def shape_ring(n: int):
    return {f"r{i}": list(CAP_UNIVERSE) for i in range(n)}


def build_shape(s: System, kind: str, n: int, rnd: random.Random) -> list:
    toks = []
    if kind == "chain":
        for i in range(n - 1):
            t = delegate_edge(s, f"n{i}", f"n{i+1}", rnd, f"t{i}")
            if t:
                toks.append(t)
    elif kind == "fanout":
        for i in range(n):
            t = delegate_edge(s, "root", f"l{i}", rnd, f"t{i}")
            if t:
                toks.append(t)
    elif kind == "diamond":
        ab = delegate_edge(s, "root", "b", rnd, "tab")
        ac = delegate_edge(s, "root", "c", rnd, "tac")
        toks += [t for t in (ab, ac) if t]
        for frm in ("b", "c"):
            t = delegate_edge(s, frm, "d", rnd, f"t{frm}d")
            if t:
                toks.append(t)
    elif kind == "ring":
        for i in range(n):
            t = delegate_edge(s, f"r{i}", f"r{(i+1) % n}", rnd, f"t{i}")
            if t:
                toks.append(t)
    return toks


# ------------------------------------------------------------------ 检查
def _independent_subset(child_scope, parent_scope) -> bool:
    """**独立重算**范围包含：child 允许的每个候选资源，parent 也必须允许。

    用"在候选资源上枚举"代替 `subsumes` 的语法判定——不同的代码路径。
    **能力边界**：候选集是有限的，因此这是**抽样**包含检查：
    它抓不到落在候选集之外的违例。作为对 `subsumes` 的交叉验证使用，不单独充当证明。
    """
    cands = ["a", "b", "c", "a/b", "a/b/c", "a/", "/a", "orders/2024-001",
             "a//b", "probe", "x", "x/y"]
    for g in child_scope:
        cap, _, pat = g.partition("@")
        grant = f"{cap}@{pat if '@' in g else '**'}"
        for r in cands:
            if independent_allows([grant], cap, r) \
                    and not independent_allows(parent_scope, cap, r):
                return False
    return True


def exercise(s: System, toks: list, rnd: random.Random, n_req: int) -> dict:
    """随机发起请求（一部分在范围内、一部分越界），然后逐条断言。"""
    all_toks = {}
    for pep in s.peps.values():
        for tk in pep.tokens.values():
            all_toks[tk.token_id] = tk
    usable = [(token_issuer(t), t.holder_id, t) for t in toks]
    for _ in range(n_req):
        if not usable:
            break
        frm, to, t = rnd.choice(usable)
        in_scope = rnd.random() < 0.5
        if in_scope and t.scope:
            g = rnd.choice(list(t.scope))
            cap = g.split("@")[0]
            res = rnd.choice(["orders/2024-001", "db/credentials", "x/y"])
        else:
            cap = rnd.choice(CAP_UNIVERSE)
            res = rnd.choice(["orders/2024-001", "db/credentials", "x/y"])
        s.request(frm, to, t.token_id, cap, res, t.task_id, text="probe")

    v = []
    # P1 / I2：ALLOW 的能力必须在所用令牌范围内
    for r in s.evidence.receipts:
        if r.decision != "ALLOW":
            continue
        tk = all_toks.get(r.token_id)
        # **独立重算**，不用判定路径的谓词（原先用 scope_allows，属自证）
        if tk is None or not independent_allows(tk.scope, r.capability, r.resource):
            v.append(f"P1: ALLOW 越权 {r.capability}@{r.resource}")
    # I3：副作用数 == ALLOW 收据数
    n_allow = sum(1 for r in s.evidence.receipts if r.decision == "ALLOW")
    if len(s.world.effects) != n_allow:
        v.append(f"I3: effects={len(s.world.effects)} allow={n_allow}")
    # I5：收据数 == 请求数
    if len(s.evidence.receipts) != len(s.requests):
        v.append(f"I5: receipts={len(s.evidence.receipts)} requests={len(s.requests)}")
    # I1：所有令牌范围 ⊆ 其根授权，且逐级非增
    for tk in all_toks.values():
        grant = s.authority.grants.get(tk.root_subject_id)
        if grant is None or not _independent_subset(tk.scope, grant.scope):
            v.append(f"I1: 根越界 {tk.token_id[:8]}")
        prev = grant.scope if grant else ()
        for link in tk.chain:
            if not _independent_subset(link.scope, prev):
                v.append(f"I1: 链非单调 {tk.token_id[:8]}")
                break
            prev = link.scope

    # 结构性：越权派生必须被拒
    attempts = 0
    for _ in range(4):
        frm = rnd.choice(list(s.peps))
        holds = set(s.authority.grants[frm].scope)
        for tk in held_tokens(s, frm):
            holds |= {g.split("@")[0] for g in tk.scope}
        outside = [c for c in CAP_UNIVERSE if c not in holds]
        if not outside:
            continue
        cap = rnd.choice(outside)
        attempts += 1
        try:
            s.delegate(frm, "__sink__", [cap], "evil")
            v.append(f"amplify: {frm} 授出了不具备的 {cap}")
        except Deny:
            pass
        except KeyError:
            pass          # 目标不存在，等价于被拒
    # 非平凡性度量：一个全部拒绝的实现也能"通过"上面的断言，必须显式排除
    n_deny = sum(1 for r in s.evidence.receipts if r.decision == "DENY")
    def is_cyclic(tk) -> bool:
        seq = [tk.root_subject_id] + [l.holder_id for l in tk.chain]
        return len(set(seq)) < len(seq)

    cyc = sum(1 for tk in all_toks.values() if is_cyclic(tk))
    return {"violations": v, "tokens": len(all_toks), "receipts": len(s.evidence.receipts),
            "effects": len(s.world.effects), "allows": n_allow, "denies": n_deny,
            "amplify_attempts": attempts, "cyclic_tokens": cyc,
            "reasons": dict(Counter(r.reason_code for r in s.evidence.receipts
                                    if r.decision == "DENY"))}


# ------------------------------------------------------------------ 主流程
def oracle_agreement(trials: int = 4000, seed: int = 99) -> dict:
    """交叉验证：独立口径（正则翻译）与实现口径（`scope_allows`）必须一致。

    不一致说明二者之一有错，任一方都不能单独作为判据。**这是 E17 从自证转为互证的依据。**
    """
    rnd = random.Random(seed)
    caps = ["order.read", "db.read", "x.y"]
    pats = ["**", "", "*", "a", "a/*", "orders/**", "a/b", "a//b", "a/", "/a"]
    resources = ["a", "a/b", "a/b/c", "orders/2024-001", "a//b", "a/", "/a", "x", ""]
    disagree = []
    for _ in range(trials):
        scope = [f"{rnd.choice(caps)}@{rnd.choice(pats)}" for _ in range(rnd.randint(1, 3))]
        cap, res = rnd.choice(caps), rnd.choice(resources)
        if scope_allows(scope, cap, res) != independent_allows(scope, cap, res):
            disagree.append((scope, cap, res))
    return {"trials": trials, "disagreements": len(disagree),
            "sample": disagree[:3]}


def topology_suite(n_random: int = 120, seed: int = 4242) -> dict:
    rnd = random.Random(seed)
    cases, violations = [], []
    total_tok = total_rec = total_eff = total_allows = total_denies = 0
    total_amp = total_cyc = 0
    reasons: Counter = Counter()

    shapes = [("chain", 5), ("chain", 10), ("fanout", 5), ("diamond", 0), ("ring", 3),
              ("ring", 5)]
    for kind, n in shapes:
        if kind == "chain":
            agents = shape_chain(n)
        elif kind == "fanout":
            agents = shape_fanout(n)
        elif kind == "diamond":
            agents = shape_diamond()
        else:
            agents = shape_ring(n)
        agents["__sink__"] = CAP_UNIVERSE[:2]
        s = make_system(agents)
        toks = build_shape(s, kind, n, rnd)
        r = exercise(s, toks, rnd, 60)
        cases.append({"case": f"{kind}(n={n})", **{k: r[k] for k in
                                                   ("tokens", "receipts", "effects",
                                                    "allows", "denies", "cyclic_tokens")}})
        violations += [f"{kind}(n={n}) {x}" for x in r["violations"]]
        total_tok += r["tokens"]; total_rec += r["receipts"]; total_eff += r["effects"]
        total_allows += r["allows"]; total_denies += r["denies"]
        total_amp += r["amplify_attempts"]; total_cyc += r["cyclic_tokens"]
        reasons.update(r["reasons"])

    for i in range(n_random):
        n = rnd.randint(3, 7)
        agents = {f"n{j}": (list(CAP_UNIVERSE) if j == 0
                            else rnd.sample(CAP_UNIVERSE, rnd.randint(1, 4)))
                  for j in range(n)}
        agents["__sink__"] = CAP_UNIVERSE[:2]
        s = make_system(agents)
        toks = []
        for _ in range(rnd.randint(n, 3 * n)):
            frm = rnd.choice([f"n{j}" for j in range(n)])
            to = rnd.choice([a for a in agents if a != frm])
            t = delegate_edge(s, frm, to, rnd, f"t{rnd.randint(0, 99)}",
                              narrow=(rnd.random() < 0.5))
            if t:
                toks.append(t)
        r = exercise(s, toks, rnd, 40)
        violations += [f"random#{i} {x}" for x in r["violations"]]
        total_tok += r["tokens"]; total_rec += r["receipts"]; total_eff += r["effects"]
        total_allows += r["allows"]; total_denies += r["denies"]
        total_amp += r["amplify_attempts"]; total_cyc += r["cyclic_tokens"]
        reasons.update(r["reasons"])

    vacuous = []
    if total_allows == 0:
        vacuous.append("没有任何 ALLOW，断言退化为平凡")
    if total_denies == 0:
        vacuous.append("没有任何 DENY，强制路径未被触发")
    if total_amp == 0:
        vacuous.append("未发起越权派生尝试")
    if total_cyc == 0:
        vacuous.append("未构造出环形委托，环场景未被覆盖")
    return {"oracle_agreement": oracle_agreement(),
            "fixed_shapes": len(shapes), "random_graphs": n_random,
            "cases": cases, "violations": violations[:20],
            "violation_count": len(violations),
            "tokens_total": total_tok, "receipts_total": total_rec,
            "effects_total": total_eff, "allows_total": total_allows,
            "denies_total": total_denies, "amplify_attempts": total_amp,
            "cyclic_tokens": total_cyc, "deny_reasons": dict(reasons),
            "vacuous": vacuous}


def main() -> int:
    res = topology_suite()
    oa = oracle_agreement()
    print(f"独立口径 vs 实现口径：{oa['trials']} 组抽样，不一致 {oa['disagreements']} 组")
    if oa["disagreements"]:
        print("  样例:", oa["sample"])
        return 1
    print(f"固定形状 {res['fixed_shapes']} 个 + 随机图 {res['random_graphs']} 个；"
          f"令牌 {res['tokens_total']}，收据 {res['receipts_total']}，"
          f"副作用 {res['effects_total']}")
    for c in res["cases"]:
        print(f"  {c['case']:14s} tokens={c['tokens']:3d} receipts={c['receipts']:3d} "
              f"effects={c['effects']:3d}")
    print(f"  非平凡性：ALLOW {res['allows_total']}，DENY {res['denies_total']}，"
          f"越权派生尝试 {res['amplify_attempts']}，环形令牌 {res['cyclic_tokens']}")
    print(f"  拒绝原因分布：{res['deny_reasons']}")
    if res["vacuous"]:
        print("\n测试退化：" + "；".join(res["vacuous"]))
        return 1
    if res["violation_count"]:
        print(f"\n违反 {res['violation_count']} 项：")
        for x in res["violations"]:
            print("  -", x)
        return 1
    print("\n全部性质在固定形状与随机图上成立"
          "（P1/I1/I2/I3/I5 与〔越权派生被拒〕）。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
