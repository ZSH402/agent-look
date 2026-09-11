"""回查器：把我此前**报告过的每一处「已修复/已更正」**逐条机械核对。

    python3 -m tools.verify_fixes     # 退出码 0 = 全部属实

存在理由：本项目出现过一次〔报告已修复、实际静默失败〕——我用 `str.replace` 改规格里的
`Link` 字段定义，替换目标带了反引号而文件实际内容没有，替换什么都没做且不报错，
我未经验证就把〔已修复〕写进了汇报。数日后由独立复现者发现。

**因此凡是我口头报告过的修复，都必须能在这里被机械验证。** 检查分两类：

  - `present` / `absent`：字面量存在/不存在检查（防"静默失败"最直接的手段）
  - `python`：结构或行为检查

覆盖不到、只能靠人读的，显式登记为 `manual` 并写明理由——**不许留空**。
"""
from __future__ import annotations

import importlib
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SPEC = os.path.join(HERE, "spec", "spec.md")
README = os.path.join(HERE, "README.md")
REG = os.path.join(HERE, "data", "anchoring_register.json")


def _read(p: str) -> str:
    return open(p, encoding="utf-8").read() if os.path.exists(p) else ""


def build_checks() -> list[dict]:
    spec, readme = _read(SPEC), _read(README)
    bench = json.loads(_read(os.path.join(HERE, "data", "agentdojo_bench.json")) or "{}")
    return [
        # ---- 规格 ↔ 代码字段（原〔静默失败〕那一处）----
        {"id": "F1", "claim": "规格 Link 字段已与代码对齐", "kind": "python",
         "fn": lambda: not importlib.import_module(
             "tools.audit_register").spec_code_field_check()},
        {"id": "F2", "claim": "规格 Link 不再含 new_scope_hash", "kind": "absent",
         "file": SPEC, "needle": "new_scope_hash"},
        {"id": "F3", "claim": "规格 Link 已含 redelegatable", "kind": "present",
         "file": SPEC, "needle": "redelegatable"},
        # ---- 其余〔已修复〕汇报 ----
        {"id": "F4", "claim": "key_epoch 比较已统一为严格大于", "kind": "present",
         "file": SPEC, "needle": "严格大于"},
        {"id": "F5", "claim": "撤销上界表述已统一为 pull_interval + ttl", "kind": "present",
         "file": SPEC, "needle": "`pull_interval + ttl`"},
        {"id": "F6", "claim": "规格不再出现〔回落 到 TTL〕的单说表述", "kind": "absent",
         "file": SPEC, "needle": "安全上界回落到 **TTL**"},
        {"id": "F7", "claim": "E24 偏差表述不再用手写的 5–50 倍", "kind": "absent",
         "file": SPEC, "needle": "5–50 倍"},
        {"id": "F8", "claim": "规格检测器特征已标注未实现", "kind": "python",
         "fn": lambda: _read(SPEC).count("**未实现**") >= 2},
        {"id": "F9", "claim": "patterns.py 的 coarsen_levels 死代码已删除", "kind": "absent",
         "file": os.path.join(HERE, "src", "patterns.py"), "needle": "def coarsen_levels"},
        {"id": "F10", "claim": "bench 字段名已改为 harm_set_from_injection_ground_truth",
         "kind": "python",
         "fn": lambda: "harm_set_from_injection_ground_truth" in bench.get("extraction", {})},
        {"id": "F11", "claim": "bench 说明不再称取自 security()", "kind": "python",
         "fn": lambda: "security()" not in bench.get("extraction", {}).get("note", "")},
        {"id": "F12", "claim": "README 陈旧 RTT 数值已清除", "kind": "python",
         "fn": lambda: all(x not in readme for x in
                           ("回环 TCP 0.24", "78.9ms", "44 项断言", "27 组实验"))},
        {"id": "F13", "claim": "README 引用冻结测量产物", "kind": "present",
         "file": README, "needle": "measurement_rtt.json"},
        {"id": "F14", "claim": "selfcheck 的 I4 已改为可证伪检查", "kind": "present",
         "file": os.path.join(HERE, "experiments", "selfcheck.py"),
         "needle": "def stale_credential_check"},
        {"id": "F15", "claim": "粗化单调性已有机械检查", "kind": "present",
         "file": os.path.join(HERE, "experiments", "selfcheck.py"),
         "needle": "def coarsening_monotone_check"},
        {"id": "F16", "claim": "P4-chain 已从规格断言表中删除", "kind": "absent",
         "file": SPEC, "needle": "以接收方签名为终点的收据链"},
        {"id": "F17", "claim": "装置自证禁令已并入 §2.16（无独立 §2.17 装置自证）",
         "kind": "absent", "file": SPEC, "needle": "### 2.17 装置自证禁令"},
        {"id": "F18", "claim": "规格章节顺序已修正（§2.x 均在「## 2. 对象」之后）",
         "kind": "python", "fn": lambda: _section_order_ok()},
        {"id": "F19", "claim": "手写 HARMFUL 能力表已从 scope_experiments 移除",
         "kind": "absent",
         "file": os.path.join(HERE, "experiments", "scope_experiments.py"),
         "needle": "HARMFUL = {"},
        {"id": "F20", "claim": "能力宇宙上下文管理器存在且 ladder 使用它",
         "kind": "python", "fn": lambda: _universe_cm_used()},
        {"id": "F21", "claim": "E26 已把 L3 读法敏感性作为一等输出", "kind": "python",
         "fn": lambda: "l3_reading_sensitivity" in _read(
             os.path.join(HERE, "experiments", "run_all.py"))},
        {"id": "F22", "claim": "冻结测量产物存在且带 provenance", "kind": "python",
         "fn": lambda: bool(json.loads(_read(os.path.join(
             HERE, "data", "measurement_rtt.json")) or "{}").get("provenance"))},
        {"id": "F23", "claim": "规格 §8 实验协议存在（补写前支柱 B 主实验不可复现）",
         "kind": "present", "file": SPEC, "needle": "## 8. 实验协议"},
        {"id": "F24", "claim": "规格已钉死 L3 锚定规则与 0-based 跳映射", "kind": "python",
         "fn": lambda: all(x in spec for x in ("锚定参数名", "从 0 开始"))},
        # ---- 只能人读的 ----
        {"id": "F25", "claim": "论文 draft.md 顶部已加〔已撤销〕横幅，且摘要在内的旧表述已标注",
         "kind": "python",
         "fn": lambda: ("本文处于「已撤销」状态" in _read(os.path.join(HERE, "paper", "draft.md"))
                        and "已撤销：同义反复" in _read(os.path.join(HERE, "paper", "draft.md")))},
        {"id": "F26", "claim": "README 顶部有〔已被撤销的结论〕表",
         "kind": "present", "file": README, "needle": "已被外部审读撤销的结论"},
    ]


def _func_source(relpath: str, symbol: str) -> str:
    """取出某个函数/方法的源码文本（用于"不得引用某标识符"这类否定检查）。"""
    import ast
    src = _read(os.path.join(HERE, relpath))
    tree = ast.parse(src)
    lines = src.splitlines()
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == symbol:
            return "\n".join(lines[node.lineno - 1:node.end_lineno])
    raise LookupError(f"{relpath}::{symbol} 未找到")


def behavioural_checks() -> list[dict]:
    """**系统扫描**：规格里每一条描述实现行为的断言，逐条对代码核对。

    与上面那组（我"记得报告过"的修复）不同，这组是从规格出发穷举，
    不依赖我的记忆——静默漂移最容易藏在这里。
    """
    return [
        # 注意：此处最初写成「runtime.py 全文不得出现 req.text」，那**是检查写错了**。
        # 规格要求不读文本的是 **P 的判定算法（§3.2 `_enforce`）**；
        # B2 基线本就定义为「读文本的护栏」，它读 `req.text` 是符合规格的。
        # 正确的检查是：判定算法内不出现，且全文唯一的 text 读者是 B2 护栏。
        {"id": "B1", "claim": "§3.2 判定算法（_enforce）不读 req.text；全文唯一读 text 处为 B2 护栏",
         "kind": "python",
         "fn": lambda: "text" not in _func_source("src/runtime.py", "_enforce")
                       and _read(os.path.join(HERE, "src", "runtime.py")).count("req.text") == 1},
        {"id": "B2", "claim": "§2.4/§3.2 判定路径不调用权威（不做运行时中心查询）",
         "kind": "python",
         "fn": lambda: not re.search(r"authority\.(current|verify_grant)\(",
                                     _func_source("src/runtime.py", "_enforce"))},
        {"id": "B3", "claim": "§2.5 收据由接收方 PEP 签名", "kind": "present",
         "file": os.path.join(HERE, "src", "runtime.py"),
         "needle": "r = replace(r, sig=sign(self.sk, r.body()))"},
        {"id": "B4", "claim": "§2.5 收据进证据平面", "kind": "present",
         "file": os.path.join(HERE, "src", "runtime.py"),
         "needle": "return s.evidence.submit(r)"},
        {"id": "B5", "claim": "§2.7 redelegatable=False 时拒绝派生", "kind": "present",
         "file": os.path.join(HERE, "src", "tokens.py"), "needle": "NOT_REDELEGATABLE"},
        {"id": "B6", "claim": "§2.12 分区时停止拉取撤销状态", "kind": "python",
         "fn": lambda: _func_source("src/runtime.py", "maybe_pull").count("partitioned") >= 1},
        {"id": "B7", "claim": "§2.12 复合动作原子判定存在于 _enforce", "kind": "present",
         "file": os.path.join(HERE, "src", "runtime.py"), "needle": "req.required"},
        {"id": "B8", "claim": "§4 漂移检测器不读取自由文本", "kind": "python",
         "fn": lambda: "text" not in _func_source("src/runtime.py", "observe")},
        # 由存在性检查改为行为检查：放宽**绝不能收窄**。早期实现对 `**` 做"末段换 *"，
        # 把它收窄成只匹配单段资源，反而使任务失败。规则迁移到 rules.py 后此处一并加强。
        {"id": "B9", "claim": "§8.3 对象族放宽永不收窄（行为检查）", "kind": "python",
         "fn": lambda: _widen_never_narrows()},
        {"id": "B10", "claim": "§3.2 归因检查要求请求由发送方 PEP 签名", "kind": "present",
         "file": os.path.join(HERE, "src", "runtime.py"), "needle": "R_UNSIGNED"},
        {"id": "B11", "claim": "§3.2 签发者绑定：token_issuer(token) == req.from_id",
         "kind": "present", "file": os.path.join(HERE, "src", "runtime.py"),
         "needle": "token_issuer(token) != req.from_id"},
        {"id": "B12", "claim": "§7 I3 的真检查是〔副作用数 == ALLOW 收据数〕", "kind": "present",
         "file": os.path.join(HERE, "experiments", "selfcheck.py"),
         "needle": "len(s.world.effects) == len(allowed)"},
        # 规格声明的 reason_code 必须与实现可达集合一致——双向。
        # 上线即抓到 `UNKNOWN_TASK` 被声明却从不产生（已从规格删除）。
        {"id": "B13", "claim": "§2.5 声明的 reason_code 与实现可达集合一致", "kind": "python",
         "fn": lambda: _reason_codes_match()},
        # 差分测试实测 `STALE_CREDENTIAL` 在黑盒路径上不可达（§3.2 步骤 4 是死代码）。
        # B13 只是字面量查找、证不了可达——这条检查补上真正的可达性。
        {"id": "B14", "claim": "STALE_CREDENTIAL 实际可达（撤销→过期顺序与刷新语义修复后）",
         "kind": "python", "fn": lambda: _stale_reachable()},
        {"id": "B15", "claim": "§2.8 段不得为空：matches/subsumes 不做斜杠归一化且自洽",
         "kind": "python", "fn": lambda: _empty_segment_rule()},
        {"id": "B16", "claim": "§3.2 时效窗口是双向的（未来时间戳被拒）",
         "kind": "present", "file": os.path.join(HERE, "src", "runtime.py"),
         "needle": "req.ts > now + sys.clock_skew"},
        {"id": "B17", "claim": "§5 凭证刷新按链根解析授权（不再用当前授权）",
         "kind": "present", "file": os.path.join(HERE, "src", "runtime.py"),
         "needle": "def resolve_grant"},
        # 第三轮全新读者指出：实现声称"纯离线验证"，实际却查权威的内部历史
        # （`grant_for_root_id` 遍历 `authority.grant_history`）。在单进程模拟器里看不出差别，
        # 结构上却不成立。已改为在**本地持有的凭据副本**中解析。
        {"id": "B29", "claim": "验证路径不查权威内部历史（离线验证名副其实）", "kind": "python",
         "fn": lambda: ("grant_history" not in _func_source("src/runtime.py", "_enforce")
                        and "authority" not in _func_source("src/runtime.py", "resolve_grant")
                        and "def resolve_grant" in _read(os.path.join(HERE, "src", "runtime.py")))},
        {"id": "B30", "claim": "委托随令牌送达其所依据的根凭据副本", "kind": "present",
         "file": os.path.join(HERE, "src", "runtime.py"),
         "needle": "install_grant(self.authority.grants[tok.root_subject_id])"},
        # E28/E29/E30 证明「粗化规则本身」就能翻转结论。既然规则是被证明影响结论的东西，
        # 它就不允许在两条基底路径里各存一份——必须只有一处实现。
        {"id": "B31", "claim": "粗化规则只在 experiments/rules.py 中实现（无副本）", "kind": "python",
         "fn": lambda: _rules_single_source()},
        # 全新读者指出：规则 6（密钥作废）的 reason_code 规格未规定，它选了 TOKEN_INVALID，
        # 参考实现返回 TOKEN_REVOKED。已钉死为后者，这里做**可达性**检查而非字面量检查。
        {"id": "B18", "claim": "§2.3 规则 6 的失败实际报 TOKEN_REVOKED", "kind": "python",
         "fn": lambda: _key_epoch_reason()},
        {"id": "B19", "claim": "§3.2 已定义 clock_skew 及其可接受区间", "kind": "python",
         "fn": lambda: ("clock_skew" in _read(SPEC)
                        and "now - max_request_age" in _read(SPEC))},
        # 反身性：健全性测试查不出"判假过多"。此项引用自检脚本里的同名检查。
        {"id": "B20", "claim": "subsumes 反身性（自检脚本已覆盖）", "kind": "present",
         "file": os.path.join(HERE, "experiments", "selfcheck.py"),
         "needle": "subsume_reflexive"},
        # 第二轮差分测试的四类剩余分歧，全部已修/已钉死。
        {"id": "B21", "claim": "§2.3 顺序：未撤销+已过期+密钥作废 ⇒ TOKEN_EXPIRED", "kind": "python",
         "fn": lambda: _priority_expired_before_key()},
        {"id": "B22", "claim": "§2.3 派生规则按列举顺序：封条+越界 ⇒ SCOPE_VIOLATION", "kind": "python",
         "fn": lambda: _derive_rule_order()},
        {"id": "B23", "claim": "§3.1 委托方不保留所授令牌副本", "kind": "python",
         "fn": lambda: _issuer_keeps_no_copy()},
        {"id": "B24", "claim": "§2.3 已定义“链根”的表示", "kind": "present",
         "file": SPEC, "needle": "链根的表示"},
        # 第三轮差分测试发现的规格不足
        {"id": "B25", "claim": "§8.3 已钉死 L4 为常量算子（空跳也有定义）", "kind": "present",
         "file": SPEC, "needle": "L4` 是常量算子"},
        {"id": "B26", "claim": "§8.3 已限定 L3 的 adj 取值范围为 U", "kind": "present",
         "file": SPEC, "needle": "该基底的 `U`"},
        {"id": "B27", "claim": "§8.4 已钉死可达半径的 witness 构造规则", "kind": "present",
         "file": SPEC, "needle": "`w` 的构造规则"},
        {"id": "B28", "claim": "四 suite × 五级 × 三指标与独立复现逐项一致", "kind": "python",
         "fn": lambda: _four_suite_match()},
        # 合规项：仓库分发由 AgentDojo（MIT）派生的数据，必须随附其版权声明与许可证正文。
        # 加这条是因为曾发现仓库里只有 README 的一句话署名，没有捆绑 MIT 正文，
        # 也没有 THIRD_PARTY/NOTICE 文件。
        {"id": "B32", "claim": "随仓库分发的 AgentDojo 派生数据已附第三方署名与 MIT 正文",
         "kind": "python", "fn": lambda: _third_party_attribution_ok()},
    ]


KNOWN_RC = ["OK", "SCOPE_VIOLATION", "TOKEN_EXPIRED", "TOKEN_REVOKED", "TOKEN_INVALID",
            "TASK_MISMATCH", "REPLAY", "NOT_REDELEGATABLE", "REQUEST_UNSIGNED",
            "STALE_CREDENTIAL", "PDP_UNAVAILABLE", "GUARD_BLOCK", "RECEIPT_INVALID",
            "LOCAL_FAILFAST"]


def _third_party_attribution_ok() -> bool:
    """第三方署名存在且覆盖了两个派生数据文件，并含 MIT 正文。

    注意：这条只检查「署名存在且指向正确」，**不判断派生数据本身是否合规使用**——
    那是人读项，登记在 THIRD_PARTY.md 里。
    """
    path = os.path.join(HERE, "THIRD_PARTY.md")
    if not os.path.exists(path):
        return False
    t = _read(path)
    return all(x in t for x in ("agentdojo", "0.1.35", "MIT License",
                                "data/agentdojo_corpus.json", "data/agentdojo_bench.json",
                                "Copyright (c) 2024 Edoardo Debenedetti"))


def _reason_codes_match() -> bool:
    """规格声明的 reason_code 集合 == 实现中可达的集合。

    实现方式：对**已声明的清单**逐个做字面量查找，而不是用"长得像常量"的启发式去扫。
    启发式版本曾漏掉 `REPLAY` 与 `OK`（它们不含下划线），导致误报——**是检查写错了，不是代码错了**。

    **能力边界**：这是字面量查找，只能证明"该码在源码中出现"，不能证明它**可达**
    （一个死字符串同样满足）。要证可达需实际触发每条分支，本检查不做。
    """
    src = _read(os.path.join(HERE, "src", "runtime.py")) + \
        _read(os.path.join(HERE, "src", "tokens.py")) + \
        _read(os.path.join(HERE, "src", "model.py"))
    declared_all = set(KNOWN_RC) | {"OK", "UNKNOWN_TASK"}
    reachable = {rc for rc in declared_all if f'"{rc}"' in src}
    m = re.search(r"`reason_code ∈ \{(.*?)\}`", _read(SPEC), re.S)
    if not m:
        return False
    declared = {x.strip() for x in m.group(1).split(",")}
    return declared == (reachable - {"UNKNOWN_TASK"})


def _four_suite_match() -> bool:
    """把实现产出的四 suite 阶梯与**独立复现**的数字逐项比对。

    这是本项目唯一被完整独立复现的架构级实验，因此值得作为常驻检查——
    任何后续改动若使数字偏离，此检查立刻失败。
    """
    import json as _json
    rep = os.path.join(HERE, "replication", "differential", "all_suites.json")
    res = os.path.join(HERE, "results", "results.json")
    if not (os.path.exists(rep) and os.path.exists(res)):
        return False
    theirs = _json.loads(_read(rep))
    mine = _json.loads(_read(res))["E26_real_substrate"]["real"]
    LV = ["L0_exact", "L1_family", "L2_drop_object", "L3_over_verb", "L4_no_derivation"]
    for suite in ("banking", "slack", "travel", "workspace"):
        m = mine[suite]["ladder"]
        if [x["surplus_grants"] for x in m] != \
                [theirs[suite]["levels"][k]["surplus_count"] for k in LV]:
            return False
        if [x["harmful"]["benchmark_injection_gt"] for x in m] != \
                [theirs[suite]["levels"][k]["harm_count"] for k in LV]:
            return False
        if [round(x["surplus_mean_radius"], 3) for x in m] != \
                [round(theirs[suite]["levels"][k]["mean_radius"], 3) for k in LV]:
            return False
    return True


def _priority_expired_before_key() -> bool:
    """未撤销、已过期、且密钥作废 → 按钉死顺序（撤销→过期→密钥作废）应为 TOKEN_EXPIRED。"""
    import sys as _s
    _s.path.insert(0, HERE)
    from src.runtime import System
    s = System(mode="P", ttl=20)
    s.add_agent("A", "C", ["order.read"])
    s.add_agent("B", "W", ["order.read"])
    t = s.delegate("A", "B", ["order.read"], "k")
    s.advance(30)                                  # 令牌过期
    s.authority.revoke_key_epochs("A", 1, s.now)   # 且密钥作废
    s.advance(s.pull_interval + 1)                 # 让接收方看到
    r = s.request("A", "B", t.token_id, "order.read", "orders/1", "k")
    return r.decision == "DENY" and r.reason_code == "TOKEN_EXPIRED"


def _derive_rule_order() -> bool:
    """父令牌已封条 且 子范围越界 → 按派生规则列举顺序应为 SCOPE_VIOLATION。"""
    import sys as _s
    _s.path.insert(0, HERE)
    from src.model import Deny
    from src.runtime import System
    s = System(mode="P")
    s.add_agent("A", "C", ["order.read"])
    s.add_agent("B", "W", ["order.read"])
    t = s.delegate("A", "B", ["order.read"], "k", redelegatable=False)
    try:
        s.delegate("B", "A", ["db.admin"], "x", parent_token_id=t.token_id)
        return False
    except Deny as e:
        return e.reason_code == "SCOPE_VIOLATION"


def _issuer_keeps_no_copy() -> bool:
    """委托方不得保留所授令牌的可用副本。"""
    import sys as _s
    _s.path.insert(0, HERE)
    from src.runtime import System
    s = System(mode="P")
    s.add_agent("A", "C", ["order.read"])
    s.add_agent("B", "W", ["order.read"])
    t = s.delegate("A", "B", ["order.read"], "k")
    return t.token_id not in s.peps["A"].tokens and t.token_id in s.peps["B"].tokens


def _widen_never_narrows() -> bool:
    """放宽后的模式必须**包含**原模式：匹配原模式的资源也必须匹配放宽后的模式。"""
    import sys as _s
    _s.path.insert(0, HERE)
    from experiments.rules import widen_family
    from src.patterns import matches
    pats = ("**", "*", "a", "a/b", "a/*", "orders/**", "a/**", "x/y/z")
    res = ("a", "a/b", "a/b/c", "x/y/z", "orders/2024-001", "/a")
    return all(not matches(p, r) or matches(widen_family(p), r)
               for p in pats for r in res)


def _rules_single_source() -> bool:
    """粗化规则不得在两条路径里各写一份——E28/E29/E30 已证明它们本身能翻转结论。"""
    defs = ("def _widen(", "def _adjacency(", "def _adjacency_param(",
            "def adjacency_param(", "def adjacency_object(",
            "def resource_universe(", "def l3_adjacency(")
    holders = []
    for f in ("experiments/substrate.py", "experiments/derived_topology.py",
              "experiments/rules.py"):
        text = _read(os.path.join(HERE, f))
        for d in defs:
            if d in text:
                holders.append((f, d))
    # rules.py 是唯一允许的实现处
    return all(f.endswith("rules.py") for f, _d in holders) and len(holders) > 0


def _key_epoch_reason() -> bool:
    """构造"根密钥 epoch 作废"的场景，确认它确实产生 TOKEN_REVOKED。"""
    import sys as _s
    _s.path.insert(0, HERE)
    from src.runtime import System
    s = System(mode="P")
    s.add_agent("A", "C", ["order.read"])
    s.add_agent("B", "W", ["order.read"])
    t = s.delegate("A", "B", ["order.read"], "task-k")
    s.authority.revoke_key_epochs("A", 1, s.now)
    # **必须先推进时间让接收方拉取撤销状态**：本检查初版漏了这一步，
    # 于是拿到 OK 并误判为代码错——实际是"撤销传播延迟"的正常表现（P3）。
    # 这是本项目第三次出现"检查写错而非代码错"。
    s.advance(s.pull_interval + 1)
    r = s.request("A", "B", t.token_id, "order.read", "orders/1", "task-k")
    return r.decision == "DENY" and r.reason_code == "TOKEN_REVOKED"


def _stale_reachable() -> bool:
    """构造刷新序列，确认 `STALE_CREDENTIAL` 真的会被产生（而不只是出现在源码里）。"""
    import sys as _s
    _s.path.insert(0, HERE)
    from src.runtime import System
    s = System(mode="P")
    s.add_agent("A", "C", ["order.read", "order.update"])
    s.add_agent("B", "W", ["order.read"])
    t1 = s.delegate("A", "B", ["order.read"], "task-1")
    s.authority.issue_grant("A", ["order.read", "order.update"], s.now)
    s.peps["B"].refresh_grant(s.authority.grants["A"])          # B 刷新到新 epoch
    r = s.request("A", "B", t1.token_id, "order.read", "orders/1", "task-1")
    return r.decision == "DENY" and r.reason_code == "STALE_CREDENTIAL"


def _empty_segment_rule() -> bool:
    """空段规则：不归一化、且 matches 与 subsumes 自洽。"""
    from src.patterns import matches, subsumes
    if matches("a", "a/") or matches("a", "/a") or matches("a", "a//"):
        return False                       # 不得把含空段的资源当成合法段
    if matches("a/*", "a//b"):
        return False
    if not matches("orders/*", "orders/7"):
        return False                       # 正常资源仍须匹配
    if not matches("**", "a//"):           # 无条件模式匹配一切
        return False
    # 自洽：若 subsumes(p,q) 为真，则任何匹配 p 的资源必须匹配 q
    r = "a/"
    if subsumes("a/", "a/*") and matches("a/", "a/") and not matches("a/", "a/*"):
        return False
    return True


def _section_order_ok() -> bool:
    s = _read(SPEC)
    i_obj = s.find("## 2. 对象")
    if i_obj < 0:
        return False
    # §2.1 起的所有小节都应出现在「## 2. 对象」之后
    for n in range(1, 18):
        m = re.search(rf"^### 2\.{n}\b", s, re.M)
        if m and m.start() < i_obj:
            return False
    return True


def _universe_cm_used() -> bool:
    sub = _read(os.path.join(HERE, "experiments", "substrate.py"))
    return "def universe(" in sub and "with universe(sub.universe)" in sub


def run() -> int:
    fails, manual = [], []
    checks = build_checks() + behavioural_checks()
    for c in checks:
        if c["kind"] == "manual":
            manual.append(c)
            continue
        ok = False
        detail = ""
        try:
            if c["kind"] == "present":
                ok = c["needle"] in _read(c["file"])
                detail = f"未在 {os.path.relpath(c['file'], HERE)} 中找到 {c['needle']!r}"
            elif c["kind"] == "absent":
                ok = c["needle"] not in _read(c["file"])
                detail = f"{os.path.relpath(c['file'], HERE)} 中仍存在 {c['needle']!r}"
            elif c["kind"] == "python":
                ok = bool(c["fn"]())
                detail = "谓词为假"
        except Exception as e:                      # noqa: BLE001
            ok, detail = False, f"{type(e).__name__}: {e}"
        print(f"[{'OK  ' if ok else 'FAIL'}] {c['id']} {c['claim']}"
              + ("" if ok else f"  ← {detail}"))
        if not ok:
            fails.append(c["id"])
    print()
    print(f"机械核查 {len(checks) - len(manual)} 项，失败 {len(fails)}；"
          f"仅能人读 {len(manual)} 项。")
    for c in manual:
        print(f"  [MANUAL] {c['id']} {c['claim']} —— {c['reason']}")
    if fails:
        print(f"\n以下汇报与实际不符：{fails}")
        return 1
    print("\n全部机械核查通过（人读项已显式登记，不计入通过）。")
    return 0


if __name__ == "__main__":
    sys.exit(run())
