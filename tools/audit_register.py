"""锚定登记表的机械校验器。

    python3 -m tools.audit_register        # 退出码 0 = 三条件全部满足

三条件（缺一即失败）：
  1. 每个**输入**要么有外部锚定（`external`/`mechanical`），要么显式标注为自造/假设并给出处置。
  2. 每个**基线**要么有独立实现路径（`independent`），要么显式标注为共用路径/不适用并给出处置。
  3. 每条**断言**要么有机械检查（`check` 指向的文件与符号真实存在），要么显式标注 `unimplemented`/`unverified` 并给出理由。

校验是**结构性的**：它不能判断标注是否诚实，只能保证没有"未标注"的项。
诚实性由 paper/review_findings.md 与外部审读承担——这是本工具的能力边界，写在这里以免被误当作正确性证明。
"""
from __future__ import annotations

import json
import os
import re
import sys

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REG = os.path.join(HERE, "data", "anchoring_register.json")


def _resolve_symbol(path: str, symbol: str) -> bool:
    """检查 `file::symbol` 中的符号确实出现在该文件里（存在性检查，非语义检查）。"""
    full = os.path.join(HERE, path)
    if not os.path.exists(full):
        return False
    try:
        text = open(full, encoding="utf-8").read()
    except OSError:
        return False
    return re.search(rf"\b{re.escape(symbol)}\b", text) is not None


def audit(reg: dict) -> tuple[list[str], dict]:
    allowed = reg["allowed"]
    problems: list[str] = []
    stats = {"inputs": 0, "baselines": 0, "assertions": 0,
             "self_made": 0, "assumption": 0, "shared_path": 0,
             "unimplemented": 0, "unverified": 0, "checked": 0}

    for it in reg["inputs"]:
        stats["inputs"] += 1
        st = it.get("status")
        if st not in allowed["input_status"]:
            problems.append(f"输入 {it['id']}：status={st!r} 不在允许集合内")
            continue
        if st in ("external", "mechanical") and not it.get("anchor"):
            problems.append(f"输入 {it['id']}：标注为 {st} 但没有 anchor")
        if st in ("self_made", "assumption", "mixed") and not it.get("disposition"):
            problems.append(f"输入 {it['id']}：标注为 {st} 但缺少 disposition（处置说明）")
        if st in ("self_made", "assumption"):
            stats[st] += 1

    for b in reg["baselines"]:
        stats["baselines"] += 1
        st = b.get("status")
        if st not in allowed["baseline_status"]:
            problems.append(f"基线 {b['id']}：status={st!r} 不在允许集合内")
            continue
        if st == "shared_path":
            stats["shared_path"] += 1
            if not b.get("shared_with") or not b.get("disposition"):
                problems.append(f"基线 {b['id']}：标注为共用路径但缺少 shared_with 或 disposition")

    for a in reg["assertions"]:
        stats["assertions"] += 1
        st = a.get("status")
        if st not in allowed["assertion_status"]:
            problems.append(f"断言 {a['id']}：status={st!r} 不在允许集合内")
            continue
        if st in ("checked", "measured"):
            stats["checked"] += 1
            ck = a.get("check") or ""
            if "::" not in ck:
                problems.append(f"断言 {a['id']}：status={st} 但 check 不是 file::symbol 形式")
                continue
            path, sym = ck.split("::", 1)
            if not _resolve_symbol(path, sym):
                problems.append(f"断言 {a['id']}：check 指向的 {ck} 不存在或符号未找到")
        else:
            stats[st] += 1
            if not a.get("reason"):
                problems.append(f"断言 {a['id']}：status={st} 但缺少 reason")

    return problems, stats


# ---------------------------------------------------------------- 规格↔代码字段一致性
# 存在理由：本项目的"文档漂移"簇有一个可诊断的机制——**静默失效的字符串替换**。
# 用于替换的目标串与文件实际内容不匹配时，`str.replace` 什么都不做且不报错，
# 于是"已修复"会被写进报告而实际未发生。规格里 Link 的定义就这样落后于实现很久。
# 本检查把"规格声明的对象字段"与"代码里的 dataclass 字段"做机械比对，使这类漂移无法静默存在。

FIELD_BLOCKS = ["Token", "Link", "RootGrant", "ActionRequest", "Receipt",
                "RevocationEpoch"]


def spec_code_field_check() -> list[str]:
    import importlib
    import re as _re
    spec = open(os.path.join(HERE, "spec", "spec.md"), encoding="utf-8").read()
    model = importlib.import_module("src.model")
    problems = []
    for name in FIELD_BLOCKS:
        m = _re.search(rf"^{name} \{{(.*?)\}}", spec, _re.S | _re.M)
        if not m:
            problems.append(f"规格未声明对象 {name} 的字段块（或格式不匹配）")
            continue
        raw = _re.sub(r"#[^\n]*", "", m.group(1))          # 去注释
        spec_fields = set()
        for chunk in raw.split(","):
            mm = _re.match(r"\s*([A-Za-z_][A-Za-z0-9_]*)", chunk)
            if mm:
                spec_fields.add(mm.group(1))
        cls = getattr(model, name, None)
        if cls is None:
            problems.append(f"src/model.py 中不存在 {name}")
            continue
        code_fields = set(cls.__dataclass_fields__)
        only_spec = sorted(spec_fields - code_fields)
        only_code = sorted(code_fields - spec_fields)
        if only_spec:
            problems.append(f"{name}：规格声明但代码没有的字段 {only_spec}")
        if only_code:
            problems.append(f"{name}：代码有但规格未声明的字段 {only_code}")
    return problems


def main() -> int:
    with open(REG, encoding="utf-8") as f:
        reg = json.load(f)
    problems, stats = audit(reg)
    print(f"登记表：输入 {stats['inputs']}（自造 {stats['self_made']}、假设 {stats['assumption']}）、"
          f"基线 {stats['baselines']}（共用路径 {stats['shared_path']}）、"
          f"断言 {stats['assertions']}（有检查 {stats['checked']}、"
          f"未实现 {stats['unimplemented']}、未验证 {stats['unverified']}）")
    fc = spec_code_field_check()
    print(f"规格↔代码字段一致性：{'通过' if not fc else f'{len(fc)} 项不一致'}")
    for x in fc:
        print("  -", x)
    problems = problems + fc
    if problems:
        print(f"\n未标注或不一致 {len(problems)} 项：")
        for p in problems:
            print("  -", p)
        return 1
    print("\n三条件全部满足：每个输入、基线、断言都已锚定或显式标注。")
    print("注意：本校验只保证「没有未标注项」，不判断标注是否诚实——"
          "诚实性由 paper/review_findings.md 与外部审读承担。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
