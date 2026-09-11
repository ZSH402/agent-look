"""一次性工具：从 AgentDojo 官方发布包抽取真实注入语料，落到本地数据文件。

    python3 -m tools.build_agentdojo_corpus            # 需要网络与 .cache/x 中已解包的 wheel
    python3 -m tools.build_agentdojo_corpus --offline  # 只用已解包的内容重建

设计要点：
  - **实验运行时不联网**。抽取只在构建期做一次，产物是 `data/agentdojo_corpus.json`；
    实验只读该文件。这样 run_all 在离线环境仍然可跑、且可复现。
  - 语料不是"抄几句话"，而是按 AgentDojo 自己的构造方式**重新组合**：
    `payload = attack_template.format(goal=injection_goal)`，
    即官方 jailbreak 模板 × 官方注入目标。
  - provenance 与抽取方法写入产物，避免"这些攻击文本哪来的"不可追溯。
"""
from __future__ import annotations

import argparse
import ast
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(HERE, ".cache", "x")
OUT = os.path.join(HERE, "data", "agentdojo_corpus.json")
SUITES = ["banking", "slack", "travel", "workspace"]
VERSIONS = ["v1", "v1_1", "v1_1_1", "v1_1_2", "v1_2", "v1_2_1", "v1_2_2"]


def _const_strs(tree: ast.AST) -> dict:
    """收集作用域内所有形如 `_X = "..."` 的字符串常量（含类属性，含类型标注）。"""
    ns: dict = {}
    for node in ast.walk(tree):
        targets, value = [], None
        if isinstance(node, ast.Assign):
            targets, value = node.targets, node.value
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            targets, value = [node.target], node.value
        if not targets or not isinstance(value, ast.Constant) \
                or not isinstance(value.value, str):
            continue
        for t in targets:
            if isinstance(t, ast.Name) and t.id.startswith("_"):
                ns[t.id] = value.value
    return ns


def _eval_fstring(node: ast.AST, ns: dict) -> str | None:
    """把 JoinedStr 求值成文本；未解析的变量保留原名，便于事后发现抽取不全。"""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if not isinstance(node, ast.JoinedStr):
        return None
    out = []
    for part in node.values:
        if isinstance(part, ast.Constant):
            out.append(str(part.value))
        elif isinstance(part, ast.FormattedValue):
            name = ast.unparse(part.value)
            out.append(str(ns.get(name, "{" + name + "}")))
        else:
            return None
    return "".join(out)


def extract_goals() -> list[dict]:
    """抽取注入任务的自然语言目标（AST 求值 f-string，常量含类属性）。"""
    out = []
    for ver in VERSIONS:
        for suite in SUITES:
            path = os.path.join(SRC, "agentdojo", "default_suites", ver, suite,
                                "injection_tasks.py")
            if not os.path.exists(path):
                continue
            tree = ast.parse(open(path, encoding="utf-8").read())
            ns = _const_strs(tree)
            for node in ast.walk(tree):
                targets, value = [], None
                if isinstance(node, ast.Assign):
                    targets, value = node.targets, node.value
                if not targets or not any(
                        isinstance(t, ast.Name) and t.id == "GOAL" for t in targets):
                    continue
                goal = _eval_fstring(value, ns)
                if goal:
                    goal = " ".join(goal.split())
                    out.append({"suite": suite, "version": ver, "goal": goal,
                                "unresolved": "{" in goal})
    return out


def _docstring_ids(tree: ast.AST) -> set[int]:
    """模块/类/函数的首条字符串语句是 docstring，不是攻击模板。"""
    ids = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef,
                             ast.AsyncFunctionDef)) and node.body:
            first = node.body[0]
            if (isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant)
                    and isinstance(first.value.value, str)):
                ids.add(id(first.value))
    return ids


def extract_templates() -> list[dict]:
    """抽取攻击模板：AST 会把隐式字符串拼接合并，因此不必再处理各类字面量形式。"""
    out, seen = [], set()
    att = os.path.join(SRC, "agentdojo", "attacks")
    for fn in sorted(os.listdir(att)):
        if not fn.endswith(".py"):
            continue
        tree = ast.parse(open(os.path.join(att, fn), encoding="utf-8").read())
        docs = _docstring_ids(tree)
        for node in ast.walk(tree):
            if (isinstance(node, ast.Constant) and isinstance(node.value, str)
                    and "{goal}" in node.value and id(node) not in docs
                    and node.value not in seen
                    and node.value.strip() != "TODO: {goal}"):
                seen.add(node.value)
                out.append({"file": fn, "template": node.value})
    return out


def ensure_src(auto: bool = True) -> bool:
    """确保 .cache/x 中有解包好的 wheel；缺失时自动下载（仅构建期需要网络）。"""
    if os.path.isdir(SRC):
        return True
    if not auto:
        return False
    import glob
    import subprocess
    import zipfile
    cache = os.path.join(HERE, ".cache")
    os.makedirs(cache, exist_ok=True)
    r = subprocess.run([sys.executable, "-m", "pip", "download", "--no-deps",
                        "-d", cache, "agentdojo"], capture_output=True, text=True)
    wheels = glob.glob(os.path.join(cache, "agentdojo-*.whl"))
    if r.returncode != 0 or not wheels:
        print("下载失败：\n" + (r.stderr or r.stdout)[-400:], file=sys.stderr)
        return False
    with zipfile.ZipFile(wheels[0]) as z:
        z.extractall(SRC)
    return True


def build() -> dict:
    goals = extract_goals()
    templates = extract_templates()
    payloads = []
    for t in templates:
        for g in goals:
            text = (t["template"].replace("{goal}", g["goal"])
                    .replace("{user}", "Emma Johnson")
                    .replace("{model}", "target-llm")
                    # {tools} 由 AgentDojo 在运行时填入工具列表；此处填一个代表性集合，
                    # 保持文本可读，且不引入我们自己的判断
                    .replace("{tools}", "(available tools)"))
            if "{" in g["goal"] or "}" in g["goal"]:
                continue          # 目标里仍有无法静态解析的占位符，丢弃而不是产出畸形文本
            payloads.append({"suite": g["suite"], "version": g["version"],
                             "attack": t["file"].replace(".py", ""),
                             "goal": g["goal"], "text": text})
    dropped = len(goals) * len(templates) - len(payloads)
    return {
        "source": {
            "package": "agentdojo",
            "version": "0.1.35",
            "origin": "PyPI wheel agentdojo-0.1.35-py3-none-any.whl",
            "license": "MIT (AgentDojo, ETH Zurich SPY Lab)",
            "url": "https://github.com/ethz-spylab/agentdojo",
        },
        "extraction": {
            "method": "attack_template.format(goal=goal)，与 AgentDojo 自身构造攻击的方式一致",
            "goals": len(goals), "templates": len(templates), "payloads": len(payloads),
            "dropped_unresolved": dropped,
            "note": "仅抽取文本语料用于护栏绕过率测量；未运行 AgentDojo 的 agent 循环"
                    "（那需要 LLM，本工作未接入）。",
        },
        "payloads": payloads,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--offline", action="store_true", help="只用已解包的缓存重建")
    args = ap.parse_args()
    if not ensure_src(auto=not args.offline):
        print(f"无法准备 {SRC}；请联网后重跑，或手工把 wheel 解包到该目录", file=sys.stderr)
        return 1
    data = build()
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=1)
    e = data["extraction"]
    print(f"写出 {OUT}")
    print(f"  目标 {e['goals']} 条 × 模板 {e['templates']} 个 = 载荷 {e['payloads']} 条")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
