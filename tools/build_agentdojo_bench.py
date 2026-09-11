"""一次性工具：从 AgentDojo 抽取**真实工具集与真实任务**，作为能力宇宙的外部锚定。

    python3 -m tools.build_agentdojo_bench

产出 `data/agentdojo_bench.json`。与 `build_agentdojo_corpus.py` 一样：
**构建期联网，实验期只读本地文件。**

抽取内容与依据（全部机械可复现，不含研究者的语义判断）：

| 抽取项 | 来源 | 规则 |
|---|---|---|
| capability | 各 suite `task_suite.py` 的 `TOOLS` 列表 | 工具函数名 |
| 工具参数 | 函数签名 | **排除** `Annotated[..., Depends(...)]` 参数（AgentDojo 自身也不把它们暴露给模型） |
| effect 类别 | 函数体静态分析 | 是否对外部依赖参数（`Depends(...)` 标注的那个形参）的属性做写入/可变调用 |
| 真实任务 | `user_tasks.py` 的 `ground_truth()` | 抽 `FunctionCall(function=..., args={...})` 的字面量 |
| 危害集合 | `injection_tasks.py` 的 `security()` | 该方法引用的工具名——**这是基准自己定义的"什么算安全违规"** |

最后一行是本文件存在的主要理由：它让危害模型有了**外部锚定**，
而不是由本仓库手写一张表。
"""
from __future__ import annotations

import argparse
import ast
import glob
import json
import os
import re
import sys
import zipfile

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CACHE = os.path.join(HERE, ".cache")
SRC = os.path.join(CACHE, "x")
OUT = os.path.join(HERE, "data", "agentdojo_bench.json")
SUITES = ["banking", "slack", "travel", "workspace"]
VERSION = "v1"


def ensure_src() -> bool:
    if os.path.isdir(SRC):
        return True
    import subprocess
    os.makedirs(CACHE, exist_ok=True)
    r = subprocess.run([sys.executable, "-m", "pip", "download", "--no-deps",
                        "-d", CACHE, "agentdojo"], capture_output=True, text=True)
    wheels = glob.glob(os.path.join(CACHE, "agentdojo-*.whl"))
    if r.returncode != 0 or not wheels:
        print("下载失败：\n" + (r.stderr or r.stdout)[-400:], file=sys.stderr)
        return False
    with zipfile.ZipFile(wheels[0]) as z:
        z.extractall(SRC)
    return True


PURE_ACCESSORS = {"values", "keys", "items", "get", "copy", "count", "index",
                  "lower", "upper", "strip", "split", "startswith", "endswith",
                  "format", "join", "replace", "find", "isoformat", "dict",
                  "model_dump", "model_copy", "__len__", "__contains__"}


def _depends_aliases(tree: ast.AST) -> dict[str, str]:
    """模块级类型别名 → 是否为 Depends 标注。AgentDojo 里有 `AnnotatedSlack = Annotated[...]`。"""
    out = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Subscript):
            for t in node.targets:
                if isinstance(t, ast.Name) and "Depends(" in ast.unparse(node.value):
                    out[t.id] = "depends"
                    m = re.search(r'Depends\(\s*["\']([^"\']+)["\']',
                                  ast.unparse(node.value))
                    if m:
                        out[t.id + "::target"] = m.group(1)
    return out


def _depends_target(fn: ast.FunctionDef, aliases: dict | None = None) -> str | None:
    """取出 `Depends("名字")` 里的**名字** —— 即该工具所操作的环境对象。"""
    aliases = aliases or {}
    for a in fn.args.args:
        ann = ast.unparse(a.annotation) if a.annotation else ""
        m = re.search(r'Depends\(\s*["\']([^"\']+)["\']', ann)
        if m:
            return m.group(1)
        for name, kind in aliases.items():
            if kind == "depends" and ann.split("[")[0].strip() == name:
                return aliases.get(name + "::target", name)
    return None


def extract_environments(suite: str) -> list[str]:
    """抽出该 suite 的 `TaskEnvironment` 字段名 —— 基准自身的环境对象分解。

    这是把**委托拓扑**从"研究者发明"变成"基准的函数"的依据：一个环境对象一个 Agent。
    """
    path = os.path.join(SRC, "agentdojo", "default_suites", VERSION, suite, "task_suite.py")
    if not os.path.exists(path):
        return []
    tree = ast.parse(open(path, encoding="utf-8").read())
    for cls in [n for n in tree.body if isinstance(n, ast.ClassDef)]:
        bases = [ast.unparse(b) for b in cls.bases]
        if any("TaskEnvironment" in b for b in bases):
            return [ast.unparse(st.target).split(":")[0].strip()
                    for st in cls.body if isinstance(st, ast.AnnAssign)]
    return []


def _depends_param(fn: ast.FunctionDef, aliases: dict | None = None) -> str | None:
    """找出环境依赖形参名（`Depends(...)` 直接标注，或经模块级类型别名标注）。"""
    aliases = aliases or {}
    for a in fn.args.args:
        ann = ast.unparse(a.annotation) if a.annotation else ""
        if "Depends(" in ann:
            return a.arg
        for name, kind in aliases.items():
            if kind == "depends" and ann.split("[")[0].strip() == name:
                return a.arg
    return None


def _env_derived(fn: ast.FunctionDef, env_param: str) -> set[str]:
    """从 env 派生出的本地名字（如 `transaction = next(... account ...)`）。"""
    derived = {env_param}
    for node in ast.walk(fn):
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.expr):
            src = ast.unparse(node.value)
            if any(re.search(rf"\b{re.escape(d)}\b", src) for d in derived):
                for t in node.targets:
                    if isinstance(t, ast.Name):
                        derived.add(t.id)
    return derived


# 声明式动词：用于对静态规则做**独立交叉验证**，不参与判定
WRITE_VERBS = {"send", "delete", "create", "update", "modify", "cancel", "reschedule",
               "add", "share", "reserve", "append", "set", "schedule", "remove",
               "transfer", "pay", "post", "invite"}
READ_VERBS = {"get", "read", "list", "search", "find", "retrieve", "check", "show",
              "return", "look", "query", "view"}


def _mutates(fn: ast.FunctionDef, env_param: str | None) -> bool:
    """静态判断是否会写入环境。

    规则（机械、可复现）：
      a. 对 env 形参派生出的目标赋值 / 下标赋值；
      b. **对 env 对象本身发起的任何方法调用**（AgentDojo 的环境对象是纯容器，
         上面的方法调用即变更，如 `inbox.delete_email(...)`）；
      c. 对 env 属性调用已知的容器变更方法。
    """
    if env_param is None:
        return False
    derived = _env_derived(fn, env_param)
    rooted = re.compile(r"^(" + "|".join(re.escape(d) for d in derived) + r")\b")

    def env_rooted(text: str) -> bool:
        return bool(rooted.match(text))

    for node in ast.walk(fn):
        # a. 对 env 派生目标赋值 / 下标赋值（含经局部别名的写入）
        if isinstance(node, (ast.Assign, ast.AugAssign, ast.AnnAssign)):
            tgts = node.targets if isinstance(node, ast.Assign) else [node.target]
            for t in tgts:
                if isinstance(t, ast.Attribute):
                    if env_rooted(ast.unparse(t.value)):
                        return True
                elif isinstance(t, ast.Subscript) and env_rooted(ast.unparse(t.value)):
                    return True
        # b. 对 env 对象发起的变更型方法调用
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr not in PURE_ACCESSORS and env_rooted(
                    ast.unparse(node.func.value)):
                return True
    return False


def _docstring_verb(doc: str) -> str | None:
    w = (doc.strip().split(" ")[0].lower().strip(".:") if doc.strip() else "")
    if w in WRITE_VERBS:
        return "write"
    if w in READ_VERBS:
        return "read"
    return None


def extract_tools() -> dict:
    """工具名 → {params, doc, mutates}。"""
    tools: dict[str, dict] = {}
    td = os.path.join(SRC, "agentdojo", "default_suites", VERSION, "tools")
    for path in sorted(glob.glob(os.path.join(td, "*.py"))):
        tree = ast.parse(open(path, encoding="utf-8").read())
        aliases = _depends_aliases(tree)
        # **只取模块级函数**：`ast.walk` 会连类方法一并遍历，同名方法会覆盖模块级函数，
        # 使 `depends_on` 变成 None（如 email_client 里 `Inbox.send_email` 覆盖了模块级 `send_email`）。
        for fn in [n for n in tree.body if isinstance(n, ast.FunctionDef)]:
            if fn.name.startswith("_"):
                continue
            env = _depends_param(fn, aliases)
            params = []
            for a in fn.args.args:
                if a.arg in ("self", env) or a.arg.startswith("_"):
                    continue
                ann = ast.unparse(a.annotation) if a.annotation else ""
                if "Depends(" in ann:
                    continue
                params.append({"name": a.arg, "type": ann or "Any"})
            doc = (ast.get_docstring(fn) or "").split("\n")[0]
            tools[fn.name] = {
                "depends_on": _depends_target(fn, aliases),
                "params": params,
                "doc": doc,
                "mutates": _mutates(fn, env),
                "docstring_verb_class": _docstring_verb(doc),
                "module": os.path.basename(path),
                "suite_tools": [],
            }
    return tools


def _suite_tool_names(path: str) -> list[str]:
    tree = ast.parse(open(path, encoding="utf-8").read())
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
                isinstance(t, ast.Name) and t.id == "TOOLS" for t in node.targets):
            return [e.id for e in node.value.elts if isinstance(e, ast.Name)]
    return []


def extract_user_tasks(suite: str) -> list[dict]:
    path = os.path.join(SRC, "agentdojo", "default_suites", VERSION, suite, "user_tasks.py")
    if not os.path.exists(path):
        return []
    tree = ast.parse(open(path, encoding="utf-8").read())
    out = []
    for cls in [n for n in tree.body if isinstance(n, ast.ClassDef)]:
        prompt = None
        calls = []
        for node in ast.walk(cls):
            if isinstance(node, ast.Assign) and any(
                    isinstance(t, ast.Name) and t.id == "PROMPT" for t in node.targets):
                if isinstance(node.value, ast.Constant):
                    prompt = node.value.value
            if isinstance(node, ast.Call) and getattr(node.func, "id", "") == "FunctionCall":
                kw = {k.arg: k.value for k in node.keywords}
                fname = kw.get("function")
                fargs = kw.get("args")
                if not (isinstance(fname, ast.Constant) and isinstance(fargs, ast.Dict)):
                    continue
                simple = {}
                for k, v in zip(fargs.keys, fargs.values):
                    kn = k.value if isinstance(k, ast.Constant) else None
                    if kn is None:
                        continue
                    if isinstance(v, ast.Constant) and isinstance(
                            v.value, (str, int, float, bool)):
                        simple[kn] = v.value
                calls.append({"function": fname.value, "args": simple})
        if prompt and calls:
            out.append({"id": cls.name, "prompt": " ".join(prompt.split()),
                        "ground_truth": calls})
    return out


def extract_injection_security(suite: str) -> list[dict]:
    """注入任务的 `ground_truth()` 调用了哪些工具 —— 基准自己定义的"恶意动作"。

    这比解析 `security()` 更可靠：`security()` 检查的是环境状态（如"有没有转给攻击者 IBAN"），
    并不直接引用工具名；而 `ground_truth()` 就是基准认定的攻击动作序列。
    """
    path = os.path.join(SRC, "agentdojo", "default_suites", VERSION, suite,
                        "injection_tasks.py")
    if not os.path.exists(path):
        return []
    tree = ast.parse(open(path, encoding="utf-8").read())
    out = []
    for cls in [n for n in tree.body if isinstance(n, ast.ClassDef)]:
        goal, gt_tools = None, []
        for node in ast.walk(cls):
            if isinstance(node, ast.Assign) and any(
                    isinstance(t, ast.Name) and t.id == "GOAL" for t in node.targets):
                goal = " ".join(ast.unparse(node.value).strip("f\"'").split())
            if isinstance(node, ast.Call) and getattr(node.func, "id", "") == "FunctionCall":
                kw = {k.arg: k.value for k in node.keywords}
                fn_node = kw.get("function")
                if isinstance(fn_node, ast.Constant) and isinstance(fn_node.value, str):
                    gt_tools.append(fn_node.value)
        out.append({"id": cls.name, "goal": goal,
                    "ground_truth_tools": sorted(set(gt_tools))})
    return out


def _cross_check_ok(mutating: bool, verb_class: str | None) -> bool:
    """静态规则与声明式动词的一致性（仅用于验证，不参与判定）。"""
    if verb_class is None:
        return True
    return (verb_class == "write") == mutating


def build() -> dict:
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "bcc", os.path.join(HERE, "tools", "build_agentdojo_corpus.py"))
    bcc = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(bcc)

    tools = extract_tools()
    suites_out = {}
    for suite in SUITES:
        names = _suite_tool_names(os.path.join(
            SRC, "agentdojo", "default_suites", VERSION, suite, "task_suite.py"))
        for n in names:
            if n in tools:
                tools[n]["suite_tools"].append(suite)
        suites_out[suite] = {
            "environments": extract_environments(suite),
            "tools": names,
            "user_tasks": extract_user_tasks(suite),
            "injection_tasks": extract_injection_security(suite),
        }

    harm = sorted({t for s in suites_out.values()
                   for it in s["injection_tasks"] for t in it["ground_truth_tools"]})
    suite_tools = sorted({t for s in suites_out.values() for t in s["tools"]})
    agree = [t for t in suite_tools
             if _cross_check_ok(tools[t]["mutates"], tools[t]["docstring_verb_class"])]
    return {
        "source": {"package": "agentdojo", "version": "0.1.35",
                   "license": "MIT (ETH Zurich SPY Lab)",
                   "url": "https://github.com/ethz-spylab/agentdojo"},
        "extraction": {
            "tools_total": len(tools),
            "suite_tools_total": len(suite_tools),
            "mutates_vs_docstring_checked": len(agree),
            "mutates_vs_docstring_agree": len(agree),
            "mutating_tools": sorted(t for t, d in tools.items() if d["mutates"]),
            "readonly_tools": sorted(t for t, d in tools.items() if not d["mutates"]),
            "harm_set_from_injection_ground_truth": harm,
            "note": "危害集合 = 各注入任务 ground_truth() 调用的工具（基准认定的恶意动作），"
                    "由基准自身定义，非本仓库手写；effect 类别由函数体静态分析得出。"
                    "注意：这是**能力级**集合——AgentDojo 不提供数据分级目录，"
                    "因此真实基底上无法按（能力 × 资源模式）判定危害，"
                    "与 spec §2.10 的要求存在已知偏差。",
        },
        "tools": tools,
        "suites": suites_out,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--offline", action="store_true")
    args = ap.parse_args()
    if not (os.path.isdir(SRC) or (not args.offline and ensure_src())):
        print(f"无法准备 {SRC}", file=sys.stderr)
        return 1
    data = build()
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=1)
    e = data["extraction"]
    print(f"写出 {OUT}")
    print(f"  工具 {e['tools_total']} 个：可变 {len(e['mutating_tools'])}，"
          f"只读 {len(e['readonly_tools'])}")
    print(f"  来自注入任务 ground_truth() 的危害集合"
          f"（{len(e['harm_set_from_injection_ground_truth'])} 个）："
          f"{e['harm_set_from_injection_ground_truth']}")
    print(f"  静态规则与 docstring 动词一致：{e['mutates_vs_docstring_agree']}"
          f"/{e['suite_tools_total']}")
    for s, d in data["suites"].items():
        print(f"  {s}: 工具 {len(d['tools'])}, 用户任务 {len(d['user_tasks'])}, "
              f"注入任务 {len(d['injection_tasks'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
