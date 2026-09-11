"""从论文里抽出它们的开源仓库，下载后与本仓库代码做机械重合检查。

为什么这样做
------------
第一次只比对了 AgentDojo —— 它恰好 pip 装在本地，所以被比到了；
真正要紧的竞品（capmas、SkillScope、WebMASLab、AIRGuard 等）一行都没比。
而用 GitHub 关键词搜索找仓库噪声极大（返回的是长尾项目，不是论文配套仓库）。
**论文正文里的 GitHub 链接才是它们的真实仓库地址。**

两种口径同时用：
1. **10-gram 标识符重合** —— 抽 `[A-Za-z_][A-Za-z0-9_]{2,}` 序列比对。
   局限：非 ASCII 全被丢弃，因此中文注释不影响结果，**翻译过注释的拷贝也可能部分逃过**。
2. **整行精确重合** —— 长度 ≥ 25 的代码行按去空行后逐行比对。
   这一条对"原样搬运"最敏感。

输出 `results/repo_overlap.json`。

运行：python3 -m tools.repo_overlap
"""
from __future__ import annotations

import io
import json
import os
import re
import subprocess
import sys
import tarfile
import time

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(HERE, "results", "repo_overlap.json")
GH = re.compile(r"github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)")

# 从已扫描的赛道论文里挑最相关的（按标题关键词）
REL = re.compile(r"least.?privileg|capabilit|permission|privileg|delegat|authoriz|"
                 r"scope|over.?privileg|tool|MCP|govern", re.I)


def paper_text(aid: str) -> str:
    base = aid.split("v")[0]
    for url in (f"https://arxiv.org/html/{aid}",
                f"https://ar5iv.labs.arxiv.org/html/{base}"):
        r = subprocess.run(["curl", "-sL", "--max-time", "60", "-A", "Mozilla/5.0", url],
                           capture_output=True)
        t = r.stdout.decode("utf-8", "ignore")
        if len(t) > 20000:
            return re.sub(r"\s+", " ", re.sub("<[^>]+>", " ", t))
    return ""


MINE_DIRS = ("src", "experiments", "tools")
MINE = []
for d in MINE_DIRS:
    for root, _, files in os.walk(os.path.join(HERE, d)):
        for fn in files:
            if fn.endswith(".py"):
                MINE.append(os.path.join(root, fn))


def ident_ngrams(text: str, n: int = 10) -> set:
    ts = re.findall(r"[A-Za-z_][A-Za-z0-9_]{2,}", text.lower())
    return {tuple(ts[i:i + n]) for i in range(len(ts) - n + 1)}


def code_lines(text: str) -> set:
    out = set()
    for ln in text.splitlines():
        s = ln.strip()
        if len(s) >= 25 and not s.startswith("#"):
            out.add(re.sub(r"\s+", " ", s))
    return out


def main() -> int:
    # 仓库列表已抽好就复用（抽链接要重抓 28 篇论文，很慢）
    if os.path.exists(OUT) and "--compare-only" in sys.argv:
        with open(OUT, encoding="utf-8") as f:
            prev = json.load(f)
        repos = {r["repo"]: r["papers"] for r in prev["rows"]}
        print(f"复用已抽出的 {len(repos)} 个仓库")
    else:
        with open(os.path.join(HERE, "results", "landscape.json"), encoding="utf-8") as f:
            land = json.load(f)["rows"]
        cands = [r for r in land if REL.search(r["title"])]
        cands.sort(key=lambda r: r["date"], reverse=True)
        cands = cands[:28]
        print(f"从 {len(cands)} 篇最相关论文里抽仓库链接…")
        repos = {}
        for r in cands:
            t = paper_text(r["id"])
            found = set()
            for m in GH.finditer(t):
                o, n = m.group(1), m.group(2).removesuffix(".git")
                if n.lower() in ("github", "blob", "tree", "raw", "releases", "issues"):
                    continue
                found.add(f"{o}/{n}")
            for f_ in found:
                repos.setdefault(f_, []).append(r["id"])
            print(f"  {r['id']:14} {len(found):2d} 个链接  {r['title'][:52]}")
            time.sleep(1)
        repos.setdefault("haven-nyuad/webmas", []).append("2608.00202")
        print(f"\n去重后 {len(repos)} 个仓库，开始下载比对…")

    base_ng = set()
    for p in MINE:
        with open(p, encoding="utf-8", errors="ignore") as f:
            base_ng |= ident_ngrams(f.read())
    base_ln = set()
    for p in MINE:
        with open(p, encoding="utf-8", errors="ignore") as f:
            base_ln |= code_lines(f.read())
    print(f"本仓库：{len(MINE)} 个 py 文件，{len(base_ng)} 个 10-gram，{len(base_ln)} 条代码行")

    rows = []
    for i, (slug, papers) in enumerate(sorted(repos.items())):
        # codeload 不接受 refs/heads/HEAD，必须先拿到真实默认分支
        api = subprocess.run(
            ["curl", "-sL", "--max-time", "30",
             f"https://api.github.com/repos/{slug}"], capture_output=True)
        try:
            br = json.loads(api.stdout.decode()).get("default_branch") or "main"
        except Exception:                                            # noqa: BLE001
            br = "main"
        blob = b""
        for b in dict.fromkeys([br, "main", "master"]):
            r = subprocess.run(
                ["curl", "-sL", "--max-time", "180",
                 f"https://codeload.github.com/{slug}/tar.gz/refs/heads/{b}"],
                capture_output=True)
            if r.stdout[:2] == b"\x1f\x8b":
                blob = r.stdout
                break
        row = {"repo": slug, "papers": papers, "bytes": len(blob),
               "py_files": 0, "ngram_overlap": 0, "line_overlap": 0,
               "examples": []}
        if len(blob) > 2000 and blob[:2] == b"\x1f\x8b":
            try:
                with tarfile.open(fileobj=io.BytesIO(blob)) as tf:
                    for m in tf.getmembers():
                        if not m.isfile() or not m.name.endswith(".py") or m.size > 400000:
                            continue
                        try:
                            src = tf.extractfile(m).read().decode("utf-8", "ignore")
                        except Exception:                            # noqa: BLE001
                            continue
                        row["py_files"] += 1
                        inter = base_ng & ident_ngrams(src)
                        row["ngram_overlap"] += len(inter)
                        row["line_overlap"] += len(base_ln & code_lines(src))
                        if inter and len(row["examples"]) < 3:
                            row["examples"].append(" ".join(sorted(inter)[0])[:110])
            except Exception as e:                                   # noqa: BLE001
                row["error"] = f"{type(e).__name__}: {e}"
        else:
            row["error"] = "下载失败（非 gzip）"
        rows.append(row)
        print(f"  [{i+1}/{len(repos)}] {slug[:44]:46} py={row['py_files']:4d} "
              f"ng={row['ngram_overlap']:5d} ln={row['line_overlap']:4d} {row.get('error','')}")
        with open(OUT, "w", encoding="utf-8") as f:
            json.dump({"mine": {"files": len(MINE), "ngrams": len(base_ng),
                                "lines": len(base_ln)}, "rows": rows},
                      f, ensure_ascii=False, indent=1)
        time.sleep(1)

    print("\n=== 有重合的仓库 ===")
    hit = [r for r in rows if r["ngram_overlap"] or r["line_overlap"]]
    if not hit:
        print("  无")
    for r in sorted(hit, key=lambda x: -x["ngram_overlap"]):
        print(f"  {r['repo'][:44]:46} ng={r['ngram_overlap']:5d} ln={r['line_overlap']:4d}")
        for e in r["examples"]:
            print(f"       e.g. {e}")
    print(f"\n完成 -> {OUT}")
    return 0


def summary() -> int:
    """只读已冻结的 results/repo_overlap.json 打印比对表，不联网。"""
    with open(OUT, encoding="utf-8") as f:
        d = json.load(f)
    m, rows = d["mine"], d["rows"]
    print(f"本仓库代码: {m['files']} 个 py 文件, {m['ngrams']} 个 10-gram, {m['lines']} 条代码行")
    print()
    print(f"{'仓库':46} {'py':>5} {'10-gram':>8} {'相同代码行':>10}")
    print("-" * 74)
    for r in sorted(rows, key=lambda x: (-x["ngram_overlap"], -x["line_overlap"])):
        err = "  (下载失败)" if r.get("error") else ""
        print(f"{r['repo'][:46]:46} {r['py_files']:>5} {r['ngram_overlap']:>8} "
              f"{r['line_overlap']:>10}{err}")
    print("-" * 74)
    print(f"比对仓库 {len(rows)} 个；10-gram 重合最高 {max(r['ngram_overlap'] for r in rows)}"
          f"（占本仓库 {m['ngrams']} 个的 {max(r['ngram_overlap'] for r in rows)/m['ngrams']*100:.2f}%）")
    return 0


if __name__ == "__main__":
    if "--summary" in sys.argv:
        raise SystemExit(summary())
    raise SystemExit(main())
