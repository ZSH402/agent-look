"""赛道扫描：系统采集同赛道最新论文，并抽取**它们自己承认的**局限与未来工作。

为什么这么做
------------
此前两次判断"有没有人做过"都用的搜索引擎片段，属于"我搜不到就等于没有"，
证据强度最低，而且连错两次。改用两个可核对的口径：

1. 用 **arXiv API** 按日期倒序系统采集（覆盖面可控），而不是搜索引擎抽样；
2. 判据取自**论文自己的局限段原文**，而不是我从标题推测它没做什么。

输出 `results/landscape.json`（结构化）与 `results/landscape.md`（可读）。

运行：python3 -m tools.landscape_scan
"""
from __future__ import annotations

import json
import os
import re
import html
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(HERE, "results", "landscape.json")
OUTMD = os.path.join(HERE, "results", "landscape.md")

QUERIES = [
    'all:"least privilege" AND all:agent',
    'all:"capability" AND all:delegation AND all:agent',
    'all:"prompt injection" AND all:agent AND all:defense',
    'all:"tool" AND all:"permission" AND all:"LLM agent"',
    'abs:"multi-agent" AND abs:security AND abs:LLM',
    'all:"capability scoping" OR all:"scope derivation"',
    'all:"authorization" AND all:agent AND all:"least privilege"',
    'all:"over-privileged" OR all:"over-permissioned"',
    'all:"agent" AND all:"delegation chain"',
    'all:"subagent" OR all:"sub-agent" AND all:security',
]

# 我们要验证的三个"未解决"主张，逐条给出判定用的检索式
CHECKS = {
    "A_子智能体委托下的权限边界推导":
        r"sub-?agent|delegat|multi-?agent|handoff|orchestrat",
    "B_非文件系统_即API级_权限边界":
        r"\bAPI\b|tool[- ]level|network access|cloud|MCP|database credent|browser state",
    "C_跨跳失败归因":
        r"attribut|blame|which agent|root cause|localiz",
}


def arxiv_search(q: str, n: int = 25) -> list[dict]:
    url = ("https://export.arxiv.org/api/query?search_query="
           + q.replace('"', "%22").replace(" ", "%20").replace("(", "%28").replace(")", "%29")
           + f"&sortBy=submittedDate&sortOrder=descending&max_results={n}")
    r = subprocess.run(["curl", "-sL", "--max-time", "45", url],
                       capture_output=True)
    t = r.stdout.decode("utf-8", "ignore")
    out = []
    for e in re.findall(r"<entry>(.*?)</entry>", t, re.S):
        try:
            aid = re.search(r"<id>(.*?)</id>", e).group(1).split("/abs/")[-1]
            pub = re.search(r"<published>(.*?)</published>", e).group(1)[:10]
            ti = re.sub(r"\s+", " ", html.unescape(
                re.search(r"<title>(.*?)</title>", e, re.S).group(1))).strip()
            ab = re.sub(r"\s+", " ", html.unescape(
                re.search(r"<summary>(.*?)</summary>", e, re.S).group(1))).strip()
            out.append({"id": aid, "date": pub, "title": ti, "abstract": ab})
        except Exception:                                          # noqa: BLE001
            continue
    return out


def paper_text(aid: str) -> str:
    base = aid.split("v")[0]
    for url in (f"https://arxiv.org/html/{aid}", f"https://arxiv.org/html/{base}v1",
                f"https://ar5iv.labs.arxiv.org/html/{base}"):
        r = subprocess.run(["curl", "-sL", "--max-time", "60", "-A", "Mozilla/5.0", url],
                           capture_output=True)
        t = r.stdout.decode("utf-8", "ignore")
        if len(t) < 20000:
            continue
        t = re.sub(r"<script.*?</script>", " ", t, flags=re.S)
        t = re.sub(r"<style.*?</style>", " ", t, flags=re.S)
        return re.sub(r"\s+", " ", html.unescape(re.sub("<[^>]+>", " ", t)))
    return ""


LIMIT_HEAD = re.compile(
    r"(Limitations?( and Future Work| and future work| & Future Work)?"
    r"|Future Work|Future Directions|Open (Problems|Questions|Challenges|Issues)"
    r"|Discussion and Limitations|Threats to Validity)", re.I)


def limitations_section(txt: str, span: int = 6000) -> str:
    """取最后一次出现的「局限/未来工作」标题起的一段（跳过目录里的同名条目）。"""
    hits = [m for m in LIMIT_HEAD.finditer(txt)]
    if not hits:
        return ""
    # 目录里的条目长度很短，正文标题后面会跟大段文字；取最靠后且后继足够长的那个
    for m in reversed(hits):
        seg = txt[m.end():m.end() + span]
        if len(seg.strip()) > 400:
            return seg.strip()
    return txt[hits[-1].end():hits[-1].end() + span].strip()


def main() -> int:
    seen: dict[str, dict] = {}
    for q in QUERIES:
        got = arxiv_search(q)
        for p in got:
            b = p["id"].split("v")[0]
            if b not in seen:
                seen[b] = p
        print(f"  {q[:52]:54} -> {len(got):3d}（累计 {len(seen)}）")
        time.sleep(3)

    # 只保留 2026 年 5 月以后，且标题/摘要落在赛道内的
    KEY = re.compile(r"agent|tool|capabilit|privileg|permission|delegat|inject|authoriz",
                     re.I)
    cands = [p for p in seen.values()
             if p["date"] >= "2026-05-01" and KEY.search(p["title"] + " " + p["abstract"][:600])]
    cands.sort(key=lambda p: p["date"], reverse=True)
    print(f"\n候选 {len(cands)} 篇，逐篇抓取局限段…")

    rows = []
    for i, p in enumerate(cands):
        txt = paper_text(p["id"])
        lim = limitations_section(txt) if txt else ""
        row = dict(p)
        row["text_len"] = len(txt)
        row["limitations"] = lim
        row["has_limitations"] = bool(lim)
        print(f"  [{i+1}/{len(cands)}] {p['id']:14} text={len(txt):7d} lim={len(lim):5d}  {p['title'][:58]}")
        rows.append(row)
        with open(OUT, "w", encoding="utf-8") as f:
            json.dump({"queries": QUERIES, "rows": rows}, f, ensure_ascii=False, indent=1)
        time.sleep(2)

    # 逐条核对三个"未解决"主张
    verdict = {}
    for name, pat in CHECKS.items():
        rx = re.compile(pat, re.I)
        hit = [r["id"] for r in rows if rx.search(r["limitations"])]
        verdict[name] = {"pattern": pat, "papers_whose_limitations_mention_it": hit,
                         "count": len(hit)}
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump({"queries": QUERIES, "checks": verdict, "rows": rows}, f,
                  ensure_ascii=False, indent=1)

    md = ["# 赛道扫描：论文自己承认的局限\n",
          f"候选 {len(rows)} 篇，其中 {sum(1 for r in rows if r['has_limitations'])} 篇抓到局限段。\n",
          "## 对三条「未解决」主张的核对\n"]
    for name, v in verdict.items():
        md.append(f"### {name}\n命中 {v['count']} 篇：{', '.join(v['papers_whose_limitations_mention_it']) or '（无）'}\n")
    md.append("\n## 逐篇局限段原文\n")
    for r in rows:
        md.append(f"### {r['id']} — {r['title']}\n*{r['date']}*\n")
        md.append((r["limitations"] or "（未抓到局限段）")[:2600] + "\n")
    with open(OUTMD, "w", encoding="utf-8") as f:
        f.write("\n".join(md))
    print(f"\n完成 -> {OUT} / {OUTMD}")
    return 0


def summary() -> int:
    """只读已冻结的 results/landscape.json 打印汇总，不联网。"""
    with open(OUT, encoding="utf-8") as f:
        d = json.load(f)
    rows = d["rows"]
    ds = sorted(r["date"] for r in rows)
    KEY = re.compile(r"least.?privileg|capabilit|permission|privileg|delegat|authoriz|"
                     r"over.?privileg|skill|scope", re.I)
    hit = [r for r in rows if KEY.search(r["title"])]
    print(f"采集查询数        {len(d['queries'])}")
    print(f"候选论文数        {len(rows)}")
    print(f"日期区间          {ds[0]} .. {ds[-1]}")
    print(f"抓到局限段的论文  {sum(1 for r in rows if r.get('has_limitations'))}")
    print(f"标题直接命中主题词（最小权限/能力/授权/委托/越权/技能）  {len(hit)}")
    print()
    print("其中与我这个问题最直接冲突的：")
    for r in sorted(hit, key=lambda x: x["date"], reverse=True)[:12]:
        print(f"  {r['date']}  {r['id']:14} {r['title'][:66]}")
    return 0


if __name__ == "__main__":
    if "--summary" in sys.argv:
        raise SystemExit(summary())
    raise SystemExit(main())
