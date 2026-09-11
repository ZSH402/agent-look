"""生成文章用的截图。

原则：**截图内容必须来自命令的真实 stdout**，不允许手写。
唯一例外是 S1（检查器抓夸大），它需要人为破坏一次 README 再还原，
该图会在图注里显式标注为演示，并且还原写在 finally 里。

渲染方式：HTML -> chromium headless。
两个环境坑：/root 只读（chromium 需要可写 HOME）、/tmp 是每次 bash 调用私有的。

运行：python3 -m tools.make_shots
产出：article/shots/*.png 与 article/shots/CAPTIONS.md
"""
from __future__ import annotations

import html
import json
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUTDIR = os.path.join(HERE, "article", "shots")
CHOME = os.path.join(HERE, ".cache", "chromium-home")
LINE_H = 21
PAD = 18
HEAD_H = 34


def run(cmd: list[str], timeout: int = 900) -> str:
    """跑真实命令，返回真实 stdout（stderr 合并，便于看到报错）。"""
    r = subprocess.run(cmd, capture_output=True, cwd=HERE, timeout=timeout)
    return (r.stdout + r.stderr).decode("utf-8", "ignore")


def _esc_color(line: str) -> str:
    """只对输出里**字面存在**的标记着色，不改动任何字符。"""
    e = html.escape(line)
    if line.startswith("[BAD") or line.startswith("[FAIL") or "Traceback" in line:
        return f'<span style="color:#f48771">{e}</span>'
    if line.startswith("[OK"):
        return f'<span style="color:#89d185">{e}</span>'
    if line.startswith("$ "):
        return f'<span style="color:#569cd6">{e}</span>'
    if line.startswith("---") or line.startswith("==="):
        return f'<span style="color:#808080">{e}</span>'
    return e


def render(lines: list[str], out: str, width: int = 960, title: str | None = None,
           highlight: set[int] = frozenset()) -> None:
    body = []
    for i, ln in enumerate(lines):
        s = _esc_color(ln) or "&nbsp;"
        if i in highlight:
            body.append(f'<div style="background:#3a2d1a;margin:0 -18px;padding:0 18px">'
                        f'{s}</div>')
        else:
            body.append(f"<div>{s}</div>")
    head = (f'<div style="background:#252526;color:#aaa;padding:6px 18px;'
            f'font:12px/1.4 sans-serif;border-bottom:1px solid #333">{html.escape(title)}</div>'
            if title else "")
    h = HEAD_H + PAD * 2 + LINE_H * len(lines)
    doc = (f'<html><meta charset="utf-8"><body style="margin:0;background:#1e1e1e">'
           f'{head}<div style="font:13px/{LINE_H}px \'DejaVu Sans Mono\','
           f'\'Droid Sans Fallback\',monospace;color:#d4d4d4;padding:{PAD}px;'
           f'white-space:pre-wrap">{"".join(body)}</div></body></html>')
    hp = os.path.join(OUTDIR, "_tmp.html")
    with open(hp, "w", encoding="utf-8") as f:
        f.write(doc)
    os.makedirs(CHOME, exist_ok=True)
    env = dict(os.environ, HOME=CHOME, XDG_CONFIG_HOME=os.path.join(CHOME, ".config"))
    # chromium 的 --screenshot 按视口高度截，算低了会切掉尾部；
    # 因此给足余量渲染，再用 PIL 按内容裁掉底部空白。
    subprocess.run([
        "chromium", "--headless=new", "--no-sandbox", "--disable-gpu",
        "--disable-dev-shm-usage", "--disable-crash-reporter", "--hide-scrollbars",
        f"--screenshot={out}", f"--window-size={width},{h + 400}", f"file://{hp}",
    ], env=env, capture_output=True, timeout=180)
    try:
        from PIL import Image
        im = Image.open(out).convert("RGB")
        w0, h0 = im.size
        px = im.load()
        bg = px[w0 - 3, h0 - 3]
        last = 0
        for y in range(h0):
            row_diff = any(px[x, y] != bg for x in range(0, w0, 7))
            if row_diff:
                last = y
        im.crop((0, 0, w0, min(h0, last + 12))).save(out)
    except Exception as e:                                        # noqa: BLE001
        print(f"     （裁边失败，保留原图：{e}）")
    from PIL import Image as _I
    print(f"  -> {os.path.relpath(out, HERE)}  ({_I.open(out).size}, {len(lines)} 行)")


# ---------------------------------------------------------------------------
CAPTIONS: list[tuple[str, str, str]] = []


def shot1_check_catches_inflation() -> None:
    """S1：人为把 README 的结论写回"全部"，看检查器变红。演示性破坏，finally 还原。"""
    rp = os.path.join(HERE, "README.md")
    orig = open(rp, encoding="utf-8").read()
    needle = "其中 **6 个三路完全一致**"
    assert orig.count(needle) == 1, "README 里的锚点变了，S1 需重做"
    try:
        with open(rp, "w", encoding="utf-8") as f:
            f.write(orig.replace(needle, "其中 **全部三路完全一致**"))
        out = run([sys.executable, "-m", "experiments.verify_claims"])
    finally:
        with open(rp, "w", encoding="utf-8") as f:
            f.write(orig)
    lines = out.splitlines()
    bad = [l for l in lines if l.startswith("[BAD")]
    tail = [l for l in lines if l.strip()][-3:]
    show = ["$ python3 -m experiments.verify_claims",
            "  （已把 README 里「6 个三路完全一致」改回「全部三路完全一致」）",
            f"  （省略中间 {len(lines) - len(bad) - 3} 行）", ""] + bad + ["", "..."] + tail
    render(show, os.path.join(OUTDIR, "s1_guards_against_inflation.png"),
           title="检查器当场抓住一次夸大（演示：README 被故意改坏后还原）")
    CAPTIONS.append((
        "s1_guards_against_inflation.png",
        "把 README 里的「6 个三路完全一致」人为改回「全部三路完全一致」后，回归检查立刻变红。"
        "**注意：这是演示性破坏，跑完已还原**；图里省略了中间 200 余行正常的检查。",
        "§11「把自己倾向于夸大这件事本身写成回归测试」的 claim(...) 代码块之后"))


def shot2_a4_blanket() -> None:
    """S2：A4 知情复核者的一整屏无差别回答（真实冻结产物）。"""
    with open(os.path.join(HERE, "results", "cross_family_review.json"), encoding="utf-8") as f:
        a4 = json.load(f)["arms"]["A4"]["reply"]
    items = [l for l in a4.splitlines() if l.strip().startswith("- ")]
    show = ["$ python3 -c \"import json;print(json.load(open('results/cross_family_review.json'))"
            "['arms']['A4']['reply'])\"",
            f"  （共 {len(items)} 条判断，下面只截前 16 条）", ""]
    show += [l[:104] for l in items[:16]]
    show += ["", f"  ...（其余 {len(items) - 16} 条同样全部是「不过头」）"]
    render(show, os.path.join(OUTDIR, "s2_informed_reviewer_collapses.png"), width=1180,
           title="知情复核者的逐条回答：37 条全部「不过头」")
    CAPTIONS.append((
        "s2_informed_reviewer_collapses.png",
        "把全部自我批评交给复核者后，它对 37 条逐条判断，无差别地全部判为「不过头」。"
        "按事先登记的无效判据（无差别回答＝顺应提问方式），这一臂作废。",
        "§9「知道结论的复核者会塌缩成附和」，在 37 条那句之后"))


def shot3_cross_family_verdict() -> None:
    """S3：跨家族裁决的离线复核输出（真实命令）。"""
    out = run([sys.executable, "-m", "tools.cross_family_verdict"])
    show = ["$ python3 -m tools.cross_family_verdict", ""] + out.splitlines()
    render(show, os.path.join(OUTDIR, "s3_cross_family_verdict.png"), width=1000,
           title="跨家族审读的裁决（离线复核，不联网）")
    CAPTIONS.append((
        "s3_cross_family_verdict.png",
        "另一个家族的模型在只看到中性事实的前提下，独立确认了我 7 条自证判断中的 6 条，"
        "同时多标了 10 条；逐条裁决后 5 条成立、2 条有争议、3 条是过度触发。",
        "§8「我的判据本身就是盲区的一部分」，在「但它还多标了 10 条」之后"))


def shot4_tautology_code() -> None:
    """S4：基线 B1 调用与 P 相同的判定函数——同义反复的代码现场。"""
    with open(os.path.join(HERE, "src", "runtime.py"), encoding="utf-8") as f:
        src = f.read().splitlines()
    # 定位 CentralPDP.decide 里的 _enforce 调用
    start = next(i for i, l in enumerate(src) if "class CentralPDP" in l)
    end = next(i for i in range(start, len(src)) if "_enforce(self.sys" in src[i])
    seg = src[start - 6:end + 4]
    show = [f"$ sed -n '{start - 5},{end + 4}p' src/runtime.py", ""]
    hl = set()
    for k, l in enumerate(seg):
        show.append(f"{start - 5 + k:4d}  {l}")
        if "_enforce(self.sys" in l:
            hl.add(len(show) - 1)
    render(show, os.path.join(OUTDIR, "s4_tautology_baseline.png"), width=1020,
           highlight=hl, title="基线 B1 与被测器件 P 共用同一个判定函数")
    CAPTIONS.append((
        "s4_tautology_baseline.png",
        "基线 CentralPDP（B1）的 decide 直接调用 `_enforce`——也就是本架构 P 用的那个函数。"
        "两个共享同一条代码路径的东西做对比，报告「两者安全等价」是同义反复。",
        "§4.3「基线与被测器件共用代码路径」"))


def shot5_landscape() -> None:
    """S5：赛道采集汇总（真实命令，只读冻结产物）。"""
    out = run([sys.executable, "-m", "tools.landscape_scan", "--summary"])
    show = ["$ python3 -m tools.landscape_scan --summary", ""] + out.splitlines()
    render(show, os.path.join(OUTDIR, "s5_landscape_density.png"), width=1000,
           title="四个月的同赛道论文密度（arXiv API 按日期系统采集）")
    CAPTIONS.append((
        "s5_landscape_density.png",
        "用 arXiv API 按日期倒序系统采集，四个月 146 篇候选、129 篇能抓到局限段，"
        "平均不到两天一篇。在这个密度下「我没搜到」的信息量约等于零。",
        "§11「四个月，146 篇候选」之后"))


def shot6_repo_overlap() -> None:
    """S6：20 个竞品仓库的代码重合比对（真实命令，只读冻结产物）。"""
    out = run([sys.executable, "-m", "tools.repo_overlap", "--summary"])
    show = ["$ python3 -m tools.repo_overlap --summary", ""] + out.splitlines()
    render(show, os.path.join(OUTDIR, "s6_repo_overlap.png"), width=1000,
           title="与 20 个竞品仓库的代码重合比对（逐行，非关键词）")
    CAPTIONS.append((
        "s6_repo_overlap.png",
        "从论文正文抽出竞品仓库地址后逐个下载逐行比对。重合最高的仓库也全是 Python 样板"
        "（`from __future__ import annotations` 一类），领域词汇与算法结构零重合。"
        "**这张图的意义在于它是我第一次说「代码零重合」时根本没有的**——那时比对范围只有一个仓库。",
        "§10 第五错，「20 个仓库逐个下载逐行比对」之后"))


def main() -> int:
    os.makedirs(OUTDIR, exist_ok=True)
    print("生成截图（内容全部来自真实命令输出）：")
    for fn in (shot1_check_catches_inflation, shot2_a4_blanket, shot3_cross_family_verdict,
               shot4_tautology_code, shot5_landscape, shot6_repo_overlap):
        try:
            fn()
        except Exception as e:                                    # noqa: BLE001
            print(f"  !! {fn.__name__} 失败: {type(e).__name__}: {e}")
    md = ["# 截图清单与图注\n",
          "所有图的内容均来自命令的真实 stdout；唯一例外是 s1，它是演示性破坏且跑完已还原。\n",
          "| 文件 | 图注 | 文中位置 |", "|---|---|---|"]
    for f, cap, pos in CAPTIONS:
        md.append(f"| `{f}` | {cap} | {pos} |")
    with open(os.path.join(OUTDIR, "CAPTIONS.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(md) + "\n")
    print(f"\n共 {len(CAPTIONS)} 张 -> article/shots/")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
