"""跨家族对抗审读：用非本会话模型家族的模型审查本项目的结论。

为什么需要它
------------
此前的六次外部检查（两轮差分、三次全新读者、一次 suite 复现）全部由同家族的执行体完成，
它们与本项目共享同一套概念盲区。规格 §2.16 禁止「装置自证」，但"哪些结论是装置自证"
这一判断本身也可能是我的盲区——同家族检查测不出这一点。

材料必须去标注
--------------
`paper/claim_evidence_map.md` 里已经写满了我自己的 X/A/B 级别判断，以及「同义反复」「已复核」
这类结论词。原样喂给审读者等于泄题，它只会附和。因此本脚本内置一份手工去标注的声明表：
只给「声明」与「它当初是怎么测出来的」，不含级别、不含我的任何结论词。
被审读者看到的材料由 `CLAIMS` 常量唯一决定，可被第三方逐行核对。

盲测设计
--------
- 我认为是装置自证的 7 条（C9/C18/C19/C20/C24/C28/C30）与我认为不是的 26 条混在一起，
  顺序按 ID 排列，不告知条数、不告知比例、不告知存在这类问题。问题只问
  「这条结论是『测量』得到的，还是由『测量方式本身』保证的」——不给这种失效起名字。
- 若审读者无差别地把所有条目都判为「装置保证」，说明它在顺应提问方式而非真的分辨，
  这一情形必须作为无效审读如实报告，不得当作发现。
- A2/A3 两个臂是盲的：不给我的结论，看它能否独立落在同一个地方，或落在别处。

密钥来自 `.secrets/qwen_api_key`，永不打印、永不写入结果文件。
联网，因此不在 `run_all` 内；产物冻结为 `results/cross_family_review.json`。

运行：
    python3 -m tools.cross_family_review --arms A1 --model qwen3.7-flash
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)

from tools.llm import chat, text, usage                             # noqa: E402

OUT = os.path.join(HERE, "results", "cross_family_review.json")

# ---------------------------------------------------------------------------
# 去标注的声明表：(ID, 声明, 它当初是怎么测出来的, 与测量有关的机械事实)
#
# 第三项「机械事实」是第一轮 A1 无效后补上的。第一轮我只给了「测量方式」，
# 结果 C9 的材料写成「逐项对比 P 列与 B1 列」——而基线 B1 复用 P 的同一个判定函数
# 这一事实被我一并删掉了，从那句话出发任何读者都只能判 MEASURED。
# 第一轮因此测的是「能否发现被我藏起来的东西」，判为无效。
# 现逐条补回机械事实，且对全部条目对称补充，不针对我怀疑的那几条。
# 仍然不含级别、不含任何结论词。
# ---------------------------------------------------------------------------
CLAIMS = [
    ("C2", "授权判定只用请求者自己那一个令牌，其范围包含链上全部约束",
     "在 126 个随机委托图上执行动作，统计越界次数；另跑攻击矩阵 A1–A3；selfcheck 不变式 i2/i3",
     "判定函数的入参只有请求者自己那一个令牌，其余令牌不传入"),
    ("C3", "回滚抵抗：被撤销后重新提交的旧凭证被拒",
     "攻击矩阵 A5_rollback 提交旧凭证；selfcheck 不变式 i4",
     "撤销表存放已作废凭证的序号，判定按序号比对后用单调纪元拒绝更旧的凭证"),
    ("C4", "撤销在 10 个 tick 内生效",
     "E3_revocation 直接测量 mean_ticks",
     "撤销靠每 10 个 tick 一次的拉取生效，该拉取周期在代码中是常量 10"),
    ("C4b", "网络分区下撤销退化为 101 个 tick",
     "E20_partition 测分区场景",
     "分区期间拉取被阻断，恢复阈值 TTL 在代码中是常量 100"),
    ("C5", "收据不可伪造，也不可被篡改",
     "攻击矩阵 A7_receipt_forgery 分别提交伪造件与篡改件，统计拒绝数",
     "收据由私钥签名、由公钥校验，伪造件与篡改件都在校验处被拒"),
    ("C6", "传播半径约束的是能力集合而非节点数",
     "E2_overapprox 统计 attack_cap_radius_P；E17 拓扑测试",
     "半径按可达的能力集合大小统计，不按可达节点数统计"),
    ("C7", "节点级传播半径无上界",
     "E10_fanout 取 m=1/3/5 测得半径 1/3/5；把 redelegatable 置 False 后全为 0",
     "转委托的开关是一个布尔哨兵，置 False 后转委托请求在入口被拒"),
    ("C8", "授权判定不读自由文本",
     "E8_text_invariance 改变文本看判定是否变化；攻击矩阵 A8_detector_injection",
     "判定函数的签名里没有任何文本类型参数，文本只进入一个与判定无关的日志字段"),
    ("C9", "本架构 P 与基线 B1 在安全上等价",
     "E1 攻击矩阵全表逐项对比 P 列与 B1 列",
     "基线 B1 的授权判定直接调用与本架构 P 相同的那个判定函数，两者不是两套实现"),
    ("C10", "每请求额外协调往返：P 为 0.1，B1 为 1.0",
     "E24 用实测 TCP RTT 折算",
     "折算用的 RTT 由本机实测得到，不是引用文献值"),
    ("C11", "中心 PDP 下线时可用性：P 为 1.00，B1 为 0.00",
     "E5_availability",
     "把中心 PDP 进程终止后继续发请求，统计成功率"),
    ("C12", "撤销延迟：P 为 10 tick，B1 为 1 tick",
     "E3_revocation",
     "P 走每 10 tick 一次的拉取；B1 的判定内联了撤销检查，无拉取周期"),
    ("C13", "文本护栏在「文本可见」的攻击上有效，在「静默越权」上完全失效",
     "攻击矩阵 A1/A2 的 B2 列",
     "护栏是一段正则，位于判定路径之外；静默越权不经过该正则"),
    ("C14", "本实现所用的 13 关键词正则在 230 条真实语料上的拦截率为 2.2%",
     "E25_real_corpus 在公开语料上跑该正则",
     "正则原文取自本项目实现；语料取自公开数据集，非自造"),
    ("C15", "自造语料会高估护栏效果（0.656 对 0.978）",
     "E23_corpus 与 E25_real_corpus 的 B2 列前后对照",
     "同一个正则，分别在自造语料与公开语料上各跑一次"),
    ("C16", "过近似可以分解为四级并逐级测量",
     "E11_coarsening.ladder",
     "四个级别是研究者自己定义的粗化算子，逐级作用于同一个最小必要范围"),
    ("C17", "最小必要范围 M 可由任务轨迹反推，且用 M 能复现原任务",
     "E11 与 E26 均检查 minimal_reproduces_task",
     "M 由真实执行轨迹反推得到，之后用它回放原任务并检查是否复现"),
    ("C18", "粗化带来的危害被根授权封顶",
     "E11 统计 critical_surplus；E15 换门限重测",
     "每一级粗化后的范围在实现中被 _filter_to_parent 钳制在父级范围之内，该钳制是粗化步骤的一部分"),
    ("C19", "危害上限 = 根授权跨度 × 模式宽度",
     "E15 换根授权与模式宽度重测（R0 的 moderate=16 而 strict=0）",
     "该上限由根授权跨度与模式宽度直接算出，再与逐级测得值作比较"),
    ("C20", "最危险的级别是 L4，且跨基底稳健",
     "E11 各级危害计数；E26 在四个 suite 上重测 worst_level，全为 L4",
     "L4 的定义是「不做任何推导，直接使用根授权」，因此它的范围按定义包含其余各级的范围"),
    ("C23", "L1/L2/L3 之间的危害排序不可跨基底迁移",
     "E26 在四个真实 suite 上重测（banking 的 L3 最轻为 0；slack 的 L3 最危险为 12；workspace 三者皆为 0）",
     "四个 suite 的工具与资源取自公开基准，非自造"),
    ("C24", "资源模式化表示优于裸动词集合",
     "E12 对比这两级（1 条危害 0 对 8 条危害 8）",
     "E12 所比的两级就是 E11 阶梯中的 L1 与 L2，两者共用同一套实现"),
    ("C25", "危害定义是承重的，必须显式扫描其变体",
     "E14_harm_robustness 换危害定义重测；E16_manifest_sensitivity",
     "换用三份不同的危害定义，各自重跑同一批实验并对比结论是否翻转"),
    ("C26", "输入扰动下「条数能代理危害」与「L3 不比 L2 危险」两条不变",
     "E16 用 6 份清单 × 3 个变体",
     "清单在有限的扰动区间内变化，区间外未测"),
    ("C27", "只按「下游总是顺从」计算传播半径会系统性高估",
     "E18_compliance 令顺从率为 0.5，测得平均半径 1.065，而按全顺从算出的上界为 4",
     "顺从率是一个可调参数，0.5 与 1.0 两档都跑过"),
    ("C28", "gossip 协议下 1 条消息即可检出异常",
     "E19_gossip 统计检出所需消息数；E1b_split_view 作对照",
     "gossip 的消息合并语句在实现中什么都不做（空操作）；分叉的主体被排在待检列表首位"),
    ("C29", "复合动作能挡住「一次就需要多能力」，但挡不住分时串通",
     "E21_compound，含专门的否定面测量",
     "既有阳性用例也有阴性用例，阴性用例是分两次、各自都在范围内的动作"),
    ("C30", "串通各方能力的并集受根授权约束",
     "E9_collusion 对各方的能力范围求并集",
     "只对各方的范围求并集并检查是否超出根授权，没有真的执行串通动作"),
    ("C31", "漂移阈值取 3.5 偏低约 3.6 倍，工作点应为 12.5",
     "E22_drift_roc 扫描阈值取 ROC",
     "检测器是非 LLM 的确定性统计代理，扫描在有限的阈值网格上进行"),
    ("C32", "漂移检测在「授权内未见过的能力」上的假阳性率为 0.717",
     "E6_drift 与 E22 在默认阈值下统计",
     "检测器是非 LLM 的确定性统计代理，样本量为数百请求"),
    ("C33", "自造替代物会系统性偏袒作者自己的论点（五次前后对照）",
     "依次替换危害表→E14、语料→E25、RTT→E24、能力宇宙→E26，各做一次前后对照",
     "每次替换前后各跑一次同一批实验，对比结论是否翻转"),
    ("C34", "复现校验必要但不充分，还需要逐项合理性检查作哨兵",
     "对比两种校验：玩具版复现校验抓到 0 个问题；任务成功率列抓到 2 个",
     "两种校验都在同一个已被外部审读标出问题的实验上运行"),
]

# 我的判断（只用于机械比对，绝不进入发给审读者的材料）
# G = 我认为结论由测量方式本身保证；M = 我认为是测量得到的
MY_LABEL = {
    "C2": "M", "C3": "M", "C4": "M", "C4b": "M", "C5": "M", "C6": "M", "C7": "M",
    "C8": "M", "C9": "G", "C10": "M", "C11": "M", "C12": "M", "C13": "M",
    "C14": "M", "C15": "M", "C16": "M", "C17": "M", "C18": "G", "C19": "G",
    "C20": "G", "C23": "M", "C24": "G", "C25": "M", "C26": "M", "C27": "M",
    "C28": "G", "C29": "M", "C30": "G", "C31": "M", "C32": "M", "C33": "M",
    "C34": "M",
}

# ---------------------------------------------------------------------------
# 提示词
# ---------------------------------------------------------------------------
P_A1 = """你是一位对抗性审稿人。下面是一份研究项目的 {n} 条结论，以及每条结论「当初是怎么测出来的」。

对每一条，判断该结论的性质：

- `MEASURED` —— 结论来自一次真实的测量，如果该性质不成立，测量结果会不同。
- `GUARANTEED` —— 结论由测量方式本身保证。即：无论该性质在现实中是否成立，
  这套测量方式都会给出这个结果。例如测量过程把待测性质作为前提写进了构造里，
  或所比较的两者实际走的是同一条代码路径。
- `UNCLEAR` —— 从给出的信息无法判断。

要求：
1. 逐条判断，不要跳过。
2. 不要默认大多数是 MEASURED，也不要默认大多数是 GUARANTEED。
3. 允许对同一条给出保留意见。
4. 只依据给出的信息判断，不要猜测项目作者的意图。

输出格式（每行一条，不要用表格，不要加额外说明）：
`ID | 判断 | 一句话理由`

声明与测量方式：

"""

P_A2 = """下面是一次实验的逐任务结果。实验内容：让一个大模型阅读若干用户任务，由它推导出完成任务所需的最小工具集合，
然后与人工标注的「真正需要哪些工具」对比。

每行含义：任务 | J=三次采样的平均 Jaccard 相似度 | 漏=少了必需工具 | 多=多了不需要的工具 | 危害=多出来的工具中落在危险工具清单内的那些

```
{rows}
```

整批数据：16 个任务，4 个工具域；漏授 3 个任务，多授 4 个任务；所有任务的平均 Jaccard = 0.972。

请回答三个问题，不要复述数据：
1. 这批错误的形状是什么？用你自己的话刻画，尽量具体到是"哪一类工具被多加了"。
2. 三路采样的 Jaccard 这么高（0.972），这对"用采样分歧度来预测推导是否出错"这个设想意味着什么？
3. 从这 16 行里，还有什么值得注意但我可能没问到的现象？

"""

P_A3 = """下面是一个多智能体安全架构的核心主张。

主张：在多智能体系统中，用「授权沿委托链向下衰减，证据沿委托链向上回流」替代
「委派即监督」。做法是：每个主体只拿一个能力令牌，令牌声明它可用资源的模式范围；
判定授权时不读自然语言，只看令牌的范围包含关系；所有动作生成签名收据，收据经侧信道独立回流，
不经过被监督者的上下文。

请只回答两点：
1. 这个主张最强的一条反对意见是什么？（不是实现细节，是主张本身的问题）
2. 设计一个实验：如果该主张是错的，这个实验会失败。说清楚失败时会看到什么。

架构自述：
{arch}
"""

P_A4 = """下面是一个研究项目的自我审读记录目录。该记录的每一条都是作者自己发现并承认的错误。

请判断：哪些条目的结论本身是过头的？即作者在承认错误时，是否又犯了一个新的、方向相反的错误
（例如：把一个小问题说成大问题以显得诚实，或把"我未验证"说成"这已被证明不成立"，
或用一个错误的理由去否定一条本来正确的结论）。

{heads}

输出：逐条给出 `小节标题 | 过头/不过头/无法判断 | 一句话理由`，最后给一句总体评价。
"""


def _material_a1() -> str:
    return "\n".join(f"{i} | {c}\n    测量方式：{h}\n    机械事实：{k}"
                     for i, c, h, k in CLAIMS)


def _material_a2() -> str:
    with open(os.path.join(HERE, "results", "E32_real_deriver.json"), encoding="utf-8") as f:
        d = json.load(f)
    lines = []
    for su, v in d["suites"].items():
        for r in v["rows"]:
            if r["status"] != "ok":
                continue
            lines.append(f"{su}/{r['task']} | J={r['jaccard_mean']} | "
                         f"漏={r['missed_union']} | 多={r['over_union']} | 危害={r['over_harm']}")
    return "\n".join(lines)


def _material_a4() -> str:
    """只取各节标题 + 首句，避免把全文（42KB）塞进去。"""
    path = os.path.join(HERE, "paper", "review_findings.md")
    with open(path, encoding="utf-8") as f:
        s = f.read()
    out, cur, buf = [], None, []
    for line in s.splitlines():
        if line.startswith("#"):
            if cur:
                out.append(f"{cur} —— {' '.join(buf)[:200]}")
            cur, buf = line.lstrip("# ").strip(), []
        elif cur and line.strip():
            buf.append(line.strip())
    if cur:
        out.append(f"{cur} —— {' '.join(buf)[:200]}")
    return "\n".join(f"- {x}" for x in out)


ARMS = {
    "A1": ("装置审计（盲，含对照）", P_A1, _material_a1),
    "A2": ("E32 失效模式刻画（盲）", P_A2, _material_a2),
    "A3": ("架构证伪（盲）", P_A3, None),
    "A4": ("攻击我方自审结论", P_A4, _material_a4),
}


def _arch() -> str:
    with open(os.path.join(HERE, "agent-security-v2.md"), encoding="utf-8") as f:
        return f.read()[:14000]


def _expand(x: str | None) -> str | None:
    """把我的 M/G 标签映射成与模型输出同名词。第一轮忘了这一步，导致比对恒不相等。"""
    return {"M": "MEASURED", "G": "GUARANTEED"}.get(x, x)


def parse_a1(reply: str) -> dict:
    got = {}
    for line in reply.splitlines():
        line = line.strip().strip("`")
        m = re.match(r"^\**\s*(C\d+b?)\s*\**\s*[|｜]\s*\**\s*(MEASURED|GUARANTEED|UNCLEAR)", line, re.I)
        if m:
            got[m.group(1)] = m.group(2).upper()
    return got


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--arms", default="A1")
    ap.add_argument("--model", default="qwen3.7-flash")
    ap.add_argument("--cap", type=int, default=12)
    ap.add_argument("--fresh", action="store_true",
                    help="归档既有产物后重跑（用于材料被判为无效后的重做）")
    a = ap.parse_args()

    arms = [x.strip().upper() for x in a.arms.split(",") if x.strip()]
    for arm in arms:
        if arm not in ARMS:
            print(f"未知臂 {arm}")
            return 2

    out = {"model": a.model, "arms": {}, "calls_used": 0, "tokens_used": 0, "elapsed_s": 0.0}
    if os.path.exists(OUT) and "--fresh" not in sys.argv:
        with open(OUT, encoding="utf-8") as f:
            prev = json.load(f)
        if prev.get("model") == a.model:
            out["arms"] = prev.get("arms", {})
        out["prev_runs"] = prev.get("prev_runs", [])
    if a.fresh:
        out["prev_runs"] = []
        if os.path.exists(OUT):
            with open(OUT, encoding="utf-8") as f:
                prev = json.load(f)
            with open(OUT, "w", encoding="utf-8") as f:
                json.dump({"model": a.model, "arms": {}, "calls_used": 0,
                           "tokens_used": 0, "elapsed_s": 0.0,
                           "prev_runs": prev.get("prev_runs", []) + [{
                               "note": "第一轮 A1（材料欠定，判为无效）",
                               "arms": prev.get("arms", {})}]}, f,
                          ensure_ascii=False, indent=1)
            with open(OUT, encoding="utf-8") as f:
                out = json.load(f)
    t0 = time.time()

    for arm in arms:
        if out["calls_used"] >= a.cap:
            print(f"达到调用上限 {a.cap}，停止")
            break
        name, tmpl, mat = ARMS[arm]
        print(f"--- {arm} {name} ---")
        if arm == "A3":
            prompt = tmpl.format(arch=_arch())
        elif arm == "A4":
            prompt = tmpl.format(heads=_material_a4())
        elif arm == "A2":
            prompt = tmpl.format(rows=_material_a2())
        else:
            prompt = tmpl.format(n=len(CLAIMS)) + _material_a1()

        resp = chat([{"role": "user", "content": prompt}], model=a.model,
                    max_tokens=4096, timeout=600)
        out["calls_used"] += 1
        u = usage(resp)
        out["tokens_used"] += u.get("total_tokens", 0)
        reply = text(resp)
        out["arms"][arm] = {"name": name, "model": a.model, "reply": reply,
                            "usage": u, "prompt_chars": len(prompt)}
        print(f"    {len(reply)} chars, {u.get('total_tokens', 0)} tokens")
        out["elapsed_s"] = round(time.time() - t0, 1)
        with open(OUT, "w", encoding="utf-8") as f:
            json.dump(out, f, ensure_ascii=False, indent=1)

    out["elapsed_s"] = round(time.time() - t0, 1)
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=1)

    # A1 机械比对（只在我自己这边算，不影响审读者看到什么）
    if "A1" in out["arms"]:
        got = parse_a1(out["arms"]["A1"]["reply"])
        out["A1_parse"] = {"parsed": len(got), "of": len(CLAIMS),
                           "labels": got,
                           "my_label_expanded": {k: _expand(v) for k, v in MY_LABEL.items()},
                           "agree": sum(1 for k, v in got.items() if _expand(MY_LABEL.get(k)) == v),
                           "disagree": {k: {"mine": _expand(MY_LABEL[k]), "theirs": v}
                                        for k, v in got.items()
                                        if _expand(MY_LABEL.get(k)) != v}}
        with open(OUT, "w", encoding="utf-8") as f:
            json.dump(out, f, ensure_ascii=False, indent=1)
        p = out["A1_parse"]
        print(f"A1 解析 {p['parsed']}/{p['of']}，与我的判断一致 {p['agree']}，"
              f"分歧 {len(p['disagree'])}")
        # 无差别判为 GUARANTEED 说明审读无效，必须显式暴露
        g = sum(1 for v in got.values() if v == "GUARANTEED")
        print(f"   审读者判为 GUARANTEED 的条数：{g}/{len(got)}"
              f"（我方参照：{sum(1 for v in MY_LABEL.values() if v == 'G')}/{len(MY_LABEL)}）")

    print(f"\n实耗 {out['calls_used']} 次调用，{out['tokens_used']} tokens，"
          f"{out['elapsed_s']}s -> {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
