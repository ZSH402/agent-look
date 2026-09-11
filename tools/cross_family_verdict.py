"""跨家族审读的**离线**部分：材料、我方判据、逐条裁决、以及对象邻接检验。

本模块**不导入任何联网代码**，因此 `run_all` / `verify_claims` 可以安全引用它；
真正的 API 调用在 `tools/cross_family_review.py` 里。

裁决判据（第二轮的，比第一轮窄判据更宽也更对）
------------------------------------------------
第一轮 A1 我把「装置自证」定义为「无论该性质是否成立，测量都会给出这个结果」。
跨家族审读者给出的判据更宽：**只要结论能靠阅读实现构造推出、不需要执行即可得知，
就算设计后果**。按这个更宽的判据重判它的额外指控：5 条成立、2 条有争议、
3 条是它读了我材料里的接口事实后过度触发。**判据被拓宽这件事本身就是收获之一。**
"""
from __future__ import annotations

import json
import os
import re

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# ---------------------------------------------------------------------------
# 去标注的声明表：(ID, 声明, 它当初是怎么测出来的, 与测量有关的机械事实)
# 不含级别、不含任何结论词。第一轮 A1 因材料欠定被判无效（见 review_findings 第十一条）。
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

MY_LABEL = {
    "C2": "M", "C3": "M", "C4": "M", "C4b": "M", "C5": "M", "C6": "M", "C7": "M",
    "C8": "M", "C9": "G", "C10": "M", "C11": "M", "C12": "M", "C13": "M",
    "C14": "M", "C15": "M", "C16": "M", "C17": "M", "C18": "G", "C19": "G",
    "C20": "G", "C23": "M", "C24": "G", "C25": "M", "C26": "M", "C27": "M",
    "C28": "G", "C29": "M", "C30": "G", "C31": "M", "C32": "M", "C33": "M",
    "C34": "M",
}


# ---------------------------------------------------------------------------
# 对审读者额外指控的逐条裁决
#   accept    —— 按更宽判据成立，是我方原先判据过窄而漏掉的
#   disputed  —— 两种读法都站得住，保留争议不强行定论
#   reject    —— 它把我材料里的「接口事实」直接当成结论被保证，属过度触发
#   keep_mine —— 它判 MEASURED 而我判 GUARANTEED，我方保留原判（理由更弱，如实标注）
# ---------------------------------------------------------------------------
ADJUDICATION = {
    "C4": "accept",     # 实测值 10 == 代码常量 10，读代码即可得知
    "C4b": "accept",    # 同上，TTL 常量 100 / 实测 101
    "C12": "accept",    # P=10 与 B1=1 的差异由「是否走拉取周期」直接决定
    "C13": "accept",    # 护栏失效由它在判定路径之外这一位置直接决定
    "C16": "accept",    # 四级是研究者自定义的算子序列，属方法定义
    "C6": "disputed",   # 我方认为半径是实测的；它认为指标口径本身即结论
    "C8": "disputed",   # 同上，接口无文本参数 vs 判定路径确实不读文本
    "C2": "reject",     # 「入参只有一个令牌」不蕴含「该令牌范围包含全链约束」
    "C3": "reject",     # 「撤销检查在判定流程内」不蕴含「旧凭证必被拒」
    "C5": "reject",     # 密码学方案蕴含伪造必被拒，但实现接线正确性是实测的
    "C24": "keep_mine", # 它判 MEASURED；我方仍判 GUARANTEED（E12 复用 E11 阶梯同一实现）
}

CRITERION = ("判据：结论能否靠阅读实现构造推出、不需执行即可得知。"
             "能则是设计后果，不能则是实测。")

ART = os.path.join(HERE, "results", "cross_family_review.json")
BENCH = os.path.join(HERE, "data", "agentdojo_bench.json")
E32 = os.path.join(HERE, "results", "E32_real_deriver.json")


def _key(x):
    m = re.match(r"C(\d+)(b?)", x)
    return (int(m.group(1)), m.group(2)) if m else (999, x)


def _expand(x):
    """把我的 M/G 标签映射成与模型输出同名词。第一轮忘了这一步导致比对恒不相等。"""
    return {"M": "MEASURED", "G": "GUARANTEED"}.get(x, x)


def parse_a1(reply):
    got = {}
    for line in reply.splitlines():
        line = line.strip().strip("`")
        m = re.match(r"^\**\s*(C\d+b?)\s*\**\s*[|｜]\s*\**\s*"
                     r"(MEASURED|GUARANTEED|UNCLEAR)", line, re.I)
        if m:
            got[m.group(1)] = m.group(2).upper()
    return got


def a1_analysis(reply):
    got = parse_a1(reply)
    dis = {k: {"mine": _expand(MY_LABEL[k]), "theirs": v}
           for k, v in got.items() if _expand(MY_LABEL.get(k)) != v}
    mine_g = {k for k, v in MY_LABEL.items() if v == "G"}
    theirs_g = {k for k, v in got.items() if v == "GUARANTEED"}
    extra = sorted(theirs_g - mine_g, key=_key)
    return {
        "parsed": len(got), "of": len(CLAIMS),
        "agree": len(got) - len(dis), "disagree": dis,
        "theirs_guaranteed": sorted(theirs_g, key=_key),
        "mine_guaranteed": sorted(mine_g, key=_key),
        "confirmed_of_mine": sorted(mine_g & theirs_g, key=_key),
        "missed_of_mine": sorted(mine_g - theirs_g, key=_key),
        "extra_flags": extra,
        "adjudication": {k: ADJUDICATION.get(k, "unadjudicated") for k in extra},
    }


def object_adjacency():
    """检验 E32 里「多授工具与所需工具同属一个环境对象」——对象取自基准的 Depends。

    同时用来判决 A2 提出的替代解释（「模型偏好高权限工具」）：
    若该解释成立，多授的应当全是高敏感工具；实测 4 个多授里有 2 个是极低权限的只读查询。
    """
    with open(BENCH, encoding="utf-8") as f:
        tools = json.load(f)["tools"]
    with open(E32, encoding="utf-8") as f:
        d = json.load(f)

    def obj(n):
        return tools.get(n, {}).get("depends_on")

    rows = []
    for su, v in d["suites"].items():
        for r in v["rows"]:
            if r["status"] != "ok" or not r["over_union"]:
                continue
            nobj = {obj(x) for x in r["needed"]}
            for o in r["over_union"]:
                rows.append({"task": f"{su}/{r['task']}", "tool": o, "object": obj(o),
                             "needed_objects": sorted(x for x in nobj if x),
                             "same_object": obj(o) in nobj,
                             "in_harm_list": o in r["over_harm"]})
    return {"rows": rows, "n": len(rows),
            "n_same_object": sum(1 for r in rows if r["same_object"]),
            "all_same_object": bool(rows) and all(r["same_object"] for r in rows),
            "n_in_harm_list": sum(1 for r in rows if r["in_harm_list"])}


def summarize():
    """把冻结产物与离线裁决汇总成可直接进报告的结构。"""
    with open(ART, encoding="utf-8") as f:
        art = json.load(f)
    # 产物里的 calls_used/tokens_used **每次运行都会重置**，单独看会低报。
    # 这里把历史轮次一并累计，给出真实总数。
    n_calls = sum(len(v.get("arms", {})) for v in art.get("prev_runs", [])) \
        + len(art.get("arms", {}))
    n_tokens = sum(a.get("usage", {}).get("total_tokens", 0)
                   for v in art.get("prev_runs", [])
                   for a in v.get("arms", {}).values()) \
        + sum(a.get("usage", {}).get("total_tokens", 0)
              for a in art.get("arms", {}).values())
    out = {"model": art["model"],
           "calls_used": art.get("calls_used"), "tokens_used": art.get("tokens_used"),
           "total_calls": n_calls, "total_tokens": n_tokens,
           "elapsed_s": art.get("elapsed_s"),
           "arms": {k: v["name"] for k, v in art.get("arms", {}).items()},
           "prev_runs": len(art.get("prev_runs", []))}
    if "A1" in art.get("arms", {}):
        out["A1"] = a1_analysis(art["arms"]["A1"]["reply"])
    out["object_adjacency"] = object_adjacency()
    out["replies"] = {k: art["arms"][k]["reply"] for k in art.get("arms", {})}
    return out


if __name__ == "__main__":
    s = summarize()
    a = s["A1"]
    print(f"模型 {s['model']}，累计 {s['total_calls']} 次调用 / {s['total_tokens']} tokens"
          f"（其中 {s['prev_runs']} 轮为被判无效或早期轮次）")
    print(f"A1 解析 {a['parsed']}/{a['of']}，一致 {a['agree']}，分歧 {len(a['disagree'])}")
    print(f"我方判 GUARANTEED {len(a['mine_guaranteed'])} 条，"
          f"审读者判 {len(a['theirs_guaranteed'])} 条")
    print(f"  被独立确认 {len(a['confirmed_of_mine'])}/{len(a['mine_guaranteed'])}: "
          f"{a['confirmed_of_mine']}")
    print(f"  未被确认: {a['missed_of_mine']}")
    print(f"审读者额外指控 {len(a['extra_flags'])} 条，逐条裁决：")
    for k, v in a["adjudication"].items():
        print(f"    {k}: {v}")
    oa = s["object_adjacency"]
    print(f"对象邻接检验：{oa['n_same_object']}/{oa['n']} 个多授工具与所需工具同对象"
          f"（其中 {oa['n_in_harm_list']} 个在危害清单内）")
