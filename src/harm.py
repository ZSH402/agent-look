"""危害模型：从"手写标签"改为"声明的系统事实 + 显式变体扫描"。

原实现的问题（两层）：
  1. `HARMFUL` 是一张手定能力集合，没有外部依据；
  2. 它按**能力**分类，而本项目的授权模型是**（能力 × 资源）**——同一个读能力作用在
     订单路径与凭据路径上，危害完全不同。per-capability 标签与模型自相矛盾。

本模块：
  - 危害的**输入**来自环境自身的描述——工具清单（effect class / 可逆性）与数据目录
    （资源命名空间敏感级别）。这是**声明的事实**，真实部署里由系统提供。
  - 危害的**聚合规则**是研究者的判断，因此不作为隐含前提，而被显式扫描
    （strict / moderate / lenient）。
  - 输入本身仍是声明的，因此 `HarmModel` 可被替换：`experiments` 用它对
    工具清单与数据目录做**有界扰动**，把"声明依赖"变成可测区间。
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .patterns import matches, split_grant

# --- 声明的系统事实 1：工具清单 -----------------------------------------
# effect: 效果的 CIA 归类；reversibility: 是否可撤销。
# 真实部署中来自工具 schema / MCP manifest，此处按其语义声明。
TOOL_EFFECTS: dict[str, tuple[str, str]] = {
    "order.read":        ("READ", "REVERSIBLE"),
    "order.update":      ("WRITE", "REVERSIBLE"),
    "food.prepare":      ("WRITE", "IRREVERSIBLE"),     # 消耗物料
    "kitchen.execute":   ("WRITE", "IRREVERSIBLE"),
    "kitchen.manage":    ("WRITE", "REVERSIBLE"),
    "service.execute":   ("WRITE", "IRREVERSIBLE"),     # 出餐，不可撤回
    "inventory.read":    ("READ", "REVERSIBLE"),
    "inventory.update":  ("WRITE", "REVERSIBLE"),
    "payment.read":      ("READ", "REVERSIBLE"),
    "payment.refund":    ("WRITE", "IRREVERSIBLE"),     # 资金出账
    "db.read":           ("READ", "REVERSIBLE"),
    "db.export":         ("EXPORT", "IRREVERSIBLE"),
    "db.admin":          ("ADMIN", "IRREVERSIBLE"),
    "credential.read":   ("READ", "REVERSIBLE"),
    "credential.export": ("EXPORT", "IRREVERSIBLE"),
    "shell.execute":     ("EXEC", "IRREVERSIBLE"),
    "net.external":      ("EXPORT", "IRREVERSIBLE"),
    "agent.delegate":    ("DELEGATE", "REVERSIBLE"),
}

# 有争议的能力：其效果类别存在多个可辩护读法。用于有界扰动。
# (最低危害读法, 最高危害读法)
CONTESTED_EFFECTS: dict[str, tuple[str, str]] = {
    "kitchen.execute":  ("WRITE", "EXEC"),      # 领域动作 vs 任意执行
    "service.execute":  ("WRITE", "EXEC"),
    "kitchen.manage":   ("WRITE", "ADMIN"),     # 管理 vs 写
    "agent.delegate":   ("DELEGATE", "ADMIN"),
}

# 危害严重度的偏序（用于扰动上下界与变体比较）
EFFECT_SEVERITY = {"READ": 0, "DELEGATE": 1, "WRITE": 2, "EXEC": 3, "ADMIN": 3,
                   "EXPORT": 3, "UNKNOWN": 3}

BOUNDARY_EFFECTS = frozenset({"EXPORT", "EXEC", "ADMIN"})
MUTATING_EFFECTS = frozenset({"WRITE", "EXPORT", "EXEC", "ADMIN", "DELEGATE"})

# --- 声明的系统事实 2：数据目录 -----------------------------------------
SENSITIVITY_LEVEL = {"PUBLIC": 0, "INTERNAL": 1, "PERSONAL": 2, "SECRET": 3}
RESOURCE_CLASSES: dict[str, list[str]] = {
    "PUBLIC":   ["public/menu", "public/hours"],
    "INTERNAL": ["orders/2024-001", "service/2024-001", "inventory/widgets",
                 "kitchen/line1"],
    "PERSONAL": ["customers/c-1", "payments/p-1"],
    "SECRET":   ["db/credentials", "cred/keys"],
}
# 未匹配任何已知命名空间时的缺省分级。这一条是真正有争议的，因此也是扰动轴。
DEFAULT_SENSITIVITY = "INTERNAL"

VARIANTS: dict[str, str] = {
    "strict": "只算跨界效果（EXPORT/EXEC/ADMIN）",
    "moderate": "跨界，或（写类效果 on ≥INTERNAL），或（读 on ≥PERSONAL）",
    "lenient": "只算能把数据带出的效果（EXPORT/EXEC）",
}


@dataclass(frozen=True)
class HarmModel:
    """一份具体的危害判定模型。默认实例 = 本仓库声明的工具清单与数据目录。"""
    effects: dict = field(default_factory=lambda: dict(TOOL_EFFECTS))
    resource_classes: dict = field(default_factory=lambda: dict(RESOURCE_CLASSES))
    default_sensitivity: str = DEFAULT_SENSITIVITY
    boundary_effects: frozenset = BOUNDARY_EFFECTS
    mutating_effects: frozenset = MUTATING_EFFECTS

    # --- 分量 ---
    def reachable_sensitivity(self, pattern: str) -> tuple[str, int]:
        """模式可达的最高数据敏感级别。取各命名空间代表资源做匹配，取最大级别。"""
        best = self.default_sensitivity
        lvl = SENSITIVITY_LEVEL[best]
        for name, reps in self.resource_classes.items():
            if any(matches(pattern, r) for r in reps):
                if SENSITIVITY_LEVEL[name] > lvl:
                    best, lvl = name, SENSITIVITY_LEVEL[name]
        return best, lvl

    def profile(self, grant: str) -> dict:
        cap, pat = split_grant(grant)
        effect, rev = self.effects.get(cap, ("UNKNOWN", "IRREVERSIBLE"))
        sens_name, sens_lvl = self.reachable_sensitivity(pat)
        return {"grant": grant, "capability": cap, "pattern": pat,
                "effect": effect, "reversibility": rev,
                "max_sensitivity": sens_name, "max_sensitivity_level": sens_lvl,
                "crosses_boundary": effect in self.boundary_effects}

    # --- 聚合规则（研究者判断，因此作为变体穷举）---
    def is_harmful(self, grant: str, variant: str = "moderate") -> bool:
        p = self.profile(grant)
        eff, lvl = p["effect"], p["max_sensitivity_level"]
        if variant == "strict":
            return eff in self.boundary_effects
        if variant == "lenient":
            return eff in {"EXPORT", "EXEC"}
        if variant == "moderate":
            if eff in self.boundary_effects:
                return True
            if eff in self.mutating_effects and lvl >= SENSITIVITY_LEVEL["INTERNAL"]:
                return True
            return eff == "READ" and lvl >= SENSITIVITY_LEVEL["PERSONAL"]
        raise ValueError(variant)

    def classify(self, grant: str) -> dict:
        d = self.profile(grant)
        d["harmful"] = {v: self.is_harmful(grant, v) for v in VARIANTS}
        return d

    def describe(self) -> str:
        return (f"default_sensitivity={self.default_sensitivity}, "
                f"contested={sorted(set(self.effects.items()) ^ set(TOOL_EFFECTS.items()))}")


DEFAULT_MODEL = HarmModel()

# --- 便捷包装（默认模型）------------------------------------------------
def reachable_sensitivity(pattern: str):
    return DEFAULT_MODEL.reachable_sensitivity(pattern)


def harm_profile(grant: str) -> dict:
    return DEFAULT_MODEL.profile(grant)


def is_harmful(grant: str, variant: str = "moderate") -> bool:
    return DEFAULT_MODEL.is_harmful(grant, variant)


def classify(grant: str) -> dict:
    return DEFAULT_MODEL.classify(grant)


# --- 有界扰动：生成备选清单 ---------------------------------------------
def perturbed_models() -> dict[str, HarmModel]:
    """在**可辩护区间**内生成备选工具清单与数据目录。

    - 效果类别：仅扰动 `CONTESTED_EFFECTS` 中列出的能力，取最低/最高危害读法；
      无争议的能力（如 `order.read` 是 READ、`net.external` 是 EXPORT）不动。
    - 缺省数据分级：PUBLIC / INTERNAL / PERSONAL 三档（`SECRET` 不作缺省——
      缺省即最高密级在现实中不成立）。
    """
    out: dict[str, HarmModel] = {"base": DEFAULT_MODEL}
    for sens in ("PUBLIC", "INTERNAL", "PERSONAL"):
        for tag, pick in (("low", 0), ("high", 1)):
            if sens == DEFAULT_SENSITIVITY and tag == "low":
                continue                      # 与 base 重合
            eff = dict(TOOL_EFFECTS)
            for cap, (lo, hi) in CONTESTED_EFFECTS.items():
                eff[cap] = (lo if pick == 0 else hi, TOOL_EFFECTS[cap][1])
            out[f"{tag}_{sens.lower()}"] = HarmModel(
                effects=eff, resource_classes=dict(RESOURCE_CLASSES),
                default_sensitivity=sens)
    return out
