"""规则 4 差分测试：§5 凭证刷新语义。

我从规格文本读出的行为：
  (§5 L360-363) 验证方按令牌**链根**解析授权，不得总是用"当前授权"；
  (§5 L366) 语义1：未刷新的一方的旧根令牌仍有效（回滚防护以验证方已见的最高 epoch 为准）；
  (§5 L367) 语义2：已刷新到新 epoch 的一方，旧根令牌报 STALE_CREDENTIAL；
  (§5 L369) 语义3：刷新必须同时更新本级持有的根令牌，否则新旧混用仍会派生失败。
"""
import sys
sys.path.insert(0, "/root/ai监督")
from src.runtime import System

SCOPE = ["x.read@a/**"]
PASS = []


def mk(pull=1):
    s = System(mode="P", ttl=1000, pull_interval=pull)
    s.add_agent("A", "root", list(SCOPE))
    s.add_agent("B", "peer", list(SCOPE))
    return s


def reissue(s):
    """权威常规重签发：cred_epoch 递增，链根 id 随之改变。"""
    return s.authority.issue_grant("A", list(SCOPE), s.now)


def note(label, got, expect):
    verdict = "一致" if got == expect else ("规格未定" if expect is None else "不一致")
    PASS.append((label, expect, got, verdict))
    print(f"{label:46} spec_expect={str(expect):18} ref={got:18} {verdict}")


# ---------- 基线 ----------
s = mk(); t = s.delegate("A", "B", list(SCOPE), "t1")
note("R0 基线（未重签发）", s.request("A", "B", t.token_id, "x.read", "a/x", "t1").reason_code, "OK")

# ---------- 未刷新的验证方 ----------
s = mk(); t_old = s.delegate("A", "B", list(SCOPE), "t1")
g2 = reissue(s)
t_new = s.delegate("A", "B", list(SCOPE), "t1")          # A 用（未刷新的）本级根令牌新派生
note("R1a 未刷新 B + 重签发前的旧根令牌", s.request("A", "B", t_old.token_id, "x.read", "a/x", "t1").reason_code, "OK")
note("R1b 未刷新 B + 重签发后 A 派生的令牌", s.request("A", "B", t_new.token_id, "x.read", "a/x", "t1").reason_code, None)

# ---------- 已刷新的验证方 ----------
s = mk(); t_old = s.delegate("A", "B", list(SCOPE), "t1")
g2 = reissue(s)
s.peps["B"].refresh_grant(g2)                            # 仅 B 刷新到新 epoch
try:
    t_mixed = s.delegate("A", "B", list(SCOPE), "t1")
    mixed = s.request("A", "B", t_mixed.token_id, "x.read", "a/x", "t1").reason_code
except Exception as e:
    mixed = f"EXC {type(e).__name__}:{e}"
note("R2b 只刷新 B、A 未刷新时派生新令牌", mixed, None)
s.peps["A"].refresh_grant(s.authority.grants["A"])       # 现在 A 也刷新
t_new = s.delegate("A", "B", list(SCOPE), "t1")
note("R2c 已刷新 B + 新根令牌", s.request("A", "B", t_new.token_id, "x.read", "a/x", "t1").reason_code, "OK")
note("R2d 刷新后旧根令牌仍报 STALE（规格语义2）",
     s.request("A", "B", t_old.token_id, "x.read", "a/x", "t1").reason_code, "STALE_CREDENTIAL")

# ---------- 签发方本级根令牌未更新 ----------
s = mk(); g2 = reissue(s)
t_after = s.delegate("A", "B", list(SCOPE), "t1")        # A 未刷新本级根令牌
note("R3a A 未刷新本级根令牌时派生", s.request("A", "B", t_after.token_id, "x.read", "a/x", "t1").reason_code, None)
s.peps["A"].refresh_grant(s.authority.grants["A"])       # 刷新 A 本级
try:
    t2 = s.delegate("A", "B", list(SCOPE), "t1")
    note("R3c A 刷新本级后派生的令牌", s.request("A", "B", t2.token_id, "x.read", "a/x", "t1").reason_code, None)
except Exception as e:
    note("R3c A 刷新本级后派生", f"EXC {type(e).__name__}:{e}", None)

# ---------- 回滚：不能刷回旧 epoch ----------
s = mk(); g1 = s.authority.grants["A"]
g2 = reissue(s)
ok_new = s.peps["B"].refresh_grant(g2)
ok_old = s.peps["B"].refresh_grant(g1)
note("R4 刷新到新 epoch 后再刷回旧 epoch（P2 回滚抵抗）", f"new={ok_new},old={ok_old}", "new=True,old=False")

print()
print("SUMMARY:", sum(1 for _, e, g, v in PASS if v == "不一致"), "不一致 /",
      sum(1 for _, e, g, v in PASS if v == "规格未定"), "规格未定 /", len(PASS))
