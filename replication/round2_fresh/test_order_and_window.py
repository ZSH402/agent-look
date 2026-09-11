"""规则 2/3 差分测试：§2.3 检查顺序、§3.2 时窗。

我从规格文本推出的判定序（§3.2 步骤 1..7 + §2.3 L62 的 4–6 优先级）：
  UNKNOWN_SIG -> REQUEST_UNSIGNED / BAD_NONCE -> REPLAY / 时窗 -> REPLAY
  -> 找不到令牌 TOKEN_INVALID -> 签发者绑定 TOKEN_INVALID -> cred_epoch STALE_CREDENTIAL
  -> verify：撤销 TOKEN_REVOKED > 过期 TOKEN_EXPIRED > 密钥作废 TOKEN_INVALID
  -> TASK_MISMATCH -> SCOPE_VIOLATION
"""
import sys, dataclasses
sys.path.insert(0, "/root/ai监督")
from src.runtime import System
import src.crypto as C

SCOPE = ["x.read@a/**", "x.write@a/**"]
R = []


def mk(ttl=1000, pull=1):
    s = System(mode="P", ttl=ttl, pull_interval=pull)
    s.add_agent("A", "root", list(SCOPE))
    s.add_agent("B", "peer", list(SCOPE))
    return s


def show(label, r, expect):
    got = r.reason_code
    print(f"{label:52} expect={expect:18} got={got:18} {'OK' if got == expect else '<<< DIFF'}")
    R.append((label, expect, got))


# ---- 状态构造 ----
def tok(s, ttl=1000, task="t1", scope=SCOPE):
    return s.delegate("A", "B", list(scope), task, ttl=ttl)


def do_revoke_token(s, tokid):
    s.authority.revoke_token(tokid, s.now)
    s.advance(s.pull_interval + 1)          # 让 PEP 拉到新 epoch


def do_revoke_key(s, sid, upto):
    s.authority.revoke_key_epochs(sid, upto, s.now)
    s.advance(s.pull_interval + 1)


# ---- A. 撤销 vs 过期 ----
s = mk(); t = tok(s, ttl=5)
do_revoke_token(s, t.token_id)
s.advance(10)                                # 现在两者都成立：已撤销 且 已过期
show("A1 已撤销+已过期", s.request("A", "B", t.token_id, "x.read", "a/x", "t1"), "TOKEN_REVOKED")

# 对照：只过期（未撤销）
s = mk(); t = tok(s, ttl=5); s.advance(10)
show("A2 只过期", s.request("A", "B", t.token_id, "x.read", "a/x", "t1"), "TOKEN_EXPIRED")

# 对照：只撤销（未过期）
s = mk(); t = tok(s, ttl=1000); do_revoke_token(s, t.token_id)
show("A3 只撤销", s.request("A", "B", t.token_id, "x.read", "a/x", "t1"), "TOKEN_REVOKED")

# ---- B. 过期 vs 密钥作废 ----
s = mk(); t = tok(s, ttl=5); do_revoke_key(s, "A", 1); s.advance(10)
show("B1 已过期+密钥作废", s.request("A", "B", t.token_id, "x.read", "a/x", "t1"), "TOKEN_EXPIRED")

s = mk(); t = tok(s, ttl=1000); do_revoke_key(s, "A", 1)
show("B2 只密钥作废（未过期）", s.request("A", "B", t.token_id, "x.read", "a/x", "t1"), "TOKEN_INVALID")

# ---- C. 撤销 vs 密钥作废 ----
s = mk(); t = tok(s, ttl=1000); do_revoke_key(s, "A", 1); do_revoke_token(s, t.token_id)
show("C1 已撤销+密钥作废", s.request("A", "B", t.token_id, "x.read", "a/x", "t1"), "TOKEN_REVOKED")

# ---- D. 撤销 / 过期 相对步骤 6、7 的先后 ----
s = mk(); t = tok(s, ttl=5); do_revoke_token(s, t.token_id); s.advance(10)
show("D1 已撤销+任务不匹配", s.request("A", "B", t.token_id, "x.read", "a/x", "tX"), "TOKEN_REVOKED")

s = mk(); t = tok(s, ttl=5); s.advance(10)
show("D2 已过期+范围越界", s.request("A", "B", t.token_id, "z.zap", "a/x", "t1"), "TOKEN_EXPIRED")

s = mk(); t = tok(s, ttl=1000); do_revoke_token(s, t.token_id)
show("D3 已撤销+范围越界", s.request("A", "B", t.token_id, "z.zap", "a/x", "t1"), "TOKEN_REVOKED")

# ---- E. 令牌查找 / 绑定 / 步骤 1 的相对先后 ----
s = mk(); t = tok(s, ttl=1000)
show("E1 未知令牌", s.request("A", "B", "no-such-token", "x.read", "a/x", "t1"), "TOKEN_INVALID")

s = mk(); t = tok(s, ttl=1000); do_revoke_token(s, t.token_id)
show("E2 已撤销+未知令牌？(用真令牌)", s.request("A", "B", t.token_id, "x.read", "a/x", "t1"), "TOKEN_REVOKED")

# 归因失败：用第三方 C 冒充（无 C 令牌，但请求方是 C）
s = mk(); s.add_agent("C", "peer", list(SCOPE)); t = tok(s, ttl=1000); do_revoke_token(s, t.token_id)
try:
    s.peps["C"].tokens[t.token_id] = t       # 只在 C 的 store 里放一份（不通过委托）
except Exception as e:
    print("setup C failed:", e)
show("E3 C 持令牌但非签发者+已撤销", s.request("C", "B", t.token_id, "x.read", "a/x", "t1"), "TOKEN_INVALID")

# ---- F. 步骤 4（回滚）相对步骤 5（撤销）的先后 ----
s = mk(); t = tok(s, ttl=1000)
g2 = s.authority.issue_grant("A", list(SCOPE), s.now)     # 重签发：cred_epoch 递增
s.peps["B"].refresh_grant(g2)                             # B 刷新到新 epoch
s.authority.revoke_token(t.token_id, s.now)
s.advance(s.pull_interval + 1)
show("F1 旧根令牌+已撤销（回滚 vs 撤销）", s.request("A", "B", t.token_id, "x.read", "a/x", "t1"),
     "STALE_CREDENTIAL")

print()
print("SUMMARY:", sum(1 for _, e, g in R if e != g), "diff /", len(R))
