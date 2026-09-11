"""Extra black-box probes: subject revocation, pull latency, store copies."""
import sys
sys.path.insert(0, "/root/ai监督")
from src.runtime import System

SCOPE = ["order.read@orders/*"]


def mk(ttl=100, pull=10):
    s = System(mode="P", ttl=ttl, pull_interval=pull, clock_skew=0)
    for sid in ("A", "B", "C"):
        s.add_agent(sid, "r", SCOPE)
    return s


print("== S1g subject-revoked + expired + key-epoch revoked ==")
s = mk()
t = s.delegate("A", "B", SCOPE, "T1")
s.authority.revoke_subject("A", s.now)
s.authority.revoke_key_epochs("A", 1, s.now)
s.advance(120)
r = s.request("A", "B", t.token_id, "order.read", "orders/1", "T1")
print("S1g:", r.decision, r.reason_code)

print("== S1h revocation not yet pulled (no advance) ==")
s = mk()
t = s.delegate("A", "B", SCOPE, "T1")
s.authority.revoke_token(t.token_id, s.now)
s.authority.revoke_key_epochs("A", 1, s.now)
r = s.request("A", "B", t.token_id, "order.read", "orders/1", "T1")
print("S1h (t=1, pull_interval=10, never advanced):", r.decision, r.reason_code)
s.advance(10)
r = s.request("A", "B", t.token_id, "order.read", "orders/2", "T1")
print("S1h after advance(10):", r.decision, r.reason_code)

print("== S3c store copies along a chain ==")
s = mk()
t1 = s.delegate("A", "B", SCOPE, "T1")
t2 = s.delegate("B", "C", SCOPE, "T1", parent_token_id=t1.token_id)
print("A store has t1:", t1.token_id in s.peps["A"].tokens)
print("A store has t2:", t2.token_id in s.peps["A"].tokens)
print("B store has t1:", t1.token_id in s.peps["B"].tokens)
print("B store has t2:", t2.token_id in s.peps["B"].tokens)
print("C store has t1:", t1.token_id in s.peps["C"].tokens)
print("C store has t2:", t2.token_id in s.peps["C"].tokens)
print("B store token ids:", list(s.peps["B"].tokens))
print("A store token ids:", list(s.peps["A"].tokens))

print("== S2d sealed parent, scope escape, delegator NOT holder ==")
s = mk()
t = s.delegate("A", "B", SCOPE, "T1", redelegatable=False)
try:
    s.delegate("A", "C", ["order.read@**"], "T1", parent_token_id=t.token_id)
    print("S2d: allowed")
except Exception as e:
    print("S2d:", type(e).__name__, getattr(e, "reason_code", None), e.args)

print("== S2e equal-scope child of sealed parent (rule2 false, rule5 true) ==")
s = mk()
t = s.delegate("A", "B", SCOPE, "T1", redelegatable=False)
try:
    s.delegate("B", "C", SCOPE, "T1", parent_token_id=t.token_id)
    print("S2e: allowed")
except Exception as e:
    print("S2e:", type(e).__name__, getattr(e, "reason_code", None))
