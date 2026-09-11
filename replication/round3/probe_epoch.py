"""Pin down what rule 6 ('all key_epochs involved') actually covers, plus expiry edges."""
import sys
sys.path.insert(0, "/root/ai监督")
from src.runtime import System

SCOPE = ["order.read@orders/*"]


def mk(ttl=100, pull=10):
    s = System(mode="P", ttl=ttl, pull_interval=pull, clock_skew=0)
    for sid in ("A", "B", "C"):
        s.add_agent(sid, "r", SCOPE)
    return s


print("== revocation target matrix (ttl large, not expired) ==")
for who in ("A", "B", "C"):
    s = mk()
    t = s.delegate("A", "B", SCOPE, "T1")
    s.authority.revoke_key_epochs(who, 1, s.now)
    s.advance(10)
    r = s.request("A", "B", t.token_id, "order.read", "orders/1", "T1")
    print(f"  revoke_key_epochs({who}, upto=1): {r.decision} {r.reason_code}")

print("== upto semantics (A key_epoch=1) ==")
for upto in (0, 1, 2, 5):
    s = mk()
    t = s.delegate("A", "B", SCOPE, "T1")
    s.authority.revoke_key_epochs("A", upto, s.now)
    s.advance(10)
    r = s.request("A", "B", t.token_id, "order.read", "orders/1", "T1")
    print(f"  upto={upto}: {r.decision} {r.reason_code}")

print("== expiry boundary (ttl=100, delegation at t=1 -> not_after=101) ==")
for adv in (99, 100, 101):
    s = mk()
    t = s.delegate("A", "B", SCOPE, "T1")
    s.advance(adv)
    r = s.request("A", "B", t.token_id, "order.read", "orders/1", "T1")
    print(f"  now={s.now} not_after={s.peps['B'].tokens[t.token_id].not_after}: {r.decision} {r.reason_code}")

print("== chain: revoke key epoch of a mid-chain attenuator ==")
s = mk()
t1 = s.delegate("A", "B", SCOPE, "T1")
t2 = s.delegate("B", "C", SCOPE, "T1", parent_token_id=t1.token_id)
s.authority.revoke_key_epochs("B", 1, s.now)
s.advance(10)
r = s.request("B", "C", t2.token_id, "order.read", "orders/1", "T1")
print("  revoke B's epoch, request on B->C token:", r.decision, r.reason_code)
