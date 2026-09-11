"""Black-box probes of the reference implementation, spec/spec.md only.

Scenarios:
  S1  verify order  revoke -> expire -> key-epoch
  S2  attenuate order  rule2 (scope) vs rule5 (redelegatable)
  S3  token copies / parent-token availability
Only public API from the task prompt + attribute reads are used.
"""
import sys
sys.path.insert(0, "/root/ai监督")
from src.runtime import System
from src.model import Deny

SCOPE = ["order.read@orders/*"]


def tok(s, tid):
    for p in s.peps.values():
        if tid in p.tokens:
            return p.tokens[tid]
    return None


def mk(ttl=100, pull=10, skew=0):
    s = System(mode="P", ttl=ttl, pull_interval=pull, clock_skew=skew)
    s.add_agent("A", "coord", SCOPE)
    s.add_agent("B", "worker", SCOPE)
    s.add_agent("C", "worker", SCOPE)
    return s


def show(tag, r):
    print(f"{tag}: {r.decision} {r.reason_code}")


print("== S1 verify check order ==")

# S1a: not revoked, expired, key epoch revoked -> spec says TOKEN_EXPIRED
s = mk(ttl=100, pull=10, skew=0)
t = s.delegate("A", "B", SCOPE, "T1")
s.authority.revoke_key_epochs("A", 1, s.now)   # epoch 1 == current -> revoked
s.advance(120)                                  # token now expired, revocation pulled
tk = tok(s, t.token_id)
print("S1a token not_after", tk.not_after, "now", s.now,
      "revoked_ids", s.authority.revoked_token_ids,
      "revoked_epochs", dict(s.authority.revoked_key_epochs))
show("S1a (expired+key-epoch-revoked, NOT revoke_token)", s.request("A", "B", t.token_id, "order.read", "orders/1", "T1"))

# S1b: revoked + expired -> TOKEN_REVOKED
s = mk(ttl=100, pull=10, skew=0)
t = s.delegate("A", "B", SCOPE, "T1")
s.authority.revoke_token(t.token_id, s.now)
s.advance(120)
show("S1b (revoked+expired)", s.request("A", "B", t.token_id, "order.read", "orders/1", "T1"))

# S1c: key epoch revoked only (not expired, not revoked)
s = mk(ttl=100, pull=10, skew=0)
t = s.delegate("A", "B", SCOPE, "T1")
s.authority.revoke_key_epochs("A", 1, s.now)
s.advance(10)
print("S1c now", s.now, "not_after", tok(s, t.token_id).not_after)
show("S1c (key-epoch-revoked only)", s.request("A", "B", t.token_id, "order.read", "orders/1", "T1"))

# S1d: revoked only (rule 5 alone)
s = mk(ttl=100, pull=10, skew=0)
t = s.delegate("A", "B", SCOPE, "T1")
s.authority.revoke_token(t.token_id, s.now)
s.advance(10)
show("S1d (revoked only)", s.request("A", "B", t.token_id, "order.read", "orders/1", "T1"))

# S1e: revoked + key epoch revoked, not expired
s = mk(ttl=100, pull=10, skew=0)
t = s.delegate("A", "B", SCOPE, "T1")
s.authority.revoke_token(t.token_id, s.now)
s.authority.revoke_key_epochs("A", 1, s.now)
s.advance(10)
show("S1e (revoked+key-epoch, not expired)", s.request("A", "B", t.token_id, "order.read", "orders/1", "T1"))

# S1f: baseline allow
s = mk(ttl=100, pull=10, skew=0)
t = s.delegate("A", "B", SCOPE, "T1")
s.advance(10)
show("S1f (baseline)", s.request("A", "B", t.token_id, "order.read", "orders/1", "T1"))


print("== S2 attenuate check order: seal + scope escape ==")

def try_delegate(tag, s, frm, to, scope, parent):
    try:
        s.delegate(frm, to, scope, "T1", parent_token_id=parent)
        print(f"{tag}: NO EXCEPTION (allowed)")
    except Deny as d:
        print(f"{tag}: Deny code={getattr(d, 'reason_code', None)!r} args={d.args!r}")


# parent sealed (redelegatable=False) AND child scope escapes parent scope
s = mk()
t = s.delegate("A", "B", SCOPE, "T1", redelegatable=False)
try_delegate("S2a (sealed + scope escape, delegator=holder B)", s, "B", "C", ["order.read@**"], t.token_id)
# sealed + scope in-bounds -> rule 5 alone
try_delegate("S2b (sealed + in-bounds)", s, "B", "C", SCOPE, t.token_id)
# not sealed + scope escape -> rule 2 alone
s2 = mk()
t2 = s2.delegate("A", "B", SCOPE, "T1", redelegatable=True)
try_delegate("S2c (open + scope escape)", s2, "B", "C", ["order.read@**"], t2.token_id)

print("== S3 token copies / parent availability ==")
s = mk()
t = s.delegate("A", "B", SCOPE, "T1")
print("S3 token holders:", {k: list(v.tokens) for k, v in s.peps.items()})
# A (issuer, not holder) tries to redelegate the token it issued
try_delegate("S3a (issuer A reuses token held by B)", s, "A", "C", SCOPE, t.token_id)
# B (holder) redelegates -> should work
try_delegate("S3b (holder B redelegates)", s, "B", "C", SCOPE, t.token_id)
