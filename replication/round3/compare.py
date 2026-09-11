"""Run the reference implementation live and compare against v1 (my_impl.py)."""
import sys
sys.path.insert(0, "/root/ai监督")
sys.path.insert(0, "/root/ai监督/replication/round3")
from src.runtime import System, Deny
import my_impl as M

SCOPE = ["order.read@orders/*"]
rows = []


def mk(ttl=100, pull=10, skew=0):
    s = System(mode="P", ttl=ttl, pull_interval=pull, clock_skew=skew)
    for sid in ("A", "B", "C"):
        s.add_agent(sid, "r", SCOPE)
    return s


def tk(s, tid):
    for p in s.peps.values():
        if tid in p.tokens:
            return p.tokens[tid]
    return None


def rec(name, mine, ref):
    rows.append((name, mine, ref, "AGREE" if mine == ref else "DISAGREE"))
    print(f"{name:52s} mine={mine:18s} ref={ref:18s} {'AGREE' if mine == ref else 'DISAGREE'}")


def verify_case(name, revoke_token=False, revoke_subject=False, key_epoch_subject=None,
                expired=False, advance_ok=True):
    s = mk()
    t = s.delegate("A", "B", SCOPE, "T1")
    if revoke_token:
        s.authority.revoke_token(t.token_id, s.now)
    if revoke_subject:
        s.authority.revoke_subject("A", s.now)
    if key_epoch_subject is not None:
        s.authority.revoke_key_epochs(key_epoch_subject, 1, s.now)
    if advance_ok:
        s.advance(120 if expired else 10)
    r = s.request("A", "B", t.token_id, "order.read", "orders/1", "T1")
    seen = s.peps["B"]
    mine = M.verify_reason(
        {"token_id": t.token_id, "root_subject_id": "A", "holder_id": "B", "not_after": 101,
         "chain": [{"attenuator_id": "A", "attenuator_key_epoch": 1}]},
        {"subject_id": "A", "key_epoch": 1}, s.now,
        revoked_token_ids={t.token_id} if (revoke_token and advance_ok) else set(),
        revoked_subject_ids={"A"} if (revoke_subject and advance_ok) else set(),
        revoked_key_upper={key_epoch_subject: 1} if (key_epoch_subject and advance_ok) else {})
    rec(name, mine, r.reason_code)


def derive_case(name, sealed, escape, delegator="B"):
    s = mk()
    t = s.delegate("A", "B", SCOPE, "T1", redelegatable=not sealed)
    child = ["order.read@**"] if escape else SCOPE
    try:
        s.delegate(delegator, "C", child, "T1", parent_token_id=t.token_id)
        ref = "OK"
    except Deny as d:
        ref = getattr(d, "reason_code", "?")
    parent_held = t.token_id in s.peps[delegator].tokens
    mine = M.attenuate_reason(parent_held, "B", delegator, child, SCOPE, not sealed,
                              child_scope_in_parent=not escape)
    rec(name, mine, ref)


print("== item 1: verify priority  revoke -> expire -> key epoch ==")
verify_case("V1 not-revoked, expired, key-epoch revoked", key_epoch_subject="A", expired=True)
verify_case("V2 revoked + expired", revoke_token=True, expired=True)
verify_case("V3 key-epoch revoked only", key_epoch_subject="A")
verify_case("V4 revoked token only", revoke_token=True)
verify_case("V5 subject revoked + expired + key revoked", revoke_subject=True, key_epoch_subject="A", expired=True)
verify_case("V6 baseline (nothing)", )

print("== item 2: attenuate order  rule2 (scope) vs rule5 (seal) ==")
derive_case("D1 sealed + scope escape (delegator = holder B)", True, True)
derive_case("D2 sealed + scope in-bounds", True, False)
derive_case("D3 open + scope escape", False, True)
derive_case("D4 sealed + scope escape (delegator = A, not holder)", True, True, delegator="A")

print("== item 4: time window ==")
for skew in (0, 20):
    for k in (0, 1, 20, 21, -1, -50, -51):
        s = mk(skew=skew)
        t = s.delegate("A", "B", SCOPE, "T1")
        s.request("A", "B", t.token_id, "order.read", "orders/1", "T1")
        req = s.requests[-1]
        t0 = req.ts
        s.now = t0 - k
        s.peps["B"].seen_nonces.clear()
        r = s.peps["B"].handle(req)
        mine = "OK" if M.window_ok(s.now, t0, skew, 50) else "REPLAY"
        expected_mine = "OK" if M.window_ok(t0, t0, skew, 50) else "REPLAY"
        rec(f"T skew={skew} ts-now={k:+d}", mine, r.reason_code if r.decision == "DENY" else "OK")

print("== item 5: chain root ==")
s = mk()
t1 = s.delegate("A", "B", SCOPE, "T1")
t2 = s.delegate("B", "C", SCOPE, "T1", parent_token_id=t1.token_id)
tok = s.peps["C"].tokens[t2.token_id]
mine_root = M.chain_root({"token_id": tok.token_id, "chain": [{"parent_token_id": lk.parent_token_id} for lk in tok.chain]})
rec("R1 chain_root of 2-hop token", mine_root, tok.chain[0].parent_token_id)

print()
print("AGREE:", sum(1 for r in rows if r[3] == "AGREE"), "/", len(rows))
for n, m, r, v in rows:
    if v == "DISAGREE":
        print("  DISAGREE:", n, m, r)
