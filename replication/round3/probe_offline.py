"""Item 5: can a chain be verified OFFLINE from spec fields alone?

Uses only: the token object from the receiver's store, a trusted copy of the root
grant, and a public-key directory. Two generic primitives are supplied by the
reference (their encodings are NOT in the spec): H=src.model.derive_token_id and
Ed25519 verify=src.crypto.verify.
"""
import sys, dataclasses, json
sys.path.insert(0, "/root/ai监督")
import src.crypto as c
from src.runtime import System
from src.model import derive_token_id

SCOPE = ["order.read@orders/**"]
s = System(mode="P", ttl=100, pull_interval=10, clock_skew=0)
for sid in ("A", "B", "C"):
    s.add_agent(sid, "r", SCOPE)
t1 = s.delegate("A", "B", SCOPE, "T1")
t2 = s.delegate("B", "C", ["order.read@orders/eu/*"], "T1", parent_token_id=t1.token_id)
tok = s.peps["C"].tokens[t2.token_id]

# --- offline inputs
root_id = tok.chain[0].parent_token_id                       # §2.3 line 66
grant = s.authority.grant_for_root_id("A", root_id)          # "权威的授权历史" by chain root
pk = {sid: s.authority.registry[sid].pubkey for sid in ("A", "B", "C")}
print("chain_root =", root_id, "| grant resolved:", grant is not None, "| grant.cred_epoch =", grant.cred_epoch)

# --- rule 1: root grant signature
gd = {k: v for k, v in dataclasses.asdict(grant).items() if k != "sig"}
print("rule1 root grant sig verifies under K_A:", c.verify(s.authority.pk, gd, grant.sig))

# --- rule 2 + 3: per link
prev_scope = grant.scope
ok_all = True
for i, lk in enumerate(tok.chain):
    d = {k: v for k, v in vars(lk).items() if k != "sig"}
    sig_ok = c.verify(pk[lk.attenuator_id], d, lk.sig)
    rec = derive_token_id(lk.parent_token_id, lk.holder_id, lk.scope, lk.task_id,
                          lk.not_after, lk.depth, lk.redelegatable)
    print(f"link[{i}] attenuator={lk.attenuator_id} sig_ok={sig_ok} id_recompute_ok={rec == lk.token_id}")
    ok_all &= sig_ok and rec == lk.token_id
print("all links verified offline:", ok_all)

# --- rule 7 / final fields vs token fields
last = tok.chain[-1]
print("rule7 last-link matches token fields:",
      last.token_id == tok.token_id, last.holder_id == tok.holder_id,
      last.scope == tok.scope, last.not_after == tok.not_after,
      last.depth == tok.depth, last.redelegatable == tok.redelegatable)

# --- what is NOT in the token
print("token carries root grant:", False if not hasattr(tok, "grant") else True)
print("Link carries attenuator pubkey:", any("pubkey" in f.name for f in dataclasses.fields(last)),
      "| Link fields:", [f.name for f in dataclasses.fields(last)])
print("registry exposes key history:", hasattr(s.authority, "key_history"),
      [n for n in dir(s.authority) if "key" in n])
