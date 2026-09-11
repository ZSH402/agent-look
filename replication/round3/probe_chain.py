"""S5: is the token chain self-describing enough for OFFLINE verification?"""
import sys, dataclasses, json
sys.path.insert(0, "/root/ai监督")
from src.runtime import System
from src.model import derive_token_id

SCOPE = ["order.read@orders/**"]
SCOPE_C = ["order.read@orders/eu/*"]

s = System(mode="P", ttl=100, pull_interval=10, clock_skew=0)
for sid in ("A", "B", "C"):
    s.add_agent(sid, "r", SCOPE)
t1 = s.delegate("A", "B", SCOPE, "T1")
t2 = s.delegate("B", "C", SCOPE_C, "T1", parent_token_id=t1.token_id)


def held(sid, tid):
    return s.peps[sid].tokens.get(tid)


print("-- token as seen in C's store --")
tok = held("C", t2.token_id)
print("Token fields:", [f.name for f in dataclasses.fields(tok)])
print("values:", {k: v for k, v in vars(tok).items() if k != "chain"})
print("chain length:", len(tok.chain))
for i, lk in enumerate(tok.chain):
    print(f"  Link[{i}] fields:", [f.name for f in dataclasses.fields(lk)])
    print(f"  Link[{i}] values:", {k: (v[:12] + '..' if isinstance(v, str) and len(v) > 14 else v)
                                   for k, v in vars(lk).items()})

print("-- chain root per spec (chain[0].parent_token_id) --")
print("chain[0].parent_token_id =", tok.chain[0].parent_token_id)
print("token.token_id           =", tok.token_id)
print("t1.token_id              =", t1.token_id)

print("-- offline recomputation of token_id from Link fields --")
try:
    for i, lk in enumerate(tok.chain):
        rec = derive_token_id(lk.parent_token_id, lk.holder_id, lk.scope, lk.task_id,
                              lk.not_after, lk.depth, lk.redelegatable)
        print(f"  Link[{i}] recomputed={rec} stored={lk.token_id} match={rec == lk.token_id}")
except Exception as e:
    print("  derive_token_id failed:", type(e).__name__, e)

print("-- what the verifier can resolve the chain root to --")
print("authority.grant_history keys:", list(s.authority.grant_history)[:8])
print("grant_for_root_id(root):", s.authority.grant_for_root_id("A", tok.chain[0].parent_token_id))
print("grant fields:", [f.name for f in dataclasses.fields(
    s.authority.grant_for_root_id("A", tok.chain[0].parent_token_id))])

print("-- is the root grant inside the token? --")
print("has grant field:", hasattr(tok, "grant"), "| token field names:", [f.name for f in dataclasses.fields(tok)])
print("-- attenuator public key available from the token alone? --")
print("Link has pubkey field:", any(f.name.endswith("pubkey") or "key" in f.name for f in dataclasses.fields(tok.chain[0])))
print("registry keys:", list(s.authority.registry) if hasattr(s.authority.registry, "keys") else s.authority.registry)
