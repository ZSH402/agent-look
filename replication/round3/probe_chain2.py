"""S5b: identify H empirically, and check attenuator-key availability for old epochs."""
import sys, hashlib, json
sys.path.insert(0, "/root/ai监督")
from src.runtime import System
from src.model import derive_token_id

args = ("pid", "hid", ("order.read@orders/**",), "T1", 101, 1, True)
target = derive_token_id(*args)
print("derive_token_id(*args) =", target)

cands = {
    "md5('|'.join(map(str,args)))": hashlib.md5("|".join(map(str, args)).encode()).hexdigest(),
    "md5(json(list))": hashlib.md5(json.dumps(list(args), sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
    "md5(json(list,default=str))": hashlib.md5(json.dumps(list(args), sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest(),
    "md5(concat)": hashlib.md5("".join(map(str, args)).encode()).hexdigest(),
    "sha256[:32]": hashlib.sha256(json.dumps(list(args), sort_keys=True, separators=(",", ":")).encode()).hexdigest()[:32],
}
for k, v in cands.items():
    print(f"  {k}: {v} match={v == target}")

print()
print("-- key rotation vs old link verification --")
SCOPE = ["order.read@orders/**"]
s = System(mode="P", ttl=100, pull_interval=10, clock_skew=0)
for sid in ("A", "B", "C"):
    s.add_agent(sid, "r", SCOPE)
t1 = s.delegate("A", "B", SCOPE, "T1")
print("registry A before rotate:", s.authority.registry["A"].pubkey[:16], "epoch", s.authority.registry["A"].key_epoch)
s.rotate_key("A", 2, SCOPE)
print("registry A after  rotate:", s.authority.registry["A"].pubkey[:16], "epoch", s.authority.registry["A"].key_epoch)
try:
    t2 = s.delegate("B", "C", SCOPE, "T1", parent_token_id=t1.token_id)
    print("delegate on old-epoch parent token: OK, chain len", len(t2.chain))
except Exception as e:
    print("delegate on old-epoch parent token FAILED:", type(e).__name__, e)

s2 = System(mode="P", ttl=100, pull_interval=10, clock_skew=0)
for sid in ("A", "B"):
    s2.add_agent(sid, "r", SCOPE)
tk = s2.delegate("A", "B", SCOPE, "T1")
s2.rotate_key("A", 2, SCOPE)
s2.advance(10)
r = s2.request("A", "B", tk.token_id, "order.read", "orders/1", "T1")
print("request with pre-rotation token after rotate:", r.decision, r.reason_code)
