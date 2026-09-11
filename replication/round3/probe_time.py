"""S4: time window with non-default clock_skew.

The documented API has no ts parameter, so a request is created at ts = t0 and the
receiver clock is then set to t0 - k, making the request's ts k ticks in the future
at handling time (k<0 => ts in the past by |k|).
"""
import sys
sys.path.insert(0, "/root/ai监督")
from src.runtime import System

SCOPE = ["order.read@orders/*"]


def run(skew, k, max_age=50):
    s = System(mode="P", ttl=100, pull_interval=10, max_request_age=max_age, clock_skew=skew)
    s.add_agent("A", "coord", SCOPE)
    s.add_agent("B", "worker", SCOPE)
    t = s.delegate("A", "B", SCOPE, "T1")
    s.request("A", "B", t.token_id, "order.read", "orders/1", "T1")  # consumes nonce, ts = t0
    req = s.requests[-1]
    t0 = req.ts
    s.now = t0 - k
    s.peps["B"].seen_nonces.clear()
    r = s.peps["B"].handle(req)
    return f"skew={skew} (now-ts)={-k:+d} -> {r.decision} {r.reason_code}"


print("== future timestamps ==")
for skew in (0, 20):
    for k in (0, 1, 19, 20, 21, 50):
        print(run(skew, k))
print("== past timestamps (max_request_age=50) ==")
for k in (-1, -50, -51, -60):
    print(run(0, k))
print("== past timestamps with skew=20 ==")
for k in (-51, -60):
    print(run(20, k))
