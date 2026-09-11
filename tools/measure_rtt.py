"""一次性测量工具：把本机网络往返测量**冻结**成带时间戳的产物。

    python3 -m tools.measure_rtt            # 测量并写入 data/measurement_rtt.json
    python3 -m tools.measure_rtt --force    # 覆盖已有产物

为什么需要单独的工具，而不是让 `run_all` 顺手测一次：

    实测值**随运行波动**（同一台机器上回环 TCP 在 0.23–0.30ms、公网在 7.5–26.7ms 之间跳）。
    起初文档直接引用了某一次运行的数值，而 `run_all` 每次重跑都会产生新值，
    于是文档在无人察觉的情况下变成了**已失效的数字**——正是"文档数字必须脚本核对"
    这条规则要防的事，我却给实测值开了例外。

    因此：**测量与实验解耦**。本工具产出带时间戳的冻结产物，文档只引用它；
    `run_all` 里的 E24 仍然每次实测（用于关系型断言），但它的数值不得写进文档。

产物同时记录**派生比值**（如 Nagle 伪影相对真实回环往返的倍数），
避免文档里出现手工算出来的倍数。
"""
from __future__ import annotations

import argparse
import datetime
import json
import os
import platform
import statistics
import sys

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(HERE, "data", "measurement_rtt.json")
sys.path.insert(0, HERE)

from experiments.latency import measure_rtt_loopback, measure_rtt_wan  # noqa: E402


def collect(rounds: int = 3, n: int = 300) -> dict:
    """多轮测量，取每项的中位数；同时记录轮间极差，暴露波动幅度。"""
    series: dict[str, list[float]] = {}
    for _ in range(rounds):
        lp = measure_rtt_loopback(n)
        wan = measure_rtt_wan()
        vals = {"loopback_tcp_ms": lp["tcp_median_ms"],
                "loopback_http_nodelay_ms": lp["http_nodelay_median_ms"],
                "loopback_http_nagle_ms": lp["http_median_ms"],
                "nagle_artifact_ms": lp["nagle_artifact_ms"]}
        for host, v in wan.items():
            if isinstance(v, (int, float)):
                vals[f"wan_{host}_ms"] = v
        for k, v in vals.items():
            series.setdefault(k, []).append(v)

    measured, spread = {}, {}
    for k, vs in series.items():
        measured[k] = round(statistics.median(vs), 3)
        spread[k] = round(max(vs) - min(vs), 3)

    tcp = measured.get("loopback_tcp_ms") or 0.0
    art = measured.get("nagle_artifact_ms") or 0.0
    return {
        "measured_ms": measured,
        "round_to_round_spread_ms": spread,
        "derived": {
            "nagle_artifact_over_loopback_tcp": round(art / tcp, 1) if tcp else None,
            "loopback_tcp_over_modeled_1.5ms": round(tcp / 1.5, 3) if tcp else None,
            "wan_min_ms": min(v for k, v in measured.items() if k.startswith("wan_")),
            "wan_max_ms": max(v for k, v in measured.items() if k.startswith("wan_")),
            "modeled_1.5ms_underestimates_wan_by": [
                round(min(v for k, v in measured.items() if k.startswith("wan_")) / 1.5, 1),
                round(max(v for k, v in measured.items() if k.startswith("wan_")) / 1.5, 1)],
        },
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--force", action="store_true")
    ap.add_argument("--rounds", type=int, default=3)
    ap.add_argument("--samples", type=int, default=300)
    args = ap.parse_args()
    if os.path.exists(OUT) and not args.force:
        print(f"{OUT} 已存在（用 --force 覆盖）。文档应引用该冻结产物，不要重测后改文档。")
        return 0
    data = collect(args.rounds, args.samples)
    data["provenance"] = {
        "measured_at_utc": datetime.datetime.now(datetime.timezone.utc)
                                     .isoformat(timespec="seconds"),
        "host": {"platform": platform.platform(), "python": platform.python_version()},
        "method": f"每项 {args.rounds} 轮 × 每轮 {args.samples} 次回环 / 8 次公网 TCP 连接，"
                  f"取轮间中位数",
        "warning": "实测值随运行与网络状况波动，轮间极差见 round_to_round_spread_ms。"
                   "文档只可引用本文件，不得引用 run_all 当次产生的数值。",
    }
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=1)
    print(f"写出 {OUT}")
    for k, v in data["measured_ms"].items():
        print(f"  {k:32s} {v:8.3f} ms   (轮间极差 {data['round_to_round_spread_ms'][k]})")
    print(f"  {data['derived']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
