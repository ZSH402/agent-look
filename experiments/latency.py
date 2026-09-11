"""实测延迟：把 E4 里模型化的中央 RTT 换成真实测量值，并补上此前漏算的拉取开销。

两个更正：
  1. 中央 RTT 此前是拍的 1.5ms。此处实测三类 RTT：回环 HTTP、回环 TCP、公网。
  2. 此前把 P 的每请求额外往返记为 0。**这是错的**——P 仍需周期性地拉取撤销状态，
     每次拉取是一次真实往返。摊到每请求上是 1/(pull_interval × 每 tick 请求数)。
     该项只在极低请求率下才不可忽略，但它是非零的，不应被写成 0。

公网测量失败时（离线环境）自动降级为"不可用"，不影响其余实验。
"""
from __future__ import annotations

import socket
import statistics
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

WAN_HOSTS = ("api.deepseek.com", "pypi.org")


# ------------------------------------------------------------- 回环测量
class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_POST(self):                       # noqa: N802
        n = int(self.headers.get("Content-Length", 0))
        self.rfile.read(n)
        body = b'{"ok":true}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):               # 静音
        pass


class _HandlerNoDelay(_Handler):
    """关掉 Nagle：BaseHTTPRequestHandler 默认会因分次 write 触发 Nagle + 延迟 ACK，
    在回环上引入约 40ms 的假象。这是协议栈伪影，不是网络 RTT。"""
    disable_nagle_algorithm = True


def _http_rtt(handler_cls, n: int) -> list[float]:
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    out = []
    try:
        import http.client
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        for _ in range(n):
            t0 = time.perf_counter()
            conn.request("POST", "/", body=b'{"a":1}',
                         headers={"Content-Type": "application/json"})
            r = conn.getresponse()
            r.read()
            out.append((time.perf_counter() - t0) * 1000)
        conn.close()
    finally:
        srv.shutdown()
        srv.server_close()
    return out


def measure_rtt_loopback(n: int = 300) -> dict:
    """真实回环往返：HTTP（含/不含 Nagle）+ 裸 TCP。"""
    http_rtt = _http_rtt(_Handler, n)
    nod_rtt = _http_rtt(_HandlerNoDelay, n)
    tcp_rtt: list[float] = []
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    srv.server_close()   # 仅用其占位，实际测量走 _http_rtt 与下面的 echo

    # 裸 TCP 回环：独立的 echo 服务端（HTTP 服务端不会回应非 HTTP 负载）
    echo = socket.socket()
    echo.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    echo.bind(("127.0.0.1", 0))
    echo.listen(8)
    eport = echo.getsockname()[1]
    stop = threading.Event()

    def _echo():
        echo.settimeout(1.0)
        while not stop.is_set():
            try:
                c, _ = echo.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            with c:
                c.settimeout(2.0)
                try:
                    while True:
                        data = c.recv(64)
                        if not data:
                            break
                        c.sendall(data)
                except OSError:
                    pass

    te = threading.Thread(target=_echo, daemon=True)
    te.start()
    try:
        s = socket.create_connection(("127.0.0.1", eport), timeout=5)
        for _ in range(n):
            t0 = time.perf_counter()
            s.sendall(b"ping")
            s.recv(4)
            tcp_rtt.append((time.perf_counter() - t0) * 1000)
        s.close()
    finally:
        stop.set()
        echo.close()
    nod = sorted(nod_rtt)
    raw = sorted(http_rtt)
    return {"samples": n,
            "http_median_ms": round(statistics.median(raw), 4),
            "http_p95_ms": round(raw[int(0.95 * len(raw)) - 1], 4),
            "http_nodelay_median_ms": round(statistics.median(nod), 4),
            "http_nodelay_p95_ms": round(nod[int(0.95 * len(nod)) - 1], 4),
            "tcp_median_ms": round(statistics.median(tcp_rtt), 4),
            "nagle_artifact_ms": round(statistics.median(raw) - statistics.median(nod), 3)}


def measure_rtt_wan(hosts=WAN_HOSTS, n: int = 8) -> dict:
    """公网 TCP 连接往返（真实网络）。离线时返回 unavailable。"""
    out = {}
    for host in hosts:
        ts = []
        try:
            ip = socket.gethostbyname(host)
            for _ in range(n):
                s = socket.socket()
                s.settimeout(4)
                t0 = time.perf_counter()
                s.connect((ip, 443))
                ts.append((time.perf_counter() - t0) * 1000)
                s.close()
            out[host] = round(statistics.median(ts), 2)
        except Exception as e:                # 离线/被拒：降级而不是失败
            out[host] = f"unavailable ({type(e).__name__})"
    return out


# ------------------------------------------------------------- 端到端重算
def e4_latency(workload: int = 200, pull_interval: int = 10,
               requests_per_tick: int = 1, loopback_n: int = 300) -> dict:
    """用实测 RTT 重算各模式的每请求延迟，并补上 P 的拉取开销。"""
    from .run_all import e4_cost

    lp = measure_rtt_loopback(loopback_n)
    wan = measure_rtt_wan()
    bases = {"loopback_http_nodelay": lp["http_nodelay_median_ms"],
             "loopback_tcp": lp["tcp_median_ms"],
             "loopback_http_nagle": lp["http_median_ms"]}
    for host, v in wan.items():
        if isinstance(v, (int, float)):
            bases[f"wan_{host}"] = v

    local = {m: d["wall_ms_per_request"] for m, d in e4_cost(workload).items()}
    # 每请求的**额外**协调往返数（发送到接收方的那一次是所有模式共有的，不计入）
    pull_per_request = 1.0 / (pull_interval * requests_per_tick)
    extra_rt = {"P": pull_per_request, "B1": 1.0, "B2": 0.0, "B0": 0.0}

    rows = []
    for mode in ("P", "B1", "B2", "B0"):
        row = {"mode": mode, "local_ms": local[mode],
               "extra_round_trips_per_request": round(extra_rt[mode], 5)}
        for name, rtt in bases.items():
            row[name] = round(local[mode] + extra_rt[mode] * rtt, 4)
        rows.append(row)
    return {"rtt_bases_ms": bases, "loopback": lp, "wan": wan,
            "pull_interval": pull_interval, "requests_per_tick": requests_per_tick,
            "rows": rows,
            "note": "local_ms 为实测本机 CPU 时间；rtt 为实测值；"
                    "P 的额外往返 = 撤销状态拉取的摊销值，此前被错误地记为 0"}
