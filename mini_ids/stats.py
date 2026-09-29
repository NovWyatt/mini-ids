"""Thống kê traffic cho dashboard: pps/bps theo giây, giao thức, top talkers, top port."""

from __future__ import annotations

from collections import Counter, deque
from typing import Any

from mini_ids.packet import PacketInfo
from mini_ids.utils import NetSet, service_name

_MAX_KEYS = 20000
_KEEP_KEYS = 5000


def _trim(counter: Counter) -> Counter:
    if len(counter) > _MAX_KEYS:
        return Counter(dict(counter.most_common(_KEEP_KEYS)))
    return counter


class TrafficStats:
    def __init__(self, home_net: NetSet | None = None, history: int = 900):
        self.home = home_net or NetSet()
        self.buckets: deque[list] = deque(maxlen=history)   # [giây, gói, byte]
        self.total_packets = 0
        self.total_bytes = 0
        self.first_ts: float | None = None
        self.last_ts: float | None = None
        self.protocols: Counter[str] = Counter()
        self.services: Counter[str] = Counter()
        self.src_bytes: Counter[str] = Counter()
        self.dst_bytes: Counter[str] = Counter()
        self.dst_ports: Counter[int] = Counter()
        self.hosts: set[str] = set()

    def update(self, pkt: PacketInfo) -> None:
        sec = int(pkt.ts)
        if not self.buckets or sec > self.buckets[-1][0]:
            self.buckets.append([sec, 0, 0])
        bucket = self.buckets[-1]
        bucket[1] += 1
        bucket[2] += pkt.length

        self.total_packets += 1
        self.total_bytes += pkt.length
        if self.first_ts is None:
            self.first_ts = pkt.ts
        self.last_ts = pkt.ts if self.last_ts is None else max(self.last_ts, pkt.ts)

        proto = "DNS" if pkt.dns_qname is not None else pkt.proto
        self.protocols[proto] += 1
        svc = service_name(pkt.dport) or service_name(pkt.sport)
        if svc:
            self.services[svc] += pkt.length
        if pkt.src:
            self.src_bytes[pkt.src] += pkt.length
            if len(self.hosts) < 50000 and pkt.src in self.home:
                self.hosts.add(pkt.src)
        if pkt.dst:
            self.dst_bytes[pkt.dst] += pkt.length
        if pkt.dport is not None and (pkt.is_syn or (pkt.proto == "UDP" and not pkt.dns_response)):
            self.dst_ports[pkt.dport] += 1
        if self.total_packets % 50000 == 0:
            self.src_bytes = _trim(self.src_bytes)
            self.dst_bytes = _trim(self.dst_bytes)
            self.dst_ports = _trim(self.dst_ports)

    def series(self, now: float, seconds: int = 300) -> dict[str, list]:
        end = int(now) - 1   # bỏ giây hiện tại (chưa đủ dữ liệu → đường bị tụt ở cuối)
        start = end - seconds + 1
        if self.first_ts is not None:
            start = max(start, min(int(self.first_ts), end - 1))  # đừng vẽ "0 gói" cho lúc chưa bắt đầu
        data = {b[0]: b for b in self.buckets if b[0] >= start}
        t, pps, bps = [], [], []
        for sec in range(start, end + 1):
            b = data.get(sec)
            t.append(sec)
            pps.append(b[1] if b else 0)
            bps.append(b[2] * 8 if b else 0)
        return {"t": t, "pps": pps, "bps": bps}

    def current_rate(self, now: float) -> tuple[int, int]:
        """Tốc độ của giây vừa hoàn tất (gói/s, bit/s)."""
        target = int(now) - 1
        for b in reversed(self.buckets):
            if b[0] == target:
                return b[1], b[2] * 8
            if b[0] < target:
                break
        return 0, 0

    def snapshot(self, now: float, seconds: int = 300) -> dict[str, Any]:
        pps, bps = self.current_rate(now)
        top = lambda c, n=8: c.most_common(n)
        return {
            "now": now,
            "series": self.series(now, seconds),
            "rate": {"pps": pps, "bps": bps},
            "totals": {"packets": self.total_packets, "bytes": self.total_bytes,
                       "hosts": len(self.hosts), "first_ts": self.first_ts, "last_ts": self.last_ts},
            "protocols": [{"name": k, "packets": v} for k, v in top(self.protocols)],
            "services": [{"name": k, "bytes": v} for k, v in top(self.services)],
            "top_src": [{"ip": k, "bytes": v, "internal": k in self.home} for k, v in top(self.src_bytes)],
            "top_dst": [{"ip": k, "bytes": v, "internal": k in self.home} for k, v in top(self.dst_bytes)],
            "top_ports": [{"port": k, "service": service_name(k), "hits": v} for k, v in top(self.dst_ports)],
        }
