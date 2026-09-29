"""C2 beaconing — MITRE T1071 (Application Layer Protocol) / T1573.

Malware sau khi nhiễm thường "gọi về nhà" (beacon) tới máy chủ C2 theo CHU KỲ đều đặn
(vd: mỗi 60 giây) để nhận lệnh. Con người lướt web thì ngẫu nhiên; máy thì đều tăm tắp.

Đo độ đều bằng hệ số biến thiên CV = σ / μ của khoảng cách giữa các lần kết nối mới:
  * CV ≈ 0      → cực kỳ đều (rất giống beacon)
  * CV ≥ 0.5    → ngẫu nhiên như người dùng
Malware xịn thêm "jitter" (vd ±20%) để né — khi đó cần thêm phân tích dài hạn.
"""

from __future__ import annotations

import statistics
from collections import defaultdict, deque

from mini_ids.detectors.base import Detector
from mini_ids.packet import PacketInfo


class BeaconDetector(Detector):
    name = "beacon"
    title = "C2 beaconing"
    description = "Kết nối lặp lại tới cùng đích với chu kỳ đều bất thường."
    mitre = ["T1071", "T1573"]

    HISTORY = 20

    def __init__(self, cfg):
        super().__init__(cfg)
        self.min_events = int(self.opt("min_events", 6))
        self.min_interval = float(self.opt("min_interval", 1.0))
        self.max_interval = float(self.opt("max_interval", 3600))
        self.max_cv = float(self.opt("max_cv", 0.1))
        self.allow_ports = set(self.opt("allow_ports", [53, 123]))
        self.home = cfg.home_net
        self.starts: dict[tuple, deque[float]] = defaultdict(lambda: deque(maxlen=self.HISTORY))

    def process(self, pkt: PacketInfo):
        # Chỉ xét kết nối TCP mới từ trong mạng ra ngoài
        if not pkt.is_syn or pkt.dport in self.allow_ports:
            return ()
        if pkt.src not in self.home or pkt.dst in self.home:
            return ()
        key = (pkt.src, pkt.dst, pkt.dport)
        times = self.starts[key]
        if times and pkt.ts - times[-1] < 0.5:   # SYN retransmit, không tính
            return ()
        times.append(pkt.ts)
        if len(times) < self.min_events:
            return ()
        ts = list(times)
        intervals = [b - a for a, b in zip(ts, ts[1:])]
        mean = statistics.fmean(intervals)
        if not (self.min_interval <= mean <= self.max_interval):
            return ()
        cv = statistics.pstdev(intervals) / mean
        if cv > self.max_cv:
            return ()
        return [self.alert(
            pkt, title="Beaconing định kỳ (nghi C2)", severity="high",
            key=f"{pkt.src}->{pkt.dst}:{pkt.dport}", src=pkt.src, dst=pkt.dst,
            description=f"{pkt.src} kết nối {pkt.dst}:{pkt.dport} {len(ts)} lần, chu kỳ "
                        f"~{mean:.1f}s, CV={cv:.3f} (càng gần 0 càng máy móc).",
            interval=round(mean, 2), cv=round(cv, 4), connections=len(ts), dport=pkt.dport)]

    def tick(self, now):
        stale = [k for k, v in self.starts.items() if v and now - v[-1] > self.max_interval * 2]
        for k in stale:
            del self.starts[k]
        return ()
