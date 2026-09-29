"""Data exfiltration — MITRE T1048 (Exfiltration Over Alternative Protocol) / T1041.

Sau khi chiếm được máy, kẻ tấn công gom dữ liệu rồi đẩy ra ngoài. Dấu hiệu mạng:
1 host NỘI BỘ gửi lượng byte lớn bất thường tới 1 đích BÊN NGOÀI trong thời gian ngắn.
(Cần $HOME_NET đúng — xem home_net trong config.)

False positive thường gặp: backup cloud, upload video, sync Google Drive/OneDrive
→ giải pháp thực tế: allowlist đích hợp lệ hoặc so với baseline từng host.
"""

from __future__ import annotations

from mini_ids.detectors.base import Detector
from mini_ids.packet import PacketInfo
from mini_ids.utils import WindowSum


class ExfilDetector(Detector):
    name = "exfil"
    title = "Data exfiltration"
    description = "Host nội bộ đẩy lượng dữ liệu lớn ra 1 đích Internet trong thời gian ngắn."
    mitre = ["T1048", "T1041"]

    def __init__(self, cfg):
        super().__init__(cfg)
        self.window = float(self.opt("window", 300))
        self.threshold = float(self.opt("threshold_bytes", 50_000_000))
        self.home = cfg.home_net
        self.outbound = WindowSum(self.window)

    def process(self, pkt: PacketInfo):
        if not pkt.src or not pkt.dst or pkt.proto == "ARP":
            return ()
        if pkt.src not in self.home or pkt.dst in self.home:
            return ()
        total = self.outbound.add((pkt.src, pkt.dst), pkt.ts, pkt.length)
        if total < self.threshold:
            return ()
        return [self.alert(
            pkt, title="Nghi rò rỉ dữ liệu (exfiltration)", severity="high",
            key=f"{pkt.src}->{pkt.dst}", src=pkt.src, dst=pkt.dst,
            description=f"{pkt.src} đã gửi {total / 1e6:.1f} MB tới {pkt.dst} "
                        f"trong {self.window / 60:g} phút (ngưỡng {self.threshold / 1e6:g} MB).",
            bytes_out=int(total), dport=pkt.dport)]

    def tick(self, now):
        self.outbound.prune(now)
        return ()
