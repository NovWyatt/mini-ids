"""Brute-force đăng nhập — MITRE T1110.

Hydra/Medusa/ncrack thử mật khẩu bằng cách mở RẤT NHIỀU kết nối mới tới cùng 1 dịch vụ
đăng nhập (SSH, RDP, FTP...). IDS mạng không đọc được mật khẩu (SSH/RDP mã hoá) nhưng
vẫn thấy được "hình dạng" traffic: số SYN mới tới cùng (src, dst, port) tăng vọt.
"""

from __future__ import annotations

from mini_ids.detectors.base import Detector
from mini_ids.packet import PacketInfo
from mini_ids.utils import WindowCounter


class BruteForceDetector(Detector):
    name = "bruteforce"
    title = "Brute-force đăng nhập"
    description = "Nhiều kết nối mới liên tục tới dịch vụ đăng nhập (SSH, RDP, FTP, SMB...)."
    mitre = ["T1110"]

    def __init__(self, cfg):
        super().__init__(cfg)
        self.window = float(self.opt("window", 60))
        self.threshold = int(self.opt("threshold", 15))
        ports = self.opt("ports", {22: "SSH", 3389: "RDP"})
        self.ports = {int(p): str(n) for p, n in ports.items()}
        self.attempts = WindowCounter(self.window)

    def process(self, pkt: PacketInfo):
        if not pkt.is_syn or pkt.dport not in self.ports:
            return ()
        key = (pkt.src, pkt.dst, pkt.dport)
        n = self.attempts.add(key, pkt.ts)
        if n < self.threshold:
            return ()
        service = self.ports[pkt.dport]
        return [self.alert(
            pkt, title=f"Brute-force {service}", severity="high",
            key=f"{pkt.src}->{pkt.dst}:{pkt.dport}", src=pkt.src, dst=pkt.dst,
            description=f"{pkt.src} mở {n} kết nối {service} tới {pkt.dst} trong {self.window:g}s "
                        "(nghi dò mật khẩu tự động).",
            service=service, dport=pkt.dport, attempts=n)]

    def tick(self, now):
        self.attempts.prune(now)
        return ()
