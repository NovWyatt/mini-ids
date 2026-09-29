"""Tấn công làm ngập (flood / DoS) và ICMP recon.

SYN flood (T1498/T1499): kẻ tấn công gửi hàng loạt SYN nhưng KHÔNG hoàn tất bắt tay 3 bước
(SYN → SYN/ACK → ACK). Server giữ hàng đợi "half-open" tới khi cạn tài nguyên.
  → Đo 2 chỉ số: tốc độ SYN tới 1 đích, và tỉ lệ ACK/SYN (bắt tay hoàn tất) — flood thì rất thấp.
  → Nhiều IP nguồn khác nhau = gần như chắc chắn IP bị giả mạo (spoofed) hoặc botnet (DDoS).

ICMP:
  * Ping flood — quá nhiều echo-request tới 1 đích.
  * Ping sweep (T1018) — 1 nguồn ping lần lượt cả dải IP để tìm máy đang sống.
  * ICMP payload lớn bất thường — ping thường 32–64 byte; payload lớn có thể là ICMP tunnel.
"""

from __future__ import annotations

from mini_ids.detectors.base import Detector
from mini_ids.packet import PacketInfo
from mini_ids.utils import WindowCounter, WindowDistinct


class SynFloodDetector(Detector):
    name = "synflood"
    title = "SYN flood"
    description = "Tốc độ SYN tới 1 dịch vụ rất cao trong khi bắt tay TCP hầu như không hoàn tất."
    mitre = ["T1498", "T1499"]

    def __init__(self, cfg):
        super().__init__(cfg)
        self.window = float(self.opt("window", 5))
        self.rate_threshold = float(self.opt("rate_threshold", 100))
        self.max_completion = float(self.opt("max_completion_ratio", 0.3))
        self.syns = WindowCounter(self.window)
        self.acks = WindowCounter(self.window)
        self.sources = WindowDistinct(self.window)

    def process(self, pkt: PacketInfo):
        if pkt.proto != "TCP":
            return ()
        target = (pkt.dst, pkt.dport)
        if pkt.flags == "A":
            self.acks.add(target, pkt.ts)
            return ()
        if not pkt.is_syn:
            return ()
        n_syn = self.syns.add(target, pkt.ts)
        n_src = self.sources.add(target, pkt.src, pkt.ts)
        rate = n_syn / self.window
        if rate < self.rate_threshold:
            return ()
        completion = self.acks.count(target, pkt.ts) / n_syn
        if completion > self.max_completion:
            return ()
        distributed = n_src >= 50
        return [self.alert(
            pkt, title="SYN flood" + (" (phân tán / IP giả mạo)" if distributed else ""),
            severity="critical" if distributed else "high",
            key=f"{pkt.dst}:{pkt.dport}", src=None if distributed else pkt.src, dst=pkt.dst,
            description=f"{rate:.0f} SYN/s tới {pkt.dst}:{pkt.dport} từ {n_src} nguồn, "
                        f"chỉ {completion:.0%} bắt tay hoàn tất.",
            syn_rate=round(rate, 1), sources=n_src, completion_ratio=round(completion, 3),
            dport=pkt.dport)]

    def tick(self, now):
        self.syns.prune(now)
        self.acks.prune(now)
        self.sources.prune(now)
        return ()


class IcmpDetector(Detector):
    name = "icmp"
    title = "ICMP flood / ping sweep"
    description = "Ping flood, ping sweep dò host, và ICMP payload lớn bất thường."
    mitre = ["T1018", "T1498"]

    ECHO_REQUEST = 8

    def __init__(self, cfg):
        super().__init__(cfg)
        self.window = float(self.opt("window", 5))
        self.flood_rate = float(self.opt("flood_rate", 50))
        self.sweep_window = float(self.opt("sweep_window", 10))
        self.sweep_threshold = int(self.opt("sweep_threshold", 15))
        self.large_payload = int(self.opt("large_payload", 1024))
        self.echo = WindowCounter(self.window)
        self.sweep = WindowDistinct(self.sweep_window)

    def process(self, pkt: PacketInfo):
        if pkt.proto != "ICMP":
            return ()
        alerts = []
        if len(pkt.payload) >= self.large_payload:
            alerts.append(self.alert(
                pkt, title="ICMP payload lớn bất thường", severity="low",
                key=f"large:{pkt.src}->{pkt.dst}", src=pkt.src, dst=pkt.dst, mitre=["T1095"],
                description=f"Gói ICMP type {pkt.icmp_type} mang {len(pkt.payload)} byte payload "
                            "(ping bình thường ~32-64 byte), nghi ICMP tunnel/exfil.",
                payload_bytes=len(pkt.payload)))
        if pkt.icmp_type != self.ECHO_REQUEST:
            return alerts

        n = self.echo.add(pkt.dst, pkt.ts)
        rate = n / self.window
        if rate >= self.flood_rate:
            alerts.append(self.alert(
                pkt, title="ICMP ping flood", severity="high", key=f"flood:{pkt.dst}",
                src=pkt.src, dst=pkt.dst, mitre=["T1498"],
                description=f"{rate:.0f} echo-request/s tới {pkt.dst}.", rate=round(rate, 1)))

        hosts = self.sweep.add(pkt.src, pkt.dst, pkt.ts)
        if hosts >= self.sweep_threshold:
            alerts.append(self.alert(
                pkt, title="Ping sweep (dò host đang sống)", severity="medium",
                key=f"sweep:{pkt.src}", src=pkt.src, mitre=["T1018"],
                description=f"{pkt.src} ping {hosts} host khác nhau trong {self.sweep_window:g}s.",
                hosts_count=hosts, sample_hosts=sorted(self.sweep.values(pkt.src))[:25]))
        return alerts

    def tick(self, now):
        self.echo.prune(now)
        self.sweep.prune(now)
        return ()
