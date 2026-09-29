"""Port scan (dò cổng) — MITRE ATT&CK T1046 Network Service Discovery.

Dấu hiệu:
  * Vertical scan:   1 nguồn gửi SYN/UDP tới NHIỀU PORT trên 1 host trong thời gian ngắn.
  * Horizontal scan: 1 nguồn gõ CÙNG 1 PORT trên NHIỀU HOST (tìm máy mở SSH, SMB...).
  * Stealth scan:    gói TCP có tổ hợp cờ bất thường mà client bình thường không bao giờ gửi:
                       NULL (không cờ), FIN đơn lẻ, XMAS (FIN+PSH+URG) — nmap -sN / -sF / -sX.
"""

from __future__ import annotations

from mini_ids.detectors.base import Detector
from mini_ids.packet import PacketInfo
from mini_ids.utils import WindowDistinct


def stealth_scan_type(flags: str) -> str | None:
    f = set(flags)
    if not f:
        return "NULL"
    if f == {"F"}:
        return "FIN"
    if {"F", "P", "U"} <= f and "S" not in f and "A" not in f:
        return "XMAS"
    return None


class PortScanDetector(Detector):
    name = "portscan"
    title = "Port scan"
    description = "Một nguồn dò nhiều port/host trong thời gian ngắn, hoặc dùng cờ TCP stealth."
    mitre = ["T1046"]

    def __init__(self, cfg):
        super().__init__(cfg)
        window = self.opt("window", 10)
        self.vertical_threshold = int(self.opt("vertical_threshold", 20))
        self.horizontal_threshold = int(self.opt("horizontal_threshold", 20))
        self.horizontal_ignore = set(self.opt("horizontal_ignore_ports", [53, 80, 123, 443]))
        self.vertical = WindowDistinct(window)     # key (src, dst)  -> distinct dport
        self.horizontal = WindowDistinct(window)   # key (src, dport) -> distinct dst
        self.window = window

    def process(self, pkt: PacketInfo):
        if pkt.proto == "TCP":
            stealth = stealth_scan_type(pkt.flags)
            if stealth:
                return [self.alert(
                    pkt, title=f"TCP {stealth} scan", severity="medium",
                    key=f"stealth:{stealth}:{pkt.src}", src=pkt.src, dst=pkt.dst,
                    description=f"Gói TCP cờ '{pkt.flags or 'none'}': kiểu {stealth} scan "
                                f"(nmap -s{stealth[0]}), client bình thường không gửi tổ hợp này.",
                    scan_type=stealth, dport=pkt.dport)]
            if not pkt.is_syn:
                return ()
        elif pkt.proto != "UDP" or pkt.dns_response:
            return ()
        if pkt.dport is None:
            return ()
        # UDP trả lời từ port dịch vụ (<1024, vd DNS/QUIC 443) về port tạm (ephemeral) của client
        # trông giống "dò nhiều port" nhưng thật ra là response — bỏ qua để tránh false positive.
        if pkt.proto == "UDP" and pkt.sport is not None and pkt.sport < 1024 <= pkt.dport:
            return ()

        alerts = []
        n_ports = self.vertical.add((pkt.src, pkt.dst), pkt.dport, pkt.ts)
        if n_ports >= self.vertical_threshold:
            ports = sorted(self.vertical.values((pkt.src, pkt.dst)))
            alerts.append(self.alert(
                pkt, title="Vertical port scan", severity="high",
                key=f"v:{pkt.src}->{pkt.dst}", src=pkt.src, dst=pkt.dst,
                description=f"{pkt.src} dò {n_ports} port khác nhau trên {pkt.dst} "
                            f"trong {self.window:g}s ({pkt.proto}).",
                ports_count=n_ports, sample_ports=ports[:25], proto=pkt.proto))

        if pkt.dport not in self.horizontal_ignore:
            n_hosts = self.horizontal.add((pkt.src, pkt.dport), pkt.dst, pkt.ts)
            if n_hosts >= self.horizontal_threshold:
                hosts = sorted(self.horizontal.values((pkt.src, pkt.dport)))
                alerts.append(self.alert(
                    pkt, title="Horizontal scan (port sweep)", severity="high",
                    key=f"h:{pkt.src}:{pkt.dport}", src=pkt.src,
                    description=f"{pkt.src} gõ port {pkt.dport}/{pkt.proto.lower()} trên "
                                f"{n_hosts} host khác nhau trong {self.window:g}s.",
                    dport=pkt.dport, hosts_count=n_hosts, sample_hosts=hosts[:25]))
        return alerts

    def tick(self, now):
        self.vertical.prune(now)
        self.horizontal.prune(now)
        return ()
