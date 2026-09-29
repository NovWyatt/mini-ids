"""ARP spoofing / poisoning — MITRE T1557.002 (Adversary-in-the-Middle: ARP Cache Poisoning).

ARP không có xác thực: bất kỳ máy nào cũng có thể nói "IP 192.168.1.1 (router) là MAC của tôi".
Nạn nhân tin và gửi toàn bộ traffic ra Internet qua máy kẻ tấn công (MITM).

Cách phát hiện:
  * Lập bảng IP → MAC từ mọi gói ARP thấy được. Nếu 1 IP bỗng đổi sang MAC khác → cảnh báo.
  * 1 MAC tự nhận là chủ của nhiều IP → dấu hiệu MITM/proxy ARP.
  * Quá nhiều ARP reply không ai hỏi (gratuitous) → đang "đầu độc" liên tục.
  * 1 máy hỏi ARP cho cả dải IP → ARP scan (dò host trong LAN, T1018).
"""

from __future__ import annotations

from mini_ids.detectors.base import Detector
from mini_ids.packet import PacketInfo
from mini_ids.utils import WindowCounter, WindowDistinct

_IGNORED_IPS = {"0.0.0.0"}
_IGNORED_MACS = {"00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"}


class ArpSpoofDetector(Detector):
    name = "arp"
    title = "ARP spoofing"
    description = "IP đổi MAC bất thường, 1 MAC nhận nhiều IP, ARP reply flood, ARP scan."
    mitre = ["T1557.002"]

    def __init__(self, cfg):
        super().__init__(cfg)
        window = float(self.opt("window", 10))
        self.reply_flood_threshold = int(self.opt("reply_flood_threshold", 30))
        self.scan_threshold = int(self.opt("scan_threshold", 50))
        self.multi_ip_threshold = int(self.opt("multi_ip_threshold", 5))
        self.table: dict[str, tuple[str, float]] = {}   # ip -> (mac, last_seen)
        self.mac_ips: dict[str, set[str]] = {}
        self.replies = WindowCounter(window)
        self.requests = WindowDistinct(window)
        self.window = window

    def process(self, pkt: PacketInfo):
        if pkt.proto != "ARP":
            return ()
        ip, mac = pkt.src, (pkt.arp_hwsrc or "").lower()
        if not ip or ip in _IGNORED_IPS or not mac or mac in _IGNORED_MACS:
            return ()

        alerts = []
        known = self.table.get(ip)
        if known and known[0] != mac:
            alerts.append(self.alert(
                pkt, title="ARP spoofing: IP đổi địa chỉ MAC", severity="high",
                key=f"spoof:{ip}", src=ip,
                description=f"{ip} trước đây là {known[0]}, nay {mac} tự nhận là {ip}. "
                            "Nếu IP này là gateway, traffic của cả mạng có thể đang bị nghe lén (MITM).",
                ip=ip, old_mac=known[0], new_mac=mac))
        self.table[ip] = (mac, pkt.ts)

        ips = self.mac_ips.setdefault(mac, set())
        ips.add(ip)
        if len(ips) >= self.multi_ip_threshold:
            alerts.append(self.alert(
                pkt, title="1 MAC nhận là chủ nhiều IP", severity="medium",
                key=f"multi:{mac}",
                description=f"MAC {mac} đã khai báo {len(ips)} IP khác nhau.",
                mac=mac, ips=sorted(ips)[:25]))

        if pkt.arp_op == 2:
            n = self.replies.add(mac, pkt.ts)
            if n >= self.reply_flood_threshold:
                alerts.append(self.alert(
                    pkt, title="ARP reply flood", severity="medium", key=f"flood:{mac}",
                    description=f"{mac} gửi {n} ARP reply trong {self.window:g}s: "
                                "dấu hiệu tool đầu độc ARP (arpspoof, ettercap, bettercap).",
                    mac=mac, replies=n))
        elif pkt.arp_op == 1 and pkt.dst:
            n = self.requests.add(ip, pkt.dst, pkt.ts)
            if n >= self.scan_threshold:
                alerts.append(self.alert(
                    pkt, title="ARP scan (dò host trong LAN)", severity="low",
                    key=f"scan:{ip}", src=ip, mitre=["T1018"],
                    description=f"{ip} hỏi ARP cho {n} IP khác nhau trong {self.window:g}s.",
                    targets=n))
        return alerts

    def tick(self, now):
        self.replies.prune(now)
        self.requests.prune(now)
        return ()

    def snapshot(self) -> dict[str, str]:
        return {ip: mac for ip, (mac, _) in self.table.items()}
