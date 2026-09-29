"""Threat intelligence — đối chiếu IP/domain với danh sách đen (IOC: Indicator of Compromise).

Đây là cách phát hiện đơn giản nhất nhưng hiệu quả: nếu máy trong mạng nói chuyện với
IP của botnet C2 đã biết, gần như chắc chắn có vấn đề. Nguồn feed miễn phí:
abuse.ch Feodo Tracker, Spamhaus DROP, Emerging Threats... (xem: mini-ids intel update).
"""

from __future__ import annotations

from mini_ids.detectors.base import Detector
from mini_ids.packet import PacketInfo
from mini_ids.utils import NetSet, domain_matches, load_list_file


class BlacklistDetector(Detector):
    name = "blacklist"
    title = "Threat intel (blacklist)"
    description = "Liên lạc với IP/domain nằm trong danh sách đen."
    mitre = ["T1071"]

    def __init__(self, cfg):
        super().__init__(cfg)
        self.ips = NetSet()
        for f in self.opt("ip_files", []):
            for entry in load_list_file(cfg.path(f)):
                self.ips.add(entry)
        self.domains: list[str] = []
        for f in self.opt("domain_files", []):
            self.domains += [d.lower().rstrip(".") for d in load_list_file(cfg.path(f))]

    def process(self, pkt: PacketInfo):
        alerts = []
        if pkt.proto != "ARP" and self.ips:
            for ip, role in ((pkt.dst, "đích"), (pkt.src, "nguồn")):
                if ip in self.ips:
                    peer = pkt.src if role == "đích" else pkt.dst
                    alerts.append(self.alert(
                        pkt, title="Liên lạc với IP trong blacklist", severity="high",
                        key=f"ip:{ip}:{peer}", src=pkt.src, dst=pkt.dst,
                        description=f"IP {role} {ip} nằm trong danh sách đen (peer: {peer}, "
                                    f"{pkt.proto}{'/' + str(pkt.dport) if pkt.dport else ''}).",
                        ioc=ip, direction=role))
                    break
        if pkt.is_dns_query and self.domains:
            hit = domain_matches(pkt.dns_qname or "", self.domains)
            if hit:
                alerts.append(self.alert(
                    pkt, title="Truy vấn domain trong blacklist", severity="high",
                    key=f"dom:{pkt.src}:{hit}", src=pkt.src, dst=pkt.dst,
                    description=f"{pkt.src} phân giải {pkt.dns_qname} (khớp IOC {hit}).",
                    ioc=hit, query=pkt.dns_qname))
        return alerts
