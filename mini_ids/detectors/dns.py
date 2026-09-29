"""DNS bất thường — tunneling (T1071.004), DGA (T1568.002), exfiltration qua DNS (T1048).

DNS gần như luôn được phép đi ra ngoài firewall → kẻ tấn công lợi dụng làm kênh bí mật:
  * DNS tunneling: nhét dữ liệu (đã base32/hex) vào subdomain:
        MZXW6YTBOI.GEZDGNBV.t.attacker.com  → tên rất dài, entropy cao,
        số subdomain KHÁC NHAU dưới cùng 1 domain tăng vọt, hay dùng bản ghi TXT.
  * DGA (Domain Generation Algorithm): malware sinh hàng trăm domain ngẫu nhiên để tìm C2,
        hầu hết không tồn tại → nhiều phản hồi NXDOMAIN.
"""

from __future__ import annotations

from mini_ids.detectors.base import Detector
from mini_ids.packet import PacketInfo
from mini_ids.utils import (WindowCounter, WindowDistinct, base_domain, domain_matches,
                            shannon_entropy, subdomain_part)

QTYPE_TXT = 16
RCODE_NXDOMAIN = 3


class DnsAnomalyDetector(Detector):
    name = "dns"
    title = "DNS tunneling / DGA"
    description = "Query DNS quá dài, entropy cao, nhiều subdomain lạ, nhiều NXDOMAIN hoặc TXT."
    mitre = ["T1071.004", "T1568.002"]

    def __init__(self, cfg):
        super().__init__(cfg)
        self.max_len = int(self.opt("max_query_length", 60))
        self.entropy_min_len = int(self.opt("entropy_min_length", 20))
        self.entropy_threshold = float(self.opt("entropy_threshold", 3.8))
        window = float(self.opt("window", 60))
        self.unique_threshold = int(self.opt("unique_subdomain_threshold", 40))
        self.nx_threshold = int(self.opt("nxdomain_threshold", 20))
        self.txt_threshold = int(self.opt("txt_threshold", 30))
        self.allow = [d.lower() for d in self.opt("allow_domains", [])]
        self.subdomains = WindowDistinct(window)   # (client, base domain) -> distinct subdomain
        self.nxdomain = WindowCounter(window)      # client -> số NXDOMAIN
        self.txt = WindowCounter(window)
        self.window = window

    def process(self, pkt: PacketInfo):
        if pkt.dns_qname is None:
            return ()
        qname = pkt.dns_qname.rstrip(".").lower()
        if not qname or domain_matches(qname, self.allow):
            return ()
        base = base_domain(qname)

        if pkt.dns_response:
            if pkt.dns_rcode == RCODE_NXDOMAIN and pkt.dst:
                n = self.nxdomain.add(pkt.dst, pkt.ts)
                if n >= self.nx_threshold:
                    return [self.alert(
                        pkt, title="Quá nhiều NXDOMAIN (nghi DGA malware)", severity="high",
                        key=f"nx:{pkt.dst}", src=pkt.dst, mitre=["T1568.002"],
                        description=f"{pkt.dst} nhận {n} phản hồi NXDOMAIN trong {self.window:g}s: "
                                    "malware DGA thử hàng loạt domain ngẫu nhiên để tìm máy chủ C2.",
                        nxdomain=n, last_query=qname)]
            return ()

        client = pkt.src
        alerts = []
        sub = subdomain_part(qname)
        longest_label = max((len(p) for p in qname.split(".")), default=0)
        if len(qname) > self.max_len or longest_label > 50:
            alerts.append(self.alert(
                pkt, title="DNS query dài bất thường", severity="medium",
                key=f"long:{client}:{base}", src=client, dst=pkt.dst,
                description=f"Query dài {len(qname)} ký tự (label dài nhất {longest_label}) tới *.{base}.",
                query=qname[:200], length=len(qname)))

        compact = sub.replace(".", "")
        if len(compact) >= self.entropy_min_len:
            ent = shannon_entropy(compact)
            if ent >= self.entropy_threshold:
                alerts.append(self.alert(
                    pkt, title="Subdomain entropy cao (nghi dữ liệu mã hoá)", severity="medium",
                    key=f"entropy:{client}:{base}", src=client, dst=pkt.dst,
                    description=f"Subdomain '{sub[:60]}' có entropy {ent:.2f} bit/ký tự, "
                                "giống dữ liệu base32/hex hơn là tên do người đặt.",
                    query=qname[:200], entropy=round(ent, 3)))

        if sub:
            n = self.subdomains.add((client, base), sub, pkt.ts)
            if n >= self.unique_threshold:
                alerts.append(self.alert(
                    pkt, title="DNS tunneling", severity="high",
                    key=f"tunnel:{client}:{base}", src=client, dst=pkt.dst, mitre=["T1071.004", "T1048"],
                    description=f"{client} hỏi {n} subdomain khác nhau của {base} trong {self.window:g}s.",
                    base_domain=base, unique_subdomains=n, sample=qname[:200]))

        if pkt.dns_qtype == QTYPE_TXT:
            n = self.txt.add(client, pkt.ts)
            if n >= self.txt_threshold:
                alerts.append(self.alert(
                    pkt, title="Nhiều truy vấn DNS TXT", severity="medium",
                    key=f"txt:{client}", src=client, dst=pkt.dst,
                    description=f"{client} gửi {n} query TXT trong {self.window:g}s "
                                "(TXT chứa được nhiều dữ liệu → hay dùng cho tunnel/C2).",
                    txt_queries=n))
        return alerts

    def tick(self, now):
        self.subdomains.prune(now)
        self.nxdomain.prune(now)
        self.txt.prune(now)
        return ()
