"""Chuẩn hoá gói tin Scapy thành PacketInfo — cấu trúc gọn mà mọi detector dùng chung.

Tách lớp này ra giúp:
  * detector không phụ thuộc Scapy (dễ test: tự dựng PacketInfo giả)
  * parse gói tin đúng 1 lần, không phải mỗi detector tự bóc lại
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from scapy.layers.dns import DNS
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Ether
from scapy.packet import NoPayload, Padding, Raw


@dataclass(slots=True)
class PacketInfo:
    ts: float
    length: int
    proto: str = "OTHER"          # TCP | UDP | ICMP | ICMPv6 | ARP | OTHER
    src: str | None = None
    dst: str | None = None
    sport: int | None = None
    dport: int | None = None
    flags: str = ""                # cờ TCP dạng chữ: S, SA, A, PA, FA, R, FPU...
    ttl: int | None = None
    icmp_type: int | None = None
    icmp_code: int | None = None
    payload: bytes = b""
    dns_qname: str | None = None
    dns_qtype: int | None = None
    dns_rcode: int | None = None
    dns_response: bool = False
    arp_op: int | None = None      # 1 = who-has (request), 2 = is-at (reply)
    arp_hwsrc: str | None = None
    src_mac: str | None = None
    dst_mac: str | None = None
    raw: Any = None                # gói Scapy gốc — dùng để ghi evidence .pcap

    # ---- TCP helpers ----
    @property
    def is_syn(self) -> bool:
        """SYN thuần (mở kết nối mới) — chưa có ACK."""
        return self.proto == "TCP" and "S" in self.flags and "A" not in self.flags

    @property
    def is_synack(self) -> bool:
        return self.proto == "TCP" and "S" in self.flags and "A" in self.flags

    @property
    def is_rst(self) -> bool:
        return self.proto == "TCP" and "R" in self.flags

    @property
    def is_dns_query(self) -> bool:
        return self.dns_qname is not None and not self.dns_response

    def to_dict(self) -> dict[str, Any]:
        return {
            "ts": self.ts, "length": self.length, "proto": self.proto, "src": self.src,
            "dst": self.dst, "sport": self.sport, "dport": self.dport, "flags": self.flags,
        }


def _payload_bytes(layer, limit: int) -> bytes:
    pl = layer.payload
    if isinstance(pl, (NoPayload, Padding)):
        return b""
    raw = layer.getlayer(Raw)
    data = raw.load if raw is not None else bytes(pl)
    return data[:limit]


def from_scapy(pkt, max_payload: int = 2048) -> PacketInfo:
    info = PacketInfo(ts=float(pkt.time), length=len(pkt), raw=pkt)

    if pkt.haslayer(Ether):
        eth = pkt[Ether]
        info.src_mac, info.dst_mac = eth.src, eth.dst

    if pkt.haslayer(ARP):
        arp = pkt[ARP]
        info.proto = "ARP"
        info.arp_op = int(arp.op)
        info.src, info.dst = arp.psrc, arp.pdst
        info.arp_hwsrc = arp.hwsrc
        return info

    if pkt.haslayer(IP):
        ip = pkt[IP]
        info.ttl = ip.ttl
    elif pkt.haslayer(IPv6):
        ip = pkt[IPv6]
        info.ttl = ip.hlim
    else:
        return info
    info.src, info.dst = ip.src, ip.dst

    if pkt.haslayer(TCP):
        tcp = pkt[TCP]
        info.proto = "TCP"
        info.sport, info.dport = int(tcp.sport), int(tcp.dport)
        info.flags = str(tcp.flags)
        info.payload = _payload_bytes(tcp, max_payload)
    elif pkt.haslayer(UDP):
        udp = pkt[UDP]
        info.proto = "UDP"
        info.sport, info.dport = int(udp.sport), int(udp.dport)
        info.payload = _payload_bytes(udp, max_payload)
        if pkt.haslayer(DNS):
            _parse_dns(pkt[DNS], info)
    elif pkt.haslayer(ICMP):
        icmp = pkt[ICMP]
        info.proto = "ICMP"
        info.icmp_type, info.icmp_code = int(icmp.type), int(icmp.code)
        info.payload = _payload_bytes(icmp, max_payload)
    elif isinstance(ip, IPv6) and ip.nh == 58:  # ICMPv6
        info.proto = "ICMPv6"
        info.icmp_type = int(getattr(ip.payload, "type", -1))
    return info


def _parse_dns(dns, info: PacketInfo) -> None:
    qd = dns.qd
    if isinstance(qd, list):  # Scapy >= 2.6: qd là list DNSQR
        if not qd:
            return
        q = qd[0]
    elif qd is None:
        return
    else:
        q = qd
    qname = q.qname
    info.dns_qname = qname.decode(errors="replace") if isinstance(qname, bytes) else str(qname)
    info.dns_qtype = int(q.qtype)
    info.dns_rcode = int(dns.rcode)
    info.dns_response = bool(dns.qr)
