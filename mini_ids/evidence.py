"""Evidence — lưu các gói tin liên quan tới alert ra file .pcap để mở bằng Wireshark.

IDS chỉ nói "có vấn đề"; analyst cần xem gói tin gốc để xác minh (triage). Ta giữ
ring buffer N gói gần nhất; khi có alert thì lọc gói liên quan tới IP nguồn/đích và ghi pcap.
"""

from __future__ import annotations

import logging
from collections import deque
from pathlib import Path

from scapy.utils import wrpcap

from mini_ids.alerts import Alert
from mini_ids.packet import PacketInfo

log = logging.getLogger(__name__)


class EvidenceBuffer:
    def __init__(self, directory: str | Path, maxlen: int = 5000, per_alert: int = 400):
        self.dir = Path(directory)
        self.buffer: deque[PacketInfo] = deque(maxlen=maxlen)
        self.per_alert = per_alert

    def add(self, pkt: PacketInfo) -> None:
        if pkt.raw is not None:
            self.buffer.append(pkt)

    def dump(self, alert: Alert) -> str | None:
        ips = {ip for ip in (alert.src, alert.dst) if ip}
        if not ips:
            return None
        # Có cả src và dst → chỉ lấy hội thoại giữa 2 bên; chỉ có 1 bên → mọi gói dính tới bên đó
        if len(ips) == 2:
            match = lambda p: p.src in ips and p.dst in ips
        else:
            match = lambda p: p.src in ips or p.dst in ips
        pkts = [p.raw for p in list(self.buffer) if match(p)][-self.per_alert:]
        if not pkts:
            return None
        self.dir.mkdir(parents=True, exist_ok=True)
        path = self.dir / f"{alert.id}.pcap"
        try:
            wrpcap(str(path), pkts)
        except (OSError, ValueError) as exc:
            log.warning("Không ghi được evidence %s: %s", path, exc)
            return None
        return str(path)
