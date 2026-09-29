"""Nguồn gói tin. Mọi source có cùng interface: run(callback, stop_event)."""

from __future__ import annotations

import logging
import threading
import time
from pathlib import Path
from typing import Callable

log = logging.getLogger(__name__)

PacketCallback = Callable[[object], None]


class PacketSource:
    kind = "base"
    description = ""
    wall_clock = True   # True: thời gian gói ~ thời gian thực (live/demo)

    def run(self, callback: PacketCallback, stop: threading.Event) -> None:  # pragma: no cover
        raise NotImplementedError


def npcap_available() -> bool:
    from scapy.config import conf
    return bool(getattr(conf, "use_pcap", False))


def list_interfaces() -> list[dict]:
    from scapy.interfaces import get_working_ifaces
    out = []
    for iface in get_working_ifaces():
        out.append({"name": iface.name, "description": getattr(iface, "description", ""),
                    "ip": getattr(iface, "ip", None), "mac": getattr(iface, "mac", None)})
    return out


class LiveSource(PacketSource):
    """Bắt gói trực tiếp từ card mạng (Windows cần Npcap — cài kèm Wireshark)."""

    kind = "live"

    def __init__(self, interface: str | None = None, bpf_filter: str = ""):
        self.interface = interface
        self.bpf_filter = bpf_filter or None
        self.description = f"live:{interface or 'default'}"

    def run(self, callback, stop):
        from scapy.sendrecv import AsyncSniffer
        if not npcap_available():
            raise RuntimeError(
                "Không có libpcap/Npcap nên không bắt gói trực tiếp được.\n"
                "  → Cài Wireshark (tick 'Install Npcap') hoặc Npcap từ https://npcap.com\n"
                "  → Trong lúc chờ, thử: mini-ids demo  hoặc  mini-ids replay file.pcap")
        sniffer = AsyncSniffer(iface=self.interface, filter=self.bpf_filter, prn=callback, store=False)
        sniffer.start()
        try:
            while not stop.wait(0.5):
                if not sniffer.running:
                    raise RuntimeError("Sniffer dừng bất ngờ (sai tên interface hoặc thiếu quyền?)")
        finally:
            if sniffer.running:
                sniffer.stop()


class PcapSource(PacketSource):
    """Đọc lại file .pcap/.pcapng (xuất từ Wireshark/tcpdump). speed=0: nhanh nhất có thể."""

    kind = "replay"
    wall_clock = False

    def __init__(self, path: str | Path, speed: float = 0.0):
        self.path = Path(path)
        self.speed = speed
        self.description = f"replay:{self.path.name}"
        self.done = False

    def run(self, callback, stop):
        from scapy.utils import PcapReader
        if not self.path.exists():
            raise FileNotFoundError(self.path)
        first_ts = wall0 = None
        with PcapReader(str(self.path)) as reader:
            for pkt in reader:
                if stop.is_set():
                    break
                if self.speed > 0:
                    ts = float(pkt.time)
                    if first_ts is None:
                        first_ts, wall0 = ts, time.monotonic()
                    delay = (ts - first_ts) / self.speed - (time.monotonic() - wall0)
                    if delay > 0 and stop.wait(delay):
                        break
                callback(pkt)
        self.done = True


class DemoSource(PacketSource):
    """Traffic giả lập chạy theo thời gian thực — không cần card mạng / Npcap."""

    kind = "demo"

    def __init__(self, seed: int | None = None, warmup: float = 30.0, gap: float = 8.0,
                 scenarios: list[str] | None = None):
        self.seed, self.warmup, self.gap, self.scenarios = seed, warmup, gap, scenarios
        self.description = "demo:synthetic"

    def run(self, callback, stop):
        from mini_ids.capture.synthetic import SyntheticTraffic
        gen = SyntheticTraffic(seed=self.seed)
        for pkt in gen.timeline(warmup=self.warmup, gap=self.gap, scenarios=self.scenarios, loop=True):
            delay = float(pkt.time) - time.time()
            if delay > 0 and stop.wait(delay):
                break
            if stop.is_set():
                break
            callback(pkt)
