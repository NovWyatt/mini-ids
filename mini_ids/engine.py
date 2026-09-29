"""Engine — trái tim của IDS: nhận gói → cập nhật thống kê → chạy từng detector → phát alert.

    capture ──► from_scapy() ──► PacketInfo ──┬──► TrafficStats (dashboard)
                                              ├──► EvidenceBuffer (pcap cho alert)
                                              └──► detector 1..N ──► AlertManager ──► sinks
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Any

from mini_ids.config import Config
from mini_ids.detectors import Detector, build_detectors
from mini_ids.manager import AlertManager
from mini_ids.packet import PacketInfo, from_scapy
from mini_ids.stats import TrafficStats

log = logging.getLogger(__name__)


class Engine:
    def __init__(self, cfg: Config, alerts: AlertManager, detectors: list[Detector] | None = None):
        self.config = cfg
        self.alerts = alerts
        self.detectors = detectors if detectors is not None else build_detectors(cfg)
        self.stats = TrafficStats(home_net=cfg.home_net)
        self.max_payload = int(cfg.section("capture").get("max_payload", 2048))
        self.packets = 0
        self.parse_errors = 0
        self.clock = 0.0              # thời gian của gói mới nhất (packet time)
        self.proc_time = 0.0          # tổng thời gian xử lý — đo hiệu năng
        self._last_tick: int | None = None
        self._lock = threading.RLock()

    # ------------------------------------------------------------------ input
    def process_raw(self, scapy_pkt) -> None:
        try:
            info = from_scapy(scapy_pkt, self.max_payload)
        except Exception:
            self.parse_errors += 1
            log.debug("Không parse được gói tin", exc_info=True)
            return
        self.process(info)

    def process(self, pkt: PacketInfo) -> None:
        t0 = time.perf_counter()
        with self._lock:
            self.packets += 1
            sec = int(pkt.ts)
            if self._last_tick is None:
                self._last_tick = sec
            elif sec > self._last_tick:
                self._run_tick(pkt.ts)
            self.clock = max(self.clock, pkt.ts)
            self.stats.update(pkt)
            if self.alerts.evidence is not None:
                self.alerts.evidence.add(pkt)
            for det in self.detectors:
                if not det.enabled:
                    continue
                try:
                    out = det.process(pkt)
                except Exception:
                    log.exception("Detector %s lỗi", det.name)
                    continue
                for alert in out or ():
                    self.alerts.submit(alert)
        self.proc_time += time.perf_counter() - t0

    # ------------------------------------------------------------------ clock
    def tick(self, now: float | None = None) -> None:
        """Gọi định kỳ (~1s) khi chạy realtime để detector xử lý cả lúc không có gói tin."""
        with self._lock:
            now = max(now if now is not None else self.clock, self.clock)
            if self._last_tick is not None and int(now) <= self._last_tick:
                return
            self._run_tick(now)

    def _run_tick(self, now: float) -> None:
        self._last_tick = int(now)
        for det in self.detectors:
            if not det.enabled:
                continue
            try:
                out = det.tick(now)
            except Exception:
                log.exception("Detector %s lỗi khi tick", det.name)
                continue
            for alert in out or ():
                self.alerts.submit(alert)
        self.alerts.flush(now)

    def finish(self) -> None:
        """Kết thúc replay: đẩy thời gian đi xa để flow/bucket còn dở được xử lý nốt."""
        with self._lock:
            if self._last_tick is not None:
                self._run_tick(self.clock + 1)
                self._run_tick(self.clock + 3600)

    # ------------------------------------------------------------------ info
    def detector(self, name: str) -> Detector | None:
        return next((d for d in self.detectors if d.name == name), None)

    def status(self) -> dict[str, Any]:
        with self._lock:
            return {
                "packets": self.packets,
                "parse_errors": self.parse_errors,
                "clock": self.clock,
                "avg_us_per_packet": round(self.proc_time / self.packets * 1e6, 1) if self.packets else 0,
                "detectors": [d.info() for d in self.detectors],
                "alerts": self.alerts.summary(),
            }
