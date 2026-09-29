"""Runtime — lắp ráp các thành phần từ config và điều khiển vòng đời (start/stop)."""

from __future__ import annotations

import logging
import threading
import time
from logging.handlers import RotatingFileHandler
from typing import Any

from rich.console import Console

from mini_ids.capture import PacketSource
from mini_ids.config import Config
from mini_ids.engine import Engine
from mini_ids.evidence import EvidenceBuffer
from mini_ids.manager import AlertManager
from mini_ids.sinks import ConsoleSink, JsonlSink, SqliteSink, WebhookSink
from mini_ids.storage import AlertStore

log = logging.getLogger("mini_ids")


def setup_logging(cfg: Config, verbose: bool = False) -> None:
    lcfg = cfg.section("logging")
    log_dir = cfg.path(lcfg.get("dir", "logs"))
    log_dir.mkdir(parents=True, exist_ok=True)
    root = logging.getLogger("mini_ids")
    if any(isinstance(h, RotatingFileHandler) for h in root.handlers):
        return
    root.setLevel(logging.DEBUG if verbose else logging.INFO)
    fh = RotatingFileHandler(log_dir / lcfg.get("app_log", "mini_ids.log"),
                             maxBytes=5 * 1024 * 1024, backupCount=3, encoding="utf-8")
    fh.setFormatter(logging.Formatter("%(asctime)s %(levelname)-7s %(name)s: %(message)s"))
    root.addHandler(fh)


class Runtime:
    def __init__(self, cfg: Config, source: PacketSource, console: Console | None = None,
                 print_alerts: bool = True):
        self.config = cfg
        self.source = source
        self.console = console or Console(highlight=False)
        self.started = time.time()
        self.error: str | None = None
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []

        lcfg = cfg.section("logging")
        log_dir = cfg.path(lcfg.get("dir", "logs"))
        self.store = AlertStore(log_dir / lcfg.get("database", "ids.db"))
        sinks = [SqliteSink(self.store),
                 JsonlSink(log_dir / lcfg.get("alerts_jsonl", "alerts.jsonl"),
                           lcfg.get("jsonl_max_mb", 20))]
        acfg = cfg.section("alerting")
        if print_alerts and acfg.get("console", True):
            sinks.append(ConsoleSink(self.console, acfg.get("min_console_severity", "low")))
        wh = acfg.get("webhook", {}) or {}
        if wh.get("enabled") and wh.get("url"):
            sinks.append(WebhookSink(wh["url"], wh.get("kind", "discord"), wh.get("min_severity", "high"),
                                     str(wh.get("telegram_chat_id", ""))))

        ecfg = cfg.section("evidence")
        evidence = None
        if ecfg.get("enabled", True):
            evidence = EvidenceBuffer(cfg.path(ecfg.get("dir", "evidence")),
                                      int(ecfg.get("buffer_packets", 5000)),
                                      int(ecfg.get("max_packets_per_alert", 400)))
        self.alerts = AlertManager(float(acfg.get("cooldown_seconds", 60)), sinks, evidence,
                                   evidence_delay=float(ecfg.get("delay_seconds", 5)))
        self.engine = Engine(cfg, self.alerts)

    # ------------------------------------------------------------------
    @property
    def running(self) -> bool:
        return bool(self._threads) and self._threads[0].is_alive()

    def now(self) -> float:
        """Thời điểm 'hiện tại' cho dashboard: giờ thật khi live/demo, giờ gói tin khi replay."""
        if self.source.wall_clock:
            return time.time()
        return self.engine.clock or time.time()

    def _run_source(self) -> None:
        try:
            self.source.run(self.engine.process_raw, self._stop)
        except Exception as exc:
            self.error = str(exc)
            log.error("Capture dừng: %s", exc)
            self.console.print(f"[bold red]Capture lỗi:[/] {exc}")
        finally:
            if not self.source.wall_clock:
                self.engine.finish()

    def _ticker(self) -> None:
        while not self._stop.wait(1.0):
            self.engine.tick(time.time())

    def start(self) -> None:
        t = threading.Thread(target=self._run_source, name="capture", daemon=True)
        t.start()
        self._threads = [t]
        if self.source.wall_clock:
            tk = threading.Thread(target=self._ticker, name="ticker", daemon=True)
            tk.start()
            self._threads.append(tk)

    def wait(self) -> None:
        """Chờ tới khi nguồn gói hết (replay) hoặc Ctrl+C."""
        try:
            while self._threads and self._threads[0].is_alive():
                self._threads[0].join(0.5)
        except KeyboardInterrupt:
            pass

    def stop(self) -> None:
        self._stop.set()
        for t in self._threads:
            t.join(3)
        self.alerts.close()

    def status(self) -> dict[str, Any]:
        s = self.engine.status()
        s.update(mode=self.source.kind, source=self.source.description, started=self.started,
                 uptime=time.time() - self.started, running=self.running, error=self.error,
                 now=self.now())
        return s
