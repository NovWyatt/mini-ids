"""Các đích nhận alert: console, file JSONL, SQLite, webhook (Discord/Slack/Telegram)."""

from __future__ import annotations

import json
import logging
import queue
import threading
import time
import urllib.request
from datetime import datetime
from pathlib import Path

from rich.console import Console

from mini_ids.alerts import Alert, severity_at_least
from mini_ids.storage import AlertStore

log = logging.getLogger(__name__)

SEVERITY_STYLE = {"low": "cyan", "medium": "yellow", "high": "bold red", "critical": "bold white on red"}


class Sink:
    def emit(self, alert: Alert) -> None:  # pragma: no cover - interface
        raise NotImplementedError

    def update(self, alerts: list[Alert]) -> None:
        """Cập nhật count cho alert đã gửi (do gộp trong cooldown)."""

    def close(self) -> None:
        pass


class ConsoleSink(Sink):
    def __init__(self, console: Console | None = None, min_severity: str = "low"):
        self.console = console or Console(highlight=False)
        self.min_severity = min_severity

    def emit(self, a: Alert) -> None:
        if not severity_at_least(a.severity, self.min_severity):
            return
        t = datetime.fromtimestamp(a.ts).strftime("%H:%M:%S")
        flow = f"{a.src or '?'} → {a.dst}" if a.dst else (a.src or "")
        mitre = f" [dim]{','.join(a.mitre)}[/]" if a.mitre else ""
        self.console.print(
            f"[dim]{t}[/] [{SEVERITY_STYLE[a.severity]}]{a.severity.upper():<8}[/] "
            f"[magenta]{a.detector:<10}[/] [bold]{a.title}[/] [dim]{flow}[/]{mitre}")
        if a.description:
            self.console.print(f"           [dim]└ {a.description}[/]")


class JsonlSink(Sink):
    """1 dòng JSON / alert — định dạng giống Suricata EVE, dễ nạp vào ELK/Splunk/Wazuh."""

    def __init__(self, path: str | Path, max_mb: float = 20):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.max_bytes = int(max_mb * 1024 * 1024)
        self._lock = threading.Lock()

    def emit(self, a: Alert) -> None:
        record = {"timestamp": datetime.fromtimestamp(a.ts).astimezone().isoformat(),
                  "event_type": "alert", **a.to_dict()}
        line = json.dumps(record, ensure_ascii=False, default=str)
        with self._lock:
            if self.path.exists() and self.path.stat().st_size > self.max_bytes:
                self.path.replace(self.path.with_suffix(".jsonl.1"))
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")


class SqliteSink(Sink):
    def __init__(self, store: AlertStore):
        self.store = store

    def emit(self, a: Alert) -> None:
        self.store.insert(a)

    def update(self, alerts: list[Alert]) -> None:
        self.store.update_counts(alerts)


class WebhookSink(Sink):
    """Gửi alert ra chat qua webhook. Chạy thread riêng để không chặn engine."""

    def __init__(self, url: str, kind: str = "discord", min_severity: str = "high",
                 telegram_chat_id: str = "", min_interval: float = 1.0):
        self.url = url
        self.kind = kind
        self.min_severity = min_severity
        self.chat_id = telegram_chat_id
        self.min_interval = min_interval
        self._q: queue.Queue[Alert | None] = queue.Queue(maxsize=200)
        self._thread = threading.Thread(target=self._worker, name="webhook", daemon=True)
        self._thread.start()

    def emit(self, a: Alert) -> None:
        if severity_at_least(a.severity, self.min_severity):
            try:
                self._q.put_nowait(a)
            except queue.Full:
                log.warning("Webhook queue đầy, bỏ alert %s", a.id)

    def format(self, a: Alert) -> dict:
        text = (f"🚨 [{a.severity.upper()}] {a.title}\n{a.src or '?'} → {a.dst or '-'}\n"
                f"{a.description}\nMITRE: {', '.join(a.mitre) or '-'} | detector: {a.detector}")
        if self.kind == "discord":
            # Nội dung alert có thể chứa chuỗi do kẻ tấn công kiểm soát (vd tên DNS "@everyone")
            # → tắt mọi mention để không ai lợi dụng IDS để ping cả server.
            return {"content": text[:1900], "allowed_mentions": {"parse": []}}
        if self.kind == "slack":
            return {"text": text}
        if self.kind == "telegram":
            return {"chat_id": self.chat_id, "text": text}
        return a.to_dict()

    def _worker(self) -> None:
        while True:
            a = self._q.get()
            if a is None:
                return
            body = json.dumps(self.format(a), default=str).encode()
            req = urllib.request.Request(self.url, data=body, headers={
                "Content-Type": "application/json", "User-Agent": "mini-ids"})
            try:
                with urllib.request.urlopen(req, timeout=10):
                    pass
            except Exception as exc:  # mạng lỗi không được làm chết IDS
                log.warning("Gửi webhook thất bại: %s", exc)
            time.sleep(self.min_interval)

    def close(self) -> None:
        try:
            self._q.put_nowait(None)
        except queue.Full:
            pass
