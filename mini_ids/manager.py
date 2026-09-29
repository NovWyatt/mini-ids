"""AlertManager — gộp (dedup), throttle, ghi evidence và phát alert tới các sink.

Không có bước này thì 1 cú SYN flood sinh ra hàng nghìn alert giống hệt → "alert fatigue",
analyst bỏ qua cả alert thật. Quy tắc: cùng (detector, key) trong `cooldown` giây kể từ
alert đầu tiên chỉ tạo 1 alert, các lần sau chỉ tăng `count` và `last_seen`.
"""

from __future__ import annotations

import logging
import threading
from collections import Counter, deque
from typing import Any, Callable

from mini_ids.alerts import Alert
from mini_ids.evidence import EvidenceBuffer
from mini_ids.sinks import Sink

log = logging.getLogger(__name__)

Subscriber = Callable[[str, Any], None]


class AlertManager:
    def __init__(self, cooldown: float = 60, sinks: list[Sink] | None = None,
                 evidence: EvidenceBuffer | None = None, recent: int = 500,
                 evidence_delay: float = 5.0):
        self.cooldown = float(cooldown)
        self.sinks = list(sinks or [])
        self.evidence = evidence
        # Ghi pcap TRỄ vài giây sau alert: lúc alert bật thường mới thấy phần đầu cuộc tấn công
        # (vd FTP: alert ở dòng USER, dòng PASS tới ngay sau) → chờ thêm để evidence đầy đủ hơn.
        self.evidence_delay = float(evidence_delay)
        self._pending_evidence: list[Alert] = []
        self.recent: deque[Alert] = deque(maxlen=recent)
        self.by_severity: Counter[str] = Counter()
        self.by_detector: Counter[str] = Counter()
        self.total = 0
        self.suppressed = 0
        self._active: dict[tuple[str, str], Alert] = {}
        self._dirty: dict[str, Alert] = {}
        self._subs: list[Subscriber] = []
        self._lock = threading.RLock()

    def subscribe(self, fn: Subscriber) -> None:
        with self._lock:
            self._subs.append(fn)

    def unsubscribe(self, fn: Subscriber) -> None:
        with self._lock:
            if fn in self._subs:
                self._subs.remove(fn)

    def _publish(self, event: str, payload: Any) -> None:
        for fn in list(self._subs):
            try:
                fn(event, payload)
            except Exception:
                log.exception("Subscriber lỗi")

    def submit(self, alert: Alert) -> Alert | None:
        """Trả về alert nếu là alert MỚI, None nếu đã bị gộp vào alert trước."""
        with self._lock:
            k = (alert.detector, alert.key)
            prev = self._active.get(k)
            if prev is not None and 0 <= alert.ts - prev.ts < self.cooldown:
                prev.count += 1
                prev.last_seen = max(prev.last_seen, alert.ts)
                self._dirty[prev.id] = prev
                self.suppressed += 1
                return None

            alert.assign_id()
            if self.evidence is not None:
                self._pending_evidence.append(alert)
            self._active[k] = alert
            self.recent.appendleft(alert)
            self.total += 1
            self.by_severity[alert.severity] += 1
            self.by_detector[alert.detector] += 1
            for sink in self.sinks:
                try:
                    sink.emit(alert)
                except Exception:
                    log.exception("Sink %s lỗi", type(sink).__name__)
            self._publish("alert", alert.to_dict())
            return alert

    def flush(self, now: float | None = None) -> None:
        """Ghi evidence đã đủ hạn, đẩy count đã gộp xuống sink, dọn alert hết cooldown.
        now=None: ghi hết evidence đang chờ (khi dừng chương trình)."""
        with self._lock:
            if self._pending_evidence:
                due = [a for a in self._pending_evidence if now is None or now - a.ts >= self.evidence_delay]
                if due:
                    due_ids = {a.id for a in due}
                    self._pending_evidence = [a for a in self._pending_evidence if a.id not in due_ids]
                    for a in due:
                        a.pcap = self.evidence.dump(a)
                        if a.pcap:
                            self._dirty[a.id] = a
            dirty = list(self._dirty.values())
            self._dirty.clear()
            if now is not None:
                stale = [k for k, a in self._active.items() if now - a.last_seen > self.cooldown * 2]
                for k in stale:
                    del self._active[k]
        if not dirty:
            return
        for sink in self.sinks:
            try:
                sink.update(dirty)
            except Exception:
                log.exception("Sink %s lỗi khi update", type(sink).__name__)
        self._publish("alert_update", [{"id": a.id, "count": a.count, "last_seen": a.last_seen,
                                        "pcap": a.pcap} for a in dirty])

    def summary(self) -> dict[str, Any]:
        with self._lock:
            return {"total": self.total, "suppressed": self.suppressed,
                    "by_severity": dict(self.by_severity), "by_detector": dict(self.by_detector)}

    def close(self) -> None:
        self.flush()
        for sink in self.sinks:
            sink.close()
