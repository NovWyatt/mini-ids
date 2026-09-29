"""Lớp nền cho mọi detector."""

from __future__ import annotations

from typing import Any, ClassVar, Iterable

from mini_ids.alerts import Alert
from mini_ids.config import Config
from mini_ids.packet import PacketInfo


class Detector:
    """Mỗi detector nhận từng PacketInfo và trả về danh sách Alert (có thể rỗng).

    * process(pkt): gọi cho MỌI gói tin — phải nhanh, O(1) nếu được.
    * tick(now):    gọi ~1 lần/giây — dọn state cũ, xử lý việc theo chu kỳ.
    """

    name: ClassVar[str] = "base"
    title: ClassVar[str] = ""
    description: ClassVar[str] = ""
    mitre: ClassVar[list[str]] = []

    def __init__(self, cfg: Config):
        self.config = cfg
        self.opts: dict[str, Any] = cfg.detector(self.name)
        self.enabled: bool = bool(self.opts.get("enabled", True))
        self.fired = 0

    def opt(self, key: str, default: Any) -> Any:
        return self.opts.get(key, default)

    def process(self, pkt: PacketInfo) -> Iterable[Alert]:
        return ()

    def tick(self, now: float) -> Iterable[Alert]:
        return ()

    def alert(self, pkt_or_ts: PacketInfo | float, *, title: str, severity: str, key: str,
              src: str | None = None, dst: str | None = None, description: str = "",
              mitre: list[str] | None = None, **evidence: Any) -> Alert:
        ts = pkt_or_ts.ts if isinstance(pkt_or_ts, PacketInfo) else float(pkt_or_ts)
        self.fired += 1
        return Alert(
            detector=self.name, title=title, severity=severity, ts=ts, key=key, src=src, dst=dst,
            description=description, mitre=list(mitre if mitre is not None else self.mitre),
            evidence=evidence,
        )

    def info(self) -> dict[str, Any]:
        return {"name": self.name, "title": self.title, "description": self.description,
                "mitre": self.mitre, "enabled": self.enabled, "fired": self.fired}
