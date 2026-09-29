"""Mô hình Alert và mức độ nghiêm trọng."""

from __future__ import annotations

import uuid
from dataclasses import asdict, dataclass, field
from typing import Any

SEVERITIES = ("low", "medium", "high", "critical")
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITIES)}


def severity_at_least(severity: str, minimum: str) -> bool:
    return SEVERITY_RANK.get(severity, 0) >= SEVERITY_RANK.get(minimum, 0)


@dataclass
class Alert:
    detector: str
    title: str
    severity: str
    ts: float
    key: str                          # khoá gộp (dedup): cùng detector + key trong cooldown = 1 alert
    src: str | None = None
    dst: str | None = None
    description: str = ""
    mitre: list[str] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)
    id: str = ""
    count: int = 1                    # số lần đã bị gộp
    last_seen: float = 0.0
    pcap: str | None = None
    acked: bool = False

    def __post_init__(self) -> None:
        if self.severity not in SEVERITY_RANK:
            raise ValueError(f"severity không hợp lệ: {self.severity}")
        if not self.last_seen:
            self.last_seen = self.ts

    def assign_id(self) -> None:
        if not self.id:
            self.id = uuid.uuid4().hex[:12]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
