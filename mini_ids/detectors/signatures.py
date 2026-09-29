"""Signature-based detection — cách Snort/Suricata làm: so khớp payload với mẫu đã biết.

Ưu điểm:  chính xác, ít false positive, giải thích được ("khớp rule 1000006 Log4Shell").
Nhược:    chỉ bắt được cái đã biết (zero-day lọt), mù trước traffic mã hoá (HTTPS/TLS),
          và kẻ tấn công né được bằng encode/obfuscate (%55NION thay cho UNION...).
→ Vì vậy IDS thực tế kết hợp signature + anomaly (xem anomaly.py, ml.py).
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any

import yaml

from mini_ids.detectors.base import Detector
from mini_ids.packet import PacketInfo

log = logging.getLogger(__name__)


def _ports(value: Any) -> frozenset[int] | None:
    if value in (None, "any"):
        return None
    if isinstance(value, (list, tuple, set)):
        return frozenset(int(v) for v in value)
    return frozenset([int(value)])


@dataclass
class Rule:
    id: int
    name: str
    severity: str = "medium"
    proto: str = "any"
    src_port: frozenset[int] | None = None
    dst_port: frozenset[int] | None = None
    src_net: str = "any"
    dst_net: str = "any"
    content: list[bytes] = field(default_factory=list)
    regex: re.Pattern | None = None
    nocase: bool = True
    min_payload: int = 0
    mitre: list[str] = field(default_factory=list)
    description: str = ""
    hits: int = 0

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Rule":
        nocase = bool(d.get("nocase", True))
        content = [str(c).encode() for c in d.get("content", []) or []]
        if nocase:
            content = [c.lower() for c in content]
        regex = None
        if d.get("regex"):
            flags = re.IGNORECASE if nocase else 0
            regex = re.compile(str(d["regex"]).encode(), flags | re.MULTILINE)
        needs_payload = bool(content or regex)
        return cls(
            id=int(d["id"]), name=str(d["name"]), severity=str(d.get("severity", "medium")),
            proto=str(d.get("proto", "any")).lower(), src_port=_ports(d.get("src_port")),
            dst_port=_ports(d.get("dst_port")), src_net=str(d.get("src_net", "any")),
            dst_net=str(d.get("dst_net", "any")), content=content, regex=regex, nocase=nocase,
            min_payload=int(d.get("min_payload", 1 if needs_payload else 0)),
            mitre=list(d.get("mitre", [])), description=str(d.get("description", "")),
        )


class SignatureDetector(Detector):
    name = "signatures"
    title = "Signature rules"
    description = "So khớp header + payload với bộ rule kiểu Snort (config/rules.yaml)."
    mitre = []

    def __init__(self, cfg):
        super().__init__(cfg)
        self.home = cfg.home_net
        self.rules: list[Rule] = []
        path = cfg.path(self.opt("rules_file", "config/rules.yaml"))
        try:
            with open(path, encoding="utf-8") as fh:
                raw = yaml.safe_load(fh) or []
        except FileNotFoundError:
            log.warning("Không tìm thấy file rule %s", path)
            raw = []
        for d in raw:
            try:
                self.rules.append(Rule.from_dict(d))
            except (KeyError, ValueError, re.error) as exc:
                log.error("Rule lỗi %s: %s", d.get("id", "?"), exc)

    def _net_ok(self, want: str, ip: str | None) -> bool:
        if want == "any":
            return True
        inside = ip in self.home
        return inside if want == "home" else not inside

    def match(self, rule: Rule, pkt: PacketInfo) -> bool:
        if rule.proto != "any" and rule.proto != pkt.proto.lower():
            return False
        if rule.dst_port is not None and pkt.dport not in rule.dst_port:
            return False
        if rule.src_port is not None and pkt.sport not in rule.src_port:
            return False
        if len(pkt.payload) < rule.min_payload:
            return False
        if not self._net_ok(rule.src_net, pkt.src) or not self._net_ok(rule.dst_net, pkt.dst):
            return False
        if rule.content:
            data = pkt.payload.lower() if rule.nocase else pkt.payload
            if not all(c in data for c in rule.content):
                return False
        if rule.regex is not None and not rule.regex.search(pkt.payload):
            return False
        return True

    def process(self, pkt: PacketInfo):
        if pkt.proto not in ("TCP", "UDP", "ICMP"):
            return ()
        alerts = []
        for rule in self.rules:
            if not self.match(rule, pkt):
                continue
            # Rule chỉ theo port (không cần payload) → chỉ đếm gói mở kết nối để khỏi báo mỗi gói
            if not rule.min_payload and pkt.proto == "TCP" and not pkt.is_syn:
                continue
            rule.hits += 1
            snippet = pkt.payload[:160].decode("latin-1", errors="replace") if pkt.payload else ""
            alerts.append(self.alert(
                pkt, title=rule.name, severity=rule.severity,
                key=f"{rule.id}:{pkt.src}->{pkt.dst}", src=pkt.src, dst=pkt.dst,
                description=rule.description or f"Khớp signature #{rule.id}.",
                mitre=rule.mitre, sid=rule.id, dport=pkt.dport, payload_snippet=snippet))
        return alerts

    def info(self):
        d = super().info()
        d["rules"] = len(self.rules)
        return d
