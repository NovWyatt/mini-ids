"""Tiện ích dùng chung: cửa sổ thời gian trượt, entropy, xử lý IP/domain."""

from __future__ import annotations

import ipaddress
import math
from collections import Counter, defaultdict, deque
from functools import lru_cache
from typing import Hashable, Iterable


# ---------------------------------------------------------------------------
# Sliding window — nền tảng của hầu hết detector dựa trên ngưỡng (threshold).
# Ý tưởng: chỉ quan tâm sự kiện trong `window` giây gần nhất, sự kiện cũ bị đẩy ra.
# ---------------------------------------------------------------------------
class WindowCounter:
    """Đếm số sự kiện theo key trong `window` giây gần nhất."""

    def __init__(self, window: float):
        self.window = float(window)
        self._events: dict[Hashable, deque[float]] = defaultdict(deque)

    def add(self, key: Hashable, ts: float) -> int:
        dq = self._events[key]
        dq.append(ts)
        self._trim(dq, ts)
        return len(dq)

    def count(self, key: Hashable, now: float) -> int:
        dq = self._events.get(key)
        if not dq:
            return 0
        self._trim(dq, now)
        return len(dq)

    def _trim(self, dq: deque[float], now: float) -> None:
        cutoff = now - self.window
        while dq and dq[0] < cutoff:
            dq.popleft()

    def prune(self, now: float) -> None:
        for key in list(self._events):
            dq = self._events[key]
            self._trim(dq, now)
            if not dq:
                del self._events[key]

    def __len__(self) -> int:
        return len(self._events)


class WindowSum:
    """Cộng dồn giá trị (vd: số byte) theo key trong cửa sổ trượt."""

    def __init__(self, window: float):
        self.window = float(window)
        self._events: dict[Hashable, deque[tuple[float, float]]] = defaultdict(deque)
        self._sums: dict[Hashable, float] = defaultdict(float)

    def add(self, key: Hashable, ts: float, value: float) -> float:
        dq = self._events[key]
        dq.append((ts, value))
        self._sums[key] += value
        self._trim(key, ts)
        return self._sums[key]

    def _trim(self, key: Hashable, now: float) -> None:
        dq = self._events[key]
        cutoff = now - self.window
        while dq and dq[0][0] < cutoff:
            _, v = dq.popleft()
            self._sums[key] -= v

    def prune(self, now: float) -> None:
        for key in list(self._events):
            self._trim(key, now)
            if not self._events[key]:
                del self._events[key]
                self._sums.pop(key, None)


class WindowDistinct:
    """Đếm số giá trị KHÁC NHAU theo key trong cửa sổ trượt.

    Ví dụ port scan: key = IP nguồn, value = port đích → 1 IP chạm tới bao nhiêu port.
    """

    def __init__(self, window: float):
        self.window = float(window)
        self._last: dict[Hashable, dict[Hashable, float]] = defaultdict(dict)
        self._order: dict[Hashable, deque[tuple[float, Hashable]]] = defaultdict(deque)

    def add(self, key: Hashable, value: Hashable, ts: float) -> int:
        self._last[key][value] = ts
        self._order[key].append((ts, value))
        self._trim(key, ts)
        return len(self._last[key])

    def values(self, key: Hashable) -> list[Hashable]:
        return list(self._last.get(key, {}))

    def _trim(self, key: Hashable, now: float) -> None:
        last = self._last[key]
        order = self._order[key]
        cutoff = now - self.window
        while order and order[0][0] < cutoff:
            t, v = order.popleft()
            if last.get(v) == t:
                del last[v]

    def prune(self, now: float) -> None:
        for key in list(self._order):
            self._trim(key, now)
            if not self._last[key]:
                del self._last[key]
                del self._order[key]

    def __len__(self) -> int:
        return len(self._last)


# ---------------------------------------------------------------------------
# Entropy & domain
# ---------------------------------------------------------------------------
def shannon_entropy(text: str) -> float:
    """Entropy Shannon (bit/ký tự). Chữ tiếng Anh ~2.5–3.5, chuỗi base32/base64 ngẫu nhiên ~4–5."""
    if not text:
        return 0.0
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in Counter(text).values())


# Hậu tố 2 cấp hay gặp — xấp xỉ Public Suffix List cho gọn.
_MULTI_SUFFIXES = {
    "com.vn", "net.vn", "org.vn", "edu.vn", "gov.vn", "co.uk", "org.uk", "ac.uk",
    "com.au", "net.au", "co.jp", "ne.jp", "com.br", "com.cn", "co.kr", "com.sg",
}


def base_domain(qname: str) -> str:
    """'a.b.example.com.' -> 'example.com' (xấp xỉ eTLD+1)."""
    labels = [p for p in qname.lower().rstrip(".").split(".") if p]
    if len(labels) <= 2:
        return ".".join(labels)
    if ".".join(labels[-2:]) in _MULTI_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def subdomain_part(qname: str) -> str:
    """Phần đứng trước base domain: 'x1y2.tunnel.example.com' -> 'x1y2.tunnel'."""
    name = qname.lower().rstrip(".")
    base = base_domain(name)
    return name[: -len(base)].rstrip(".") if name.endswith(base) and name != base else ""


def domain_matches(qname: str, domains: Iterable[str]) -> str | None:
    name = qname.lower().rstrip(".")
    for d in domains:
        if name == d or name.endswith("." + d):
            return d
    return None


# ---------------------------------------------------------------------------
# IP networks
# ---------------------------------------------------------------------------
class NetSet:
    """Tập các IP/CIDR, kiểm tra 'ip in netset' có cache."""

    def __init__(self, entries: Iterable[str] = ()):
        self.networks: list[ipaddress._BaseNetwork] = []
        for e in entries:
            self.add(e)
        self._contains = lru_cache(maxsize=65536)(self._contains_uncached)

    def add(self, entry: str) -> bool:
        entry = entry.strip()
        if not entry or entry.startswith("#"):
            return False
        try:
            self.networks.append(ipaddress.ip_network(entry, strict=False))
        except ValueError:
            return False
        if hasattr(self, "_contains"):
            self._contains.cache_clear()
        return True

    def _contains_uncached(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr in net for net in self.networks if net.version == addr.version)

    def __contains__(self, ip: object) -> bool:
        return isinstance(ip, str) and self._contains(ip)

    def __len__(self) -> int:
        return len(self.networks)


def load_list_file(path) -> list[str]:
    """Đọc file danh sách (1 mục/dòng, bỏ comment #)."""
    try:
        with open(path, encoding="utf-8") as fh:
            return [ln.split("#", 1)[0].strip() for ln in fh if ln.split("#", 1)[0].strip()]
    except FileNotFoundError:
        return []


# Tên dịch vụ theo port — để hiển thị cho dễ đọc
SERVICES = {
    20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 67: "DHCP",
    68: "DHCP", 80: "HTTP", 110: "POP3", 123: "NTP", 137: "NetBIOS", 138: "NetBIOS",
    139: "NetBIOS", 143: "IMAP", 161: "SNMP", 389: "LDAP", 443: "HTTPS", 445: "SMB",
    465: "SMTPS", 587: "SMTP", 853: "DoT", 993: "IMAPS", 995: "POP3S", 1433: "MSSQL",
    1900: "SSDP", 3306: "MySQL", 3389: "RDP", 5353: "mDNS", 5432: "PostgreSQL",
    5900: "VNC", 6379: "Redis", 8080: "HTTP-alt", 8443: "HTTPS-alt",
}


def service_name(port: int | None) -> str | None:
    return SERVICES.get(port) if port is not None else None
