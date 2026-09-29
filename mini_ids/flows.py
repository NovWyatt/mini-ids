"""Flow table — gom các gói tin thành "cuộc hội thoại" (flow) theo 5-tuple.

5-tuple = (protocol, IP nguồn, port nguồn, IP đích, port đích). Hai chiều của cùng 1
kết nối được gộp làm 1 flow (bidirectional), chiều "fwd" là chiều của gói đầu tiên.
Đây chính là cách NetFlow/IPFIX, Zeek conn.log, CICFlowMeter hoạt động.
"""

from __future__ import annotations

import math
from collections import OrderedDict
from dataclasses import dataclass, field

from mini_ids.packet import PacketInfo

FEATURE_NAMES = [
    "log_duration", "log_fwd_pkts", "log_bwd_pkts", "log_fwd_bytes", "log_bwd_bytes",
    "mean_fwd_size", "syn_ratio", "rst", "fin", "no_reply", "dport_class", "proto",
]
_PROTO_CODE = {"TCP": 0, "UDP": 1, "ICMP": 2, "ICMPv6": 2}


@dataclass
class Flow:
    proto: str
    src: str
    sport: int
    dst: str
    dport: int
    first: float
    last: float
    fwd_pkts: int = 0
    bwd_pkts: int = 0
    fwd_bytes: int = 0
    bwd_bytes: int = 0
    syn: int = 0
    rst: int = 0
    fin: int = 0
    flags_seen: set[str] = field(default_factory=set)

    def features(self) -> list[float]:
        dport = self.dport or 0
        dport_class = 0 if dport < 1024 else (1 if dport < 49152 else 2)
        total = self.fwd_pkts + self.bwd_pkts
        return [
            math.log1p(max(self.last - self.first, 0.0)),
            math.log1p(self.fwd_pkts),
            math.log1p(self.bwd_pkts),
            math.log1p(self.fwd_bytes),
            math.log1p(self.bwd_bytes),
            self.fwd_bytes / self.fwd_pkts if self.fwd_pkts else 0.0,
            self.syn / total if total else 0.0,
            1.0 if self.rst else 0.0,
            1.0 if self.fin else 0.0,
            1.0 if self.bwd_pkts == 0 else 0.0,
            float(dport_class),
            float(_PROTO_CODE.get(self.proto, 3)),
        ]

    def summary(self) -> dict:
        return {"proto": self.proto, "src": self.src, "sport": self.sport, "dst": self.dst,
                "dport": self.dport, "duration": round(self.last - self.first, 3),
                "fwd_pkts": self.fwd_pkts, "bwd_pkts": self.bwd_pkts,
                "fwd_bytes": self.fwd_bytes, "bwd_bytes": self.bwd_bytes}


class FlowTable:
    def __init__(self, idle_timeout: float = 15.0, max_flows: int = 50000):
        self.idle_timeout = idle_timeout
        self.max_flows = max_flows
        self.flows: OrderedDict[tuple, Flow] = OrderedDict()
        self._evicted: list[Flow] = []

    @staticmethod
    def _key(pkt: PacketInfo) -> tuple:
        a = (pkt.src, pkt.sport or 0)
        b = (pkt.dst, pkt.dport or 0)
        return (pkt.proto,) + (a + b if a <= b else b + a)

    def update(self, pkt: PacketInfo) -> None:
        if pkt.proto not in _PROTO_CODE or not pkt.src or not pkt.dst:
            return
        key = self._key(pkt)
        flow = self.flows.get(key)
        if flow is None:
            flow = Flow(pkt.proto, pkt.src, pkt.sport or 0, pkt.dst, pkt.dport or 0, pkt.ts, pkt.ts)
            self.flows[key] = flow
            if len(self.flows) > self.max_flows:
                _, old = self.flows.popitem(last=False)
                self._evicted.append(old)
        else:
            self.flows.move_to_end(key)
        flow.last = max(flow.last, pkt.ts)
        if pkt.src == flow.src and (pkt.sport or 0) == flow.sport:
            flow.fwd_pkts += 1
            flow.fwd_bytes += pkt.length
        else:
            flow.bwd_pkts += 1
            flow.bwd_bytes += pkt.length
        if pkt.proto == "TCP":
            if "S" in pkt.flags:
                flow.syn += 1
            if "R" in pkt.flags:
                flow.rst += 1
            if "F" in pkt.flags:
                flow.fin += 1

    def expire(self, now: float, force: bool = False) -> list[Flow]:
        """Trả về các flow đã im lặng quá idle_timeout (hoặc tất cả nếu force)."""
        done, self._evicted = self._evicted, []
        cutoff = now - self.idle_timeout
        while self.flows:
            key, flow = next(iter(self.flows.items()))
            if not force and flow.last >= cutoff:
                break
            self.flows.popitem(last=False)
            done.append(flow)
        return done

    def __len__(self) -> int:
        return len(self.flows)
