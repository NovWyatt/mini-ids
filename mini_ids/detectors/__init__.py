"""Registry các detector. Thêm detector mới: viết class kế thừa Detector rồi đưa vào ALL."""

from __future__ import annotations

from mini_ids.config import Config
from mini_ids.detectors.anomaly import TrafficAnomalyDetector
from mini_ids.detectors.arp import ArpSpoofDetector
from mini_ids.detectors.base import Detector
from mini_ids.detectors.beacon import BeaconDetector
from mini_ids.detectors.blacklist import BlacklistDetector
from mini_ids.detectors.bruteforce import BruteForceDetector
from mini_ids.detectors.dns import DnsAnomalyDetector
from mini_ids.detectors.exfil import ExfilDetector
from mini_ids.detectors.flood import IcmpDetector, SynFloodDetector
from mini_ids.detectors.ml import MLAnomalyDetector
from mini_ids.detectors.portscan import PortScanDetector
from mini_ids.detectors.signatures import SignatureDetector

ALL: list[type[Detector]] = [
    SignatureDetector,
    BlacklistDetector,
    PortScanDetector,
    SynFloodDetector,
    IcmpDetector,
    ArpSpoofDetector,
    DnsAnomalyDetector,
    BruteForceDetector,
    ExfilDetector,
    BeaconDetector,
    TrafficAnomalyDetector,
    MLAnomalyDetector,
]


def build_detectors(cfg: Config) -> list[Detector]:
    return [cls(cfg) for cls in ALL]


__all__ = ["ALL", "Detector", "build_detectors"]
