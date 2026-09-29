import logging
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.getLogger("scapy.loading").setLevel(logging.ERROR)

from mini_ids.config import PROJECT_ROOT, Config  # noqa: E402
from mini_ids.packet import PacketInfo  # noqa: E402


@pytest.fixture
def cfg(tmp_path) -> Config:
    """Config demo nhưng mọi output ghi vào thư mục tạm."""
    c = Config.load(PROJECT_ROOT / "config" / "demo.yaml", use_local=False)
    c.override({
        "logging": {"dir": str(tmp_path / "logs")},
        "evidence": {"dir": str(tmp_path / "evidence")},
        "detectors": {"ml": {"model_file": str(tmp_path / "model.json")}},
    })
    return c


def pkt(ts=1000.0, proto="TCP", src="10.0.0.5", dst="10.0.0.9", sport=40000, dport=80,
        flags="S", length=60, **kw) -> PacketInfo:
    return PacketInfo(ts=ts, length=length, proto=proto, src=src, dst=dst, sport=sport,
                      dport=dport, flags=flags if proto == "TCP" else "", **kw)
