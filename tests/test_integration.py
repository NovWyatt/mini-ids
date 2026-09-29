"""Test end-to-end: gói Scapy giả lập → engine → alert. Kiểm tra mỗi kịch bản tấn công bị
đúng detector bắt, và traffic bình thường không sinh cảnh báo."""

import pytest
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Raw

from mini_ids.alerts import Alert
from mini_ids.capture.synthetic import SyntheticTraffic
from mini_ids.engine import Engine
from mini_ids.evidence import EvidenceBuffer
from mini_ids.manager import AlertManager
from mini_ids.packet import from_scapy

START = 1_700_000_000.0
WARMUP = 40.0
GAP = 10.0


# ------------------------------------------------------------------ parse
def test_from_scapy_tcp_http():
    p = Ether() / IP(src="1.2.3.4", dst="5.6.7.8", ttl=50) / TCP(sport=1234, dport=80, flags="PA") / Raw(b"GET / HTTP/1.1")
    p.time = 10.5
    info = from_scapy(p)
    assert (info.proto, info.src, info.dport, info.flags, info.ttl) == ("TCP", "1.2.3.4", 80, "PA", 50)
    assert info.payload.startswith(b"GET /") and info.ts == 10.5 and not info.is_syn


def test_from_scapy_dns_arp_icmp():
    q = IP(src="10.0.0.5", dst="10.0.0.1") / UDP(sport=5353, dport=53) / DNS(rd=1, qd=DNSQR(qname="a.example.com", qtype="TXT"))
    info = from_scapy(q)
    assert info.dns_qname == "a.example.com." and info.dns_qtype == 16 and info.is_dns_query
    a = from_scapy(Ether() / ARP(op=2, psrc="10.0.0.1", hwsrc="aa:bb:cc:dd:ee:ff", pdst="10.0.0.5"))
    assert (a.proto, a.arp_op, a.src, a.arp_hwsrc) == ("ARP", 2, "10.0.0.1", "aa:bb:cc:dd:ee:ff")
    i = from_scapy(IP(src="1.1.1.1", dst="2.2.2.2") / ICMP(type=8) / Raw(b"x" * 32))
    assert (i.proto, i.icmp_type, len(i.payload)) == ("ICMP", 8, 32)


# ------------------------------------------------------------------ dedup
def test_alert_manager_dedup_and_cooldown():
    events = []
    m = AlertManager(cooldown=60)
    m.subscribe(lambda kind, payload: events.append(kind))
    mk = lambda ts: Alert(detector="d", title="t", severity="high", ts=ts, key="k")
    assert m.submit(mk(100)) is not None
    assert m.submit(mk(110)) is None            # trong cooldown → gộp
    assert m.submit(mk(150)) is None
    first = m.recent[0]
    assert first.count == 3 and first.last_seen == 150
    assert m.submit(mk(170)) is not None        # quá cooldown từ alert đầu → alert mới
    m.flush()
    assert events.count("alert") == 2 and "alert_update" in events


# ------------------------------------------------------------------ kịch bản end-to-end
@pytest.fixture(scope="module")
def attack_run(tmp_path_factory):
    from mini_ids.config import PROJECT_ROOT, Config
    tmp = tmp_path_factory.mktemp("run")
    cfg = Config.load(PROJECT_ROOT / "config" / "demo.yaml")
    cfg.override({"detectors": {"ml": {"model_file": str(tmp / "m.json")}}})
    gen = SyntheticTraffic(seed=11, start=START)
    names = list(gen.scenarios)
    alerts = AlertManager(cooldown=60, evidence=EvidenceBuffer(tmp / "ev"))
    eng = Engine(cfg, alerts)
    for p in gen.timeline(warmup=WARMUP, gap=GAP, scenarios=names):
        eng.process_raw(p)
    eng.finish()
    return gen, names, list(alerts.recent), eng


SCENARIOS = list(SyntheticTraffic(seed=0).scenarios)


@pytest.mark.parametrize("name", SCENARIOS)
def test_scenario_detected(attack_run, name):
    gen, names, alerts, _ = attack_run
    start = START + WARMUP + names.index(name) * GAP
    expected = set(gen.scenarios[name][1])
    hits = [a for a in alerts if a.detector in expected and start - 1 <= a.ts <= start + GAP + 20]
    assert hits, f"{name}: không detector nào trong {expected} báo"


def test_no_alert_before_attacks(attack_run):
    _, _, alerts, _ = attack_run
    early = [a for a in alerts if a.ts < START + WARMUP - 1]
    assert early == [], [f"{a.detector}: {a.title}" for a in early]


def test_evidence_pcap_written(attack_run):
    _, _, alerts, _ = attack_run
    with_pcap = [a for a in alerts if a.pcap]
    assert with_pcap
    from scapy.utils import rdpcap
    assert len(rdpcap(with_pcap[0].pcap)) > 0


def test_normal_traffic_is_quiet(cfg):
    """3 phút traffic bình thường không được sinh bất kỳ cảnh báo nào (kể cả ML)."""
    gen = SyntheticTraffic(seed=5, start=START)
    alerts = AlertManager(cooldown=60)
    eng = Engine(cfg, alerts)
    for p in gen.timeline(duration=180, warmup=10_000, scenarios=[]):
        eng.process_raw(p)
    eng._run_tick(eng.clock + 1)
    assert alerts.total == 0, [f"{a.detector}: {a.description}" for a in alerts.recent]
    assert eng.detector("ml").model is not None, "ML phải học xong baseline"
