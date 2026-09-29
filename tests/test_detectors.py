"""Unit test từng detector với PacketInfo tự dựng (không cần Scapy/capture)."""

from mini_ids.detectors.anomaly import TrafficAnomalyDetector
from mini_ids.detectors.arp import ArpSpoofDetector
from mini_ids.detectors.beacon import BeaconDetector
from mini_ids.detectors.blacklist import BlacklistDetector
from mini_ids.detectors.bruteforce import BruteForceDetector
from mini_ids.detectors.dns import DnsAnomalyDetector
from mini_ids.detectors.exfil import ExfilDetector
from mini_ids.detectors.flood import IcmpDetector, SynFloodDetector
from mini_ids.detectors.portscan import PortScanDetector, stealth_scan_type
from tests.conftest import pkt


def run(det, packets):
    out = []
    for p in packets:
        out += list(det.process(p))
    return out


# ------------------------------------------------------------------ port scan
def test_vertical_scan_detected(cfg):
    det = PortScanDetector(cfg)
    alerts = run(det, [pkt(ts=100 + i * 0.05, dport=1 + i) for i in range(25)])
    assert any(a.title == "Vertical port scan" for a in alerts)
    assert alerts[0].src == "10.0.0.5" and "T1046" in alerts[0].mitre


def test_normal_browsing_is_not_a_scan(cfg):
    det = PortScanDetector(cfg)
    # 1 client mở kết nối HTTPS tới 40 server khác nhau: bình thường khi lướt web
    packets = [pkt(ts=100 + i * 0.1, dst=f"93.184.{i}.1", dport=443) for i in range(40)]
    assert run(det, packets) == []


def test_udp_responses_are_not_counted(cfg):
    det = PortScanDetector(cfg)
    # DNS/QUIC server trả lời về nhiều port tạm của client
    packets = [pkt(ts=100 + i * 0.1, proto="UDP", src="1.1.1.1", dst="10.0.0.5", sport=443,
                   dport=50000 + i) for i in range(40)]
    assert run(det, packets) == []


def test_stealth_flags():
    assert stealth_scan_type("") == "NULL"
    assert stealth_scan_type("F") == "FIN"
    assert stealth_scan_type("FPU") == "XMAS"
    assert stealth_scan_type("FA") is None
    assert stealth_scan_type("S") is None


# ------------------------------------------------------------------ floods
def test_syn_flood_needs_low_completion(cfg):
    det = SynFloodDetector(cfg)
    flood = [pkt(ts=100 + i * 0.002, src=f"44.{i % 250}.{i // 250}.1", dst="10.0.0.9", dport=80)
             for i in range(1200)]
    alerts = run(det, flood)
    assert alerts and alerts[-1].severity == "critical"     # nhiều nguồn = phân tán
    assert alerts[-1].evidence["completion_ratio"] < 0.3


def test_busy_server_with_completed_handshakes_is_ok(cfg):
    det = SynFloodDetector(cfg)
    packets = []
    for i in range(1000):
        t = 100 + i * 0.002
        packets.append(pkt(ts=t, src=f"44.0.{i % 250}.1", dport=80, flags="S"))
        packets.append(pkt(ts=t + 0.001, src=f"44.0.{i % 250}.1", dport=80, flags="A"))
    assert run(det, packets) == []


def test_icmp_sweep_and_flood(cfg):
    det = IcmpDetector(cfg)
    sweep = [pkt(ts=100 + i * 0.1, proto="ICMP", dst=f"10.0.0.{i}", sport=None, dport=None, icmp_type=8)
             for i in range(1, 20)]
    assert any("sweep" in a.title.lower() for a in run(det, sweep))
    flood = [pkt(ts=200 + i * 0.005, proto="ICMP", dst="10.0.0.9", sport=None, dport=None, icmp_type=8)
             for i in range(400)]
    assert any("flood" in a.title.lower() for a in run(det, flood))


# ------------------------------------------------------------------ ARP
def test_arp_spoof_mac_change(cfg):
    det = ArpSpoofDetector(cfg)
    legit = pkt(ts=100, proto="ARP", src="10.0.0.1", dst="10.0.0.5", sport=None, dport=None,
                arp_op=2, arp_hwsrc="00:11:22:33:44:01")
    spoof = pkt(ts=101, proto="ARP", src="10.0.0.1", dst="10.0.0.5", sport=None, dport=None,
                arp_op=2, arp_hwsrc="de:ad:be:ef:00:01")
    assert run(det, [legit, legit]) == []
    alerts = run(det, [spoof])
    assert alerts and alerts[0].evidence["old_mac"] == "00:11:22:33:44:01"
    assert "T1557.002" in alerts[0].mitre


# ------------------------------------------------------------------ DNS
def dns_q(ts, name, qtype=1, src="10.0.0.5"):
    return pkt(ts=ts, proto="UDP", src=src, dst="10.0.0.1", sport=53000, dport=53,
               dns_qname=name + ".", dns_qtype=qtype, dns_response=False)


def test_dns_tunnel(cfg):
    det = DnsAnomalyDetector(cfg)
    import base64
    qs = [dns_q(100 + i * 0.1, base64.b32encode(f"secret-chunk-{i:04d}-data".encode()).decode().lower().rstrip("=")
                + ".t.evil.example", qtype=16) for i in range(45)]
    titles = {a.title for a in run(det, qs)}
    assert "DNS tunneling" in titles
    assert any("entropy" in t for t in titles)


def test_normal_dns_is_quiet(cfg):
    det = DnsAnomalyDetector(cfg)
    names = ["www.google.com", "github.com", "api.github.com", "vnexpress.net", "mail.google.com"]
    assert run(det, [dns_q(100 + i, names[i % 5]) for i in range(100)]) == []


def test_dga_nxdomain(cfg):
    det = DnsAnomalyDetector(cfg)
    resp = [pkt(ts=100 + i * 0.1, proto="UDP", src="10.0.0.1", dst="10.0.0.5", sport=53, dport=53000,
                dns_qname=f"x{i}qz8k2j.com.", dns_qtype=1, dns_rcode=3, dns_response=True) for i in range(25)]
    assert any("NXDOMAIN" in a.title for a in run(det, resp))


# ------------------------------------------------------------------ brute force / blacklist
def test_ssh_bruteforce(cfg):
    det = BruteForceDetector(cfg)
    alerts = run(det, [pkt(ts=100 + i, dport=22) for i in range(20)])
    assert alerts and alerts[0].title == "Brute-force SSH"


def test_blacklist_ip_and_domain(cfg):
    det = BlacklistDetector(cfg)
    assert run(det, [pkt(dst="203.0.113.66", dport=443)])
    assert run(det, [dns_q(100, "update.malware-c2.example")])
    assert run(det, [pkt(dst="8.8.8.8", dport=443)]) == []


# ------------------------------------------------------------------ exfil / beacon / anomaly
def test_exfil(cfg):
    det = ExfilDetector(cfg)   # demo profile: 5 MB
    big = [pkt(ts=100 + i * 0.01, src="192.168.1.30", dst="198.51.100.200", dport=443, flags="PA",
               length=40000) for i in range(140)]
    assert any(a.detector == "exfil" for a in run(det, big))
    # tải VỀ nhiều thì không phải exfil
    down = [pkt(ts=100 + i * 0.01, src="198.51.100.200", dst="192.168.1.30", sport=443, dport=50000,
                flags="PA", length=40000) for i in range(300)]
    assert run(ExfilDetector(cfg), down) == []


def test_beacon_regular_vs_random(cfg):
    import random
    det = BeaconDetector(cfg)
    regular = [pkt(ts=100 + i * 30.0 + random.uniform(-0.3, 0.3), src="192.168.1.20",
                   dst="203.0.113.200", dport=8443) for i in range(8)]
    assert run(det, regular)
    rng = random.Random(1)
    t, human = 100.0, []
    for _ in range(15):
        t += rng.expovariate(1 / 20)
        human.append(pkt(ts=t, src="192.168.1.20", dst="140.82.113.3", dport=443))
    assert run(BeaconDetector(cfg), human) == []


def test_traffic_spike(cfg):
    det = TrafficAnomalyDetector(cfg)
    alerts = []
    ts = 1000.0
    for sec in range(60):                     # baseline ~50 gói/giây
        for i in range(50):
            alerts += det.process(pkt(ts=ts + sec + i / 50))
    assert alerts == []
    for i in range(2000):                     # rồi vọt lên 2000 gói/giây
        alerts += det.process(pkt(ts=ts + 60 + i / 2000))
    alerts += det.tick(ts + 62)
    assert alerts and alerts[0].evidence["z_pps"] > 5
