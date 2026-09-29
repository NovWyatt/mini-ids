"""Test API dashboard + CLI gen-pcap → replay."""

import time

import pytest
from fastapi.testclient import TestClient

from mini_ids.capture import PcapSource
from mini_ids.cli import main
from mini_ids.runtime import Runtime
from mini_ids.web.server import create_app


@pytest.fixture(scope="module")
def pcap_file(tmp_path_factory):
    out = tmp_path_factory.mktemp("pcap") / "t.pcap"
    assert main(["gen-pcap", str(out), "--scenarios", "portscan,web_attacks,ssh_bruteforce",
                 "--warmup", "8", "--gap", "6"]) == 0
    return out


@pytest.fixture
def runtime(cfg, pcap_file):
    rt = Runtime(cfg, PcapSource(pcap_file), print_alerts=False)
    rt.start()
    deadline = time.time() + 30
    while rt.running and time.time() < deadline:
        time.sleep(0.05)
    yield rt
    rt.stop()


def test_replay_produces_alerts(runtime):
    detectors = {r["detector"] for r in runtime.store.query()}
    assert {"portscan", "signatures", "bruteforce"} <= detectors


def test_api(runtime):
    client = TestClient(create_app(runtime))
    s = client.get("/api/status").json()
    assert s["mode"] == "replay" and s["packets"] > 0 and not s["running"]
    assert "Content-Security-Policy" in client.get("/").headers

    st = client.get("/api/stats?seconds=60").json()
    assert len(st["series"]["t"]) == len(st["series"]["pps"]) and st["totals"]["packets"] == s["packets"]

    alerts = client.get("/api/alerts?severity=high").json()
    assert alerts and all(a["severity"] == "high" for a in alerts)
    a = alerts[0]
    assert client.get(f"/api/alerts/{a['id']}").json()["id"] == a["id"]
    assert client.post(f"/api/alerts/{a['id']}/ack").json()["acked"] is True
    assert client.get(f"/api/alerts/{a['id']}").json()["acked"] is True
    assert client.get("/api/alerts/khong-ton-tai").status_code == 404

    with_pcap = next(x for x in client.get("/api/alerts").json() if x["pcap"])
    r = client.get(f"/api/alerts/{with_pcap['id']}/pcap")
    assert r.status_code == 200 and r.content[:4] in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4")


def test_pcap_download_rejects_paths_outside_evidence(runtime):
    a = runtime.store.query(limit=1)[0]
    a_obj = runtime.alerts.recent[0]
    a_obj.id, a_obj.pcap = a["id"], str(runtime.config.base_dir / "pyproject.toml")
    runtime.store.insert(a_obj)          # giả lập DB bị sửa trỏ ra ngoài thư mục evidence
    client = TestClient(create_app(runtime))
    assert client.get(f"/api/alerts/{a['id']}/pcap").status_code == 404


def test_websocket_pushes_stats(runtime):
    with TestClient(create_app(runtime)) as client:
        with client.websocket_connect("/ws") as ws:
            msg = ws.receive_json()
            assert msg["type"] == "stats" and "series" in msg["data"]["stats"]
