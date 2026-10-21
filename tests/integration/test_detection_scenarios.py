"""
Phase 4 exit tests: labelled DDoS and scan scenarios through the full pipeline.

- Each attack scenario raises its expected DDoS/scan classes — and no other
  DDoS/scan class — for five seeds.
- The benign scenario built to trip naive rules (quiet gaps, a large download,
  CDN browsing, many connections to one server, a DNS burst, a flash crowd)
  raises no DDoS/scan alert for five seeds.
- Attack PCAPs go through the real file path (reader → sessionizer → window →
  detectors) and raise the right alert, also via the replay API.

Other detectors (beaconing, exfiltration, DNS, anomaly) are out of scope here;
see the audit repair log for their remaining false positives.
"""

from __future__ import annotations

import shutil
import time

import pytest

from unishield.data import sample_files
from unishield.data.sample_generator import SimulatedReader, build_scenario
from unishield.ingest.pcap_reader import PcapReader
from unishield.processing.pipeline import Pipeline

pytestmark = pytest.mark.integration

DDOS_SCAN = {"DDOS_VOLUMETRIC", "SYN_FLOOD", "UDP_FLOOD", "PORT_SCAN", "HOST_SCAN", "RECONNAISSANCE"}
SEEDS = [1, 2, 3, 4, 5]


def ddos_scan_classes(result) -> set[str]:
    return {a.threat_class.value for a in result.alerts} & DDOS_SCAN


@pytest.mark.parametrize("seed", SEEDS)
@pytest.mark.parametrize("name", ["ddos_syn", "ddos_udp", "port_scan", "host_sweep"])
def test_attack_scenario_raises_exactly_its_classes(name, seed):
    scenario = build_scenario(name, seed)
    result = Pipeline(enable_correlation=False).run(SimulatedReader(scenario.flows))
    assert result.errors == 0
    assert ddos_scan_classes(result) == scenario.expected_classes


@pytest.mark.parametrize("seed", SEEDS)
def test_hard_benign_scenario_raises_no_ddos_or_scan_alert(seed):
    scenario = build_scenario("benign_hard", seed)
    result = Pipeline(enable_correlation=False).run(SimulatedReader(scenario.flows))
    assert ddos_scan_classes(result) == set()


@pytest.fixture(scope="module")
def attack_pcaps(tmp_path_factory):
    d = tmp_path_factory.mktemp("attack_pcaps")
    return {
        "portscan": sample_files.write_port_scan_pcap(d / "attack_portscan.pcap"),
        "synflood": sample_files.write_syn_flood_pcap(d / "attack_synflood.pcap"),
    }


def test_port_scan_pcap_raises_port_scan(attack_pcaps):
    result = Pipeline(enable_correlation=False).run(PcapReader(attack_pcaps["portscan"]))
    scans = [a for a in result.alerts if a.threat_class.value == "PORT_SCAN"]
    assert scans and {(a.source_ip, a.destination_ip) for a in scans} == \
        {(sample_files.SCANNER, sample_files.SCAN_TARGET)}
    assert ddos_scan_classes(result) == {"PORT_SCAN"}


def test_syn_flood_pcap_raises_syn_flood(attack_pcaps):
    result = Pipeline(enable_correlation=False).run(PcapReader(attack_pcaps["synflood"]))
    floods = [a for a in result.alerts if a.threat_class.value == "SYN_FLOOD"]
    assert floods and {a.destination_ip for a in floods} == {"192.168.1.100"}
    assert floods[0].evidence["distributed"] is True
    assert result.ingest["sessionizer"]["flows_out"] == 3000


def test_benign_sample_pcap_raises_no_ddos_or_scan_alert(sample_capture):
    result = Pipeline(enable_correlation=False).run(PcapReader(sample_capture.path))
    assert result.total_windows >= 1            # short capture is analysed (D1)
    assert ddos_scan_classes(result) == set()


# ---------------------------------------------------------------- via the API

@pytest.fixture
def api(api_client):
    yield api_client
    _wait(api_client[0])


def _wait(client, timeout=60.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        status = client.get("/replay/status").json()
        if status["status"] != "running":
            return status
        time.sleep(0.05)
    raise AssertionError("replay did not finish")


def test_port_scan_pcap_alert_reaches_the_api(api, attack_pcaps):
    client, data_dir = api
    target = data_dir / "attack_portscan.pcap"
    shutil.copy(attack_pcaps["portscan"], target)
    assert client.post("/replay/start", params={"file_path": str(target)}).status_code == 200
    assert _wait(client)["status"] == "completed"
    alerts = client.get("/alerts").json()
    assert any(a["threat_class"] == "PORT_SCAN" and a["source_type"] == "pcap_file" for a in alerts)


def test_demo_endpoint_shows_ddos_and_scan(api):
    client, _ = api
    body = client.post("/replay/demo", params={"normal": 300, "ddos": 6000, "scan": 150,
                                               "beacon": 30, "exfil": 40, "seed": 42, "wait": True}).json()
    assert body["status"] == "completed"
    classes = set(body["result"]["alerts_by_class"])
    assert {"SYN_FLOOD", "UDP_FLOOD", "DDOS_VOLUMETRIC", "PORT_SCAN"} <= classes
