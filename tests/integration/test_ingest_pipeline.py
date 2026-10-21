"""
Integration tests for Phase 3: input → normalisation → sessionization → pipeline → API.

Exit criterion: the sample PCAP, read and sessionized, yields exactly the
ground-truth flows written by unishield.data.sample_files.
"""

from __future__ import annotations

import shutil
import time

import pytest

from unishield.config import get_config
from unishield.data.sample_generator import SimulatedReader, generate_mixed_scenario
from unishield.ingest.pcap_reader import PcapReader
from unishield.ingest.zeek_reader import ZeekReader
from unishield.processing.normalization import Normalizer
from unishield.processing.pipeline import Pipeline
from unishield.processing.sessionizer import Sessionizer
from unishield.schemas.alert import SourceType

pytestmark = pytest.mark.integration


def _key(f):
    return (f.source_ip, f.source_port, f.destination_ip, f.destination_port)


def test_pcap_to_sessionized_flows_matches_ground_truth(sample_capture):
    reader = PcapReader(sample_capture.path)
    sessionizer = Sessionizer()
    normalizer = Normalizer(["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"])
    flows = list(normalizer.normalize_stream(sessionizer.process(reader.read())))

    assert reader.records_read == 26 and reader.skipped == 1 and reader.errors == 0
    assert len(flows) == len(sample_capture.flows) == 10
    assert all(a.timestamp <= b.timestamp for a, b in zip(flows, flows[1:]))

    by_key = {_key(f): f for f in flows}
    for exp in sample_capture.flows:
        got = by_key[(exp.source_ip, exp.source_port, exp.destination_ip, exp.destination_port)]
        assert got.protocol.value == exp.protocol, exp.name
        assert (got.orig_packets, got.resp_packets) == (exp.orig_packets, exp.resp_packets), exp.name
        assert (got.orig_bytes, got.resp_bytes) == (exp.orig_bytes, exp.resp_bytes), exp.name
        assert got.conn_state == exp.conn_state, exp.name
        assert got.direction.value == exp.direction, exp.name
        assert got.tcp_flags == exp.tcp_flags, exp.name
        assert (got.dns_query, got.dns_rcode) == (exp.dns_query, exp.dns_rcode), exp.name
        assert (got.tls_version, got.tls_cipher) == (exp.tls_version, exp.tls_cipher), exp.name


def test_pipeline_sessionizes_packet_level_readers(sample_capture):
    result = Pipeline(enable_correlation=False).run(PcapReader(sample_capture.path))
    assert result.errors == 0
    assert result.total_records == 10                      # flows, not packets
    ingest = result.ingest
    assert ingest["reader"] == "PcapReader" and ingest["records_read"] == 26
    assert ingest["sessionizer"]["packets_in"] == 26 and ingest["sessionizer"]["flows_out"] == 10
    assert ingest["normalizer"]["directions_inferred"] == 10


def test_pipeline_does_not_sessionize_flow_readers(sample_zeek_dir):
    result = Pipeline(enable_correlation=False).run(ZeekReader(sample_zeek_dir))
    assert result.total_records == 4
    assert result.ingest["sessionizer"] is None


def test_alerts_report_the_input_source():
    flows = generate_mixed_scenario(normal_count=100, ddos_count=100, scan_count=80,
                                    beacon_count=10, exfil_count=30)
    result = Pipeline(enable_correlation=False).run(SimulatedReader(flows))
    assert result.alerts
    assert {a.source_type for a in result.alerts} == {SourceType.SIMULATED}


# ---------------------------------------------------------------- replay API

@pytest.fixture
def api(api_client):
    yield api_client
    _wait_for_replay(api_client[0])


def _wait_for_replay(client, timeout=30.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        status = client.get("/replay/status").json()
        if status["status"] != "running":
            return status
        time.sleep(0.05)
    raise AssertionError("replay did not finish")


def test_replay_pcap_via_api(api, sample_capture):
    client, data_dir = api
    target = data_dir / "sample.pcap"
    shutil.copy(sample_capture.path, target)

    response = client.post("/replay/start", params={"file_path": str(target)})
    assert response.status_code == 200, response.text
    assert response.json()["format"] == "pcap"

    status = _wait_for_replay(client)
    assert status["status"] == "completed"
    assert status["records_processed"] == 10
    assert status["result"]["ingest"]["sessionizer"]["flows_out"] == 10


@pytest.mark.parametrize("fixture,fmt,records", [
    ("sample_flow_jsonl", "flow_json", 3),      # audit D8: previously parsed 0 records
    ("sample_flow_csv", "flow_csv", 3),
    ("sample_zeek_tsv", "zeek_tsv", 4),
])
def test_replay_files_via_api(api, request, fixture, fmt, records):
    client, data_dir = api
    source = request.getfixturevalue(fixture)
    target = data_dir / source.name
    shutil.copy(source, target)
    response = client.post("/replay/start", params={"file_path": str(target)})
    assert response.status_code == 200 and response.json()["format"] == fmt
    status = _wait_for_replay(client)
    assert (status["status"], status["records_processed"]) == ("completed", records)


def test_replay_zeek_directory_via_api(api, sample_zeek_dir):
    client, data_dir = api
    target = data_dir / "zeek"
    shutil.copytree(sample_zeek_dir, target)
    response = client.post("/replay/start", params={"file_path": str(target)})
    assert response.json()["format"] == "zeek_dir"
    assert _wait_for_replay(client)["records_processed"] == 4


def test_replay_rejects_paths_outside_data_dir(api, sample_capture):
    client, data_dir = api
    assert client.post("/replay/start", params={"file_path": str(sample_capture.path)}).status_code == 403
    traversal = data_dir / ".." / ".." / sample_capture.path.name
    assert client.post("/replay/start", params={"file_path": str(traversal)}).status_code == 403


def test_replay_missing_file_is_404(api):
    client, data_dir = api
    assert client.post("/replay/start", params={"file_path": str(data_dir / "missing.pcap")}).status_code == 404


def test_replay_unsupported_content_is_400(api):
    client, data_dir = api
    target = data_dir / "notes.txt"
    target.write_text("just some words\n", encoding="utf-8")
    response = client.post("/replay/start", params={"file_path": str(target)})
    assert response.status_code == 400


def test_replay_oversized_input_is_413(api, monkeypatch, sample_capture):
    client, data_dir = api
    target = data_dir / "sample.pcap"
    shutil.copy(sample_capture.path, target)
    monkeypatch.setattr(get_config().ingest, "max_file_size_mb", 0)
    assert client.post("/replay/start", params={"file_path": str(target)}).status_code == 413
