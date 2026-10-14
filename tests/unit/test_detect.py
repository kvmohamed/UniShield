"""Unit tests for content-based input format detection (audit D8, D9)."""

from __future__ import annotations

import json

import pytest

from unishield.ingest.detect import UnsupportedFormatError, detect_format, open_reader
from unishield.ingest.flow_reader import FlowReader
from unishield.ingest.pcap_reader import PcapReader
from unishield.ingest.zeek_reader import ZeekReader


def test_pcap_and_pcapng(sample_capture, sample_capture_ng):
    assert detect_format(sample_capture.path) == "pcap"
    assert detect_format(sample_capture_ng.path) == "pcapng"


def test_zeek_formats(sample_zeek_dir, sample_zeek_tsv):
    assert detect_format(sample_zeek_dir) == "zeek_dir"
    assert detect_format(sample_zeek_dir / "conn.log") == "zeek_json"
    assert detect_format(sample_zeek_tsv) == "zeek_tsv"


def test_flow_formats(sample_flow_csv, sample_flow_jsonl, sample_cicids_csv):
    assert detect_format(sample_flow_csv) == "flow_csv"
    assert detect_format(sample_flow_jsonl) == "flow_json"
    assert detect_format(sample_cicids_csv) == "flow_csv"


def test_detection_ignores_misleading_extensions(tmp_path, sample_capture, sample_zeek_dir):
    pcap_as_dat = tmp_path / "capture.dat"
    pcap_as_dat.write_bytes(sample_capture.path.read_bytes())
    zeek_as_txt = tmp_path / "conn.txt"
    zeek_as_txt.write_text((sample_zeek_dir / "conn.log").read_text(encoding="utf-8"), encoding="utf-8")
    flows_as_json = tmp_path / "flows.json"
    flows_as_json.write_text(json.dumps([{"timestamp": 1, "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2"}]),
                             encoding="utf-8")
    assert detect_format(pcap_as_dat) == "pcap"
    assert detect_format(zeek_as_txt) == "zeek_json"
    assert detect_format(flows_as_json) == "flow_json"


def test_zeek_json_array(tmp_path):
    path = tmp_path / "conn.json"
    path.write_text(json.dumps([{"ts": 1.0, "uid": "C1", "id.orig_h": "10.0.0.1"}]), encoding="utf-8")
    assert detect_format(path) == "zeek_json"


@pytest.mark.parametrize("content", ["", "\n\n", "just some words\n", "{not json\n"])
def test_unsupported_content(tmp_path, content):
    path = tmp_path / "x.txt"
    path.write_text(content, encoding="utf-8")
    with pytest.raises(UnsupportedFormatError):
        detect_format(path)


def test_directory_without_conn_log(tmp_path):
    with pytest.raises(UnsupportedFormatError):
        detect_format(tmp_path)


def test_missing_path(tmp_path):
    with pytest.raises(FileNotFoundError):
        detect_format(tmp_path / "missing.pcap")


def test_open_reader_returns_matching_reader(sample_capture, sample_zeek_tsv, sample_flow_csv):
    assert isinstance(open_reader(sample_capture.path)[0], PcapReader)
    assert isinstance(open_reader(sample_zeek_tsv)[0], ZeekReader)
    reader, fmt = open_reader(sample_flow_csv)
    assert isinstance(reader, FlowReader) and fmt == "flow_csv"
