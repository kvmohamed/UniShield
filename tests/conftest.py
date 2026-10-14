"""Shared fixtures: deterministic sample input files (see unishield.data.sample_files)."""

from __future__ import annotations

import pytest

from unishield.data import sample_files


@pytest.fixture(scope="session")
def sample_capture(tmp_path_factory):
    """Sample PCAP plus its ground-truth flows."""
    return sample_files.write_sample_pcap(tmp_path_factory.mktemp("pcap") / "sample.pcap")


@pytest.fixture(scope="session")
def sample_capture_ng(tmp_path_factory):
    return sample_files.write_sample_pcap(tmp_path_factory.mktemp("pcapng") / "sample.pcapng", pcapng=True)


@pytest.fixture(scope="session")
def sample_zeek_dir(tmp_path_factory):
    return sample_files.write_sample_zeek_dir(tmp_path_factory.mktemp("zeek"))


@pytest.fixture(scope="session")
def sample_zeek_tsv(tmp_path_factory):
    return sample_files.write_sample_zeek_tsv(tmp_path_factory.mktemp("zeektsv") / "conn.log")


@pytest.fixture(scope="session")
def sample_flow_csv(tmp_path_factory):
    return sample_files.write_sample_flow_csv(tmp_path_factory.mktemp("csv") / "flows.csv")


@pytest.fixture(scope="session")
def sample_flow_jsonl(tmp_path_factory):
    return sample_files.write_sample_flow_jsonl(tmp_path_factory.mktemp("jsonl") / "flows.jsonl")


@pytest.fixture(scope="session")
def sample_cicids_csv(tmp_path_factory):
    return sample_files.write_cicids_style_csv(tmp_path_factory.mktemp("cic") / "Friday-WorkingHours.csv")
