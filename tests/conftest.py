"""Shared fixtures: deterministic sample input files (see unishield.data.sample_files) and an API client."""

from __future__ import annotations

import os

import pytest

# Tests never touch the default on-disk database.
os.environ.setdefault("UNISHIELD_DB_URL", "sqlite://")

from unishield.data import sample_files  # noqa: E402


@pytest.fixture
def api_client(monkeypatch, tmp_path):
    """(TestClient from a loopback address, data dir) for a fresh app with an in-memory database."""
    from fastapi.testclient import TestClient

    from unishield.api.app import create_app
    from unishield.config import reset_config
    from unishield.storage import AlertRepository

    data_dir = tmp_path / "data"
    data_dir.mkdir()
    monkeypatch.setenv("UNISHIELD_DATA_DIR", str(data_dir))
    monkeypatch.setenv("UNISHIELD_EXPORT_DIR", str(tmp_path / "exports"))
    monkeypatch.delenv("UNISHIELD_ADMIN_API_KEY", raising=False)
    reset_config()
    app = create_app(AlertRepository.from_url("sqlite://"))
    client = TestClient(app, client=("127.0.0.1", 50000))
    yield client, data_dir
    app.state.ctx.reset()
    reset_config()


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
