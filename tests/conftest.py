"""Shared fixtures: deterministic sample input files (see unishield.data.sample_files) and API clients."""

from __future__ import annotations

import os

import pytest

# Tests never touch the default on-disk database.
os.environ.setdefault("UNISHIELD_DB_URL", "sqlite://")

from unishield.data import sample_files  # noqa: E402


@pytest.fixture(autouse=True, scope="session")
def _cheap_password_hashing():
    """Argon2id with minimal parameters: tests hash many passwords; production keeps the defaults."""
    from argon2 import PasswordHasher, profiles

    from unishield.accounts import passwords

    default = passwords._hasher
    passwords._hasher = PasswordHasher.from_parameters(profiles.CHEAPEST)
    yield
    passwords._hasher = default


TEST_PASSWORD = "test-password-0123"


def login(client, username: str, password: str = TEST_PASSWORD) -> dict:
    """Log ``client`` in and make it send the session's CSRF token, as the dashboard does."""
    response = client.post("/auth/login", json={"username": username, "password": password})
    assert response.status_code == 200, response.text
    body = response.json()
    client.headers["X-CSRF-Token"] = body["csrf_token"]
    return body


@pytest.fixture
def api_client(monkeypatch, tmp_path):
    """(TestClient logged in as administrator 'admin', data dir) for a fresh app with an in-memory database."""
    from fastapi.testclient import TestClient

    from unishield.api.app import create_app
    from unishield.config import reset_config
    from unishield.storage import AlertRepository

    data_dir = tmp_path / "data"
    data_dir.mkdir()
    monkeypatch.setenv("UNISHIELD_DATA_DIR", str(data_dir))
    monkeypatch.setenv("UNISHIELD_EXPORT_DIR", str(tmp_path / "exports"))
    for var in ("UNISHIELD_ADMIN_API_KEY", "UNISHIELD_API_KEY_ROLE", "UNISHIELD_AUTH_MODE",
                "UNISHIELD_COOKIE_SECURE"):
        monkeypatch.delenv(var, raising=False)
    reset_config()
    app = create_app(AlertRepository.from_url("sqlite://"))
    app.state.ctx.accounts.create_user("admin", TEST_PASSWORD, "admin")
    client = TestClient(app, client=("127.0.0.1", 50000))
    login(client, "admin")
    yield client, data_dir
    app.state.ctx.reset()
    reset_config()


@pytest.fixture
def client_as(api_client):
    """Factory: a new client of the same app, logged in as a new user with ``role`` (None: anonymous)."""
    from fastapi.testclient import TestClient

    app = api_client[0].app
    count = iter(range(1000))

    def make(role, address=("127.0.0.1", 50001)):
        client = TestClient(app, client=address)
        if role is not None:
            username = f"{role}{next(count)}"
            app.state.ctx.accounts.create_user(username, TEST_PASSWORD, role)
            login(client, username)
        return client

    return make


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
