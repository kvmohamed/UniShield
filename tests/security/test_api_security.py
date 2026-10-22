"""Security tests: admin authentication, input validation, injection safety, path traversal."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from unishield.config import reset_config

pytestmark = pytest.mark.security

ADMIN_CALLS = [
    ("post", "/replay/demo", {"scenario": "dga"}),
    ("post", "/replay/start", {"file_path": "x.pcap"}),
    ("post", "/replay/stop", {}),
    ("delete", "/alerts", {}),
    ("post", "/export", {}),
    ("post", "/intel/import", {"source": "feed"}),
    ("delete", "/intel/sources/feed", {}),
    ("post", "/intel/purge-expired", {}),
]


def _call(client, method, path, params, headers=None):
    return getattr(client, method)(path, params=params, headers=headers or {})


@pytest.mark.parametrize("method,path,params", ADMIN_CALLS)
def test_admin_endpoints_reject_remote_clients_without_key(api_client, method, path, params):
    client, _ = api_client
    remote = TestClient(client.app, client=("203.0.113.9", 40000))
    response = _call(remote, method, path, params)
    assert response.status_code == 403
    assert "UNISHIELD_ADMIN_API_KEY" in response.json()["detail"]


@pytest.mark.parametrize("method,path,params", ADMIN_CALLS)
def test_admin_endpoints_require_the_configured_key(api_client, monkeypatch, method, path, params):
    client, _ = api_client
    monkeypatch.setenv("UNISHIELD_ADMIN_API_KEY", "s3cret-key-for-tests")
    reset_config()
    assert _call(client, method, path, params).status_code == 401                       # loopback, no key
    assert _call(client, method, path, params, {"X-API-Key": "wrong"}).status_code == 401
    remote = TestClient(client.app, client=("203.0.113.9", 40000))
    ok = _call(remote, method, path, params, {"X-API-Key": "s3cret-key-for-tests"})
    assert ok.status_code != 401
    detail = str(ok.json().get("detail", "")) if ok.status_code >= 400 else ""
    assert "X-API-Key" not in detail and "loopback" not in detail     # past authentication


def test_read_endpoints_stay_open_to_remote_clients(api_client):
    client, _ = api_client
    remote = TestClient(client.app, client=("203.0.113.9", 40000))
    for path in ("/health", "/alerts", "/alerts/summary", "/metrics", "/replay/status", "/incidents",
                 "/intel/status", "/outputs/status"):
        assert remote.get(path).status_code == 200, path


def test_api_key_is_not_leaked(api_client, monkeypatch):
    client, _ = api_client
    monkeypatch.setenv("UNISHIELD_ADMIN_API_KEY", "s3cret-key-for-tests")
    reset_config()
    for path in ("/health", "/system/architecture", "/openapi.json"):
        assert "s3cret-key-for-tests" not in client.get(path).text
    from unishield.config import get_config
    assert "s3cret" not in repr(get_config().api)


@pytest.mark.parametrize("value", [
    "' OR '1'='1", "1; DROP TABLE alerts;--", "10.0.0.1' --", "\" OR 1=1 --", "%27%20OR%201%3D1",
])
def test_filters_reject_injection_strings(api_client, value):
    client, _ = api_client
    assert client.get("/alerts", params={"source_ip": value}).status_code == 422
    assert client.get("/alerts", params={"detector": value}).status_code == 422


def test_alert_id_lookup_is_parameterised(api_client):
    client, _ = api_client
    client.post("/replay/demo", params={"scenario": "port_scan", "wait": True})
    total = client.get("/alerts").headers["X-Total-Count"]
    assert client.get("/alerts/' OR '1'='1").status_code == 404
    assert client.get("/alerts/x';DROP TABLE alerts;--").status_code == 404
    assert client.get("/alerts").headers["X-Total-Count"] == total                 # table intact


@pytest.mark.parametrize("path", [
    "../../etc/passwd", r"..\..\windows\win.ini", "/etc/passwd", "C:/Windows/win.ini",
    "data/../../secret.pcap",
])
def test_replay_rejects_traversal(api_client, path):
    client, _ = api_client
    assert client.post("/replay/start", params={"file_path": path}).status_code in (403, 404)


def test_replay_rejects_nul_and_overlong_paths(api_client):
    client, data_dir = api_client
    assert client.post("/replay/start", params={"file_path": f"{data_dir}/a\x00.pcap"}).status_code in (400, 422)
    assert client.post("/replay/start", params={"file_path": "a" * 5000}).status_code == 422


def test_numeric_limits_are_enforced(api_client):
    client, _ = api_client
    assert client.get("/alerts", params={"limit": 100000}).status_code == 422
    assert client.get("/alerts", params={"offset": -1}).status_code == 422
    assert client.post("/replay/demo", params={"ddos": 10**9}).status_code == 422
    assert client.get("/alerts/timeline", params={"bucket_sec": 0}).status_code == 422


def test_hardening_headers_on_api_responses(api_client):
    client, _ = api_client
    r = client.get("/alerts")
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert r.headers["Cache-Control"] == "no-store"
    assert "access-control-allow-origin" not in {k.lower() for k in r.headers}


def test_no_mutating_get_endpoints(api_client):
    """Every route that changes state is POST/DELETE and guarded; GET routes never mutate."""
    client, _ = api_client
    guarded = {("POST", "/replay/start"), ("POST", "/replay/demo"), ("POST", "/replay/stop"),
               ("DELETE", "/alerts"), ("POST", "/export"), ("POST", "/intel/import"),
               ("DELETE", "/intel/sources/{source}"), ("POST", "/intel/purge-expired")}
    found = {(m.upper(), path) for path, ops in client.app.openapi()["paths"].items() for m in ops
             if m.upper() in ("POST", "PUT", "PATCH", "DELETE")}
    assert found == guarded

