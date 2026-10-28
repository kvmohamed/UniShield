"""Security tests: admin authorisation, API keys, open mode, input validation, injection, path traversal.

Login, session, CSRF and lockout behaviour is in test_auth.py; the role of
every route is checked from the OpenAPI schema in test_route_guards.py.
"""

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
READ_PATHS = ("/alerts", "/alerts/summary", "/metrics", "/replay/status", "/incidents", "/system/architecture",
              "/intel/status", "/outputs/status")


def _call(client, method, path, params, headers=None):
    return getattr(client, method)(path, params=params, headers=headers or {})


def _past_auth(response) -> bool:
    """True if the request was authorised (it may still fail validation, e.g. a path outside data/)."""
    if response.status_code == 401:
        return False
    detail = str(response.json().get("detail", "")) if response.status_code >= 400 else ""
    return not any(word in detail for word in ("X-API-Key", "Login", "role", "CSRF", "interactive login"))


@pytest.mark.parametrize("method,path,params", ADMIN_CALLS)
def test_admin_endpoints_need_a_login_even_from_loopback(api_client, method, path, params):
    """Loopback is not trusted: behind a reverse proxy on the same host every client is loopback."""
    client, _ = api_client
    for address in (("127.0.0.1", 40000), ("::1", 40000), ("203.0.113.9", 40000)):
        response = _call(TestClient(client.app, client=address), method, path, params)
        assert response.status_code == 401, (address, response.text)


@pytest.mark.parametrize("method,path,params", ADMIN_CALLS)
@pytest.mark.parametrize("role", ["viewer", "analyst"])
def test_admin_endpoints_refuse_lower_roles(client_as, method, path, params, role):
    response = _call(client_as(role), method, path, params)
    assert response.status_code == 403 and "admin" in response.json()["detail"]


@pytest.mark.parametrize("method,path,params", ADMIN_CALLS)
def test_static_api_key_grants_its_configured_role(api_client, monkeypatch, method, path, params):
    client, _ = api_client
    monkeypatch.setenv("UNISHIELD_ADMIN_API_KEY", "s3cret-key-for-tests")
    reset_config()
    remote = TestClient(client.app, client=("203.0.113.9", 40000))
    assert _call(remote, method, path, params).status_code == 401                         # no key
    assert _call(remote, method, path, params, {"X-API-Key": "wrong"}).status_code == 401
    assert _past_auth(_call(remote, method, path, params, {"X-API-Key": "s3cret-key-for-tests"}))
    monkeypatch.setenv("UNISHIELD_API_KEY_ROLE", "viewer")
    reset_config()
    assert _call(remote, method, path, params, {"X-API-Key": "s3cret-key-for-tests"}).status_code == 403
    assert remote.get("/alerts", headers={"X-API-Key": "s3cret-key-for-tests"}).status_code == 200


def test_read_endpoints_need_a_login(api_client, client_as):
    client, _ = api_client
    anonymous = client_as(None, address=("203.0.113.9", 40000))
    viewer = client_as("viewer", address=("203.0.113.9", 40000))
    assert anonymous.get("/health").status_code == 200
    for path in READ_PATHS:
        assert anonymous.get(path).status_code == 401, path
        assert viewer.get(path).status_code == 200, path


def test_open_mode_serves_reads_without_login_but_not_admin_actions(api_client, client_as, monkeypatch):
    monkeypatch.setenv("UNISHIELD_AUTH_MODE", "open")
    reset_config()
    anonymous = client_as(None, address=("203.0.113.9", 40000))
    for path in READ_PATHS:
        assert anonymous.get(path).status_code == 200, path
    me = anonymous.get("/auth/me").json()
    assert me["mode"] == "open" and me["authenticated"] is False and me["effective_role"] == "viewer"
    for method, path, params in ADMIN_CALLS:
        assert _call(anonymous, method, path, params).status_code == 401
    assert anonymous.get("/audit").status_code == 401 and anonymous.get("/users").status_code == 401


def test_open_mode_is_refused_in_production(monkeypatch):
    from unishield.config import UnishieldConfig

    with pytest.raises(ValueError, match="labs only"):
        UnishieldConfig(environment="production", auth={"mode": "open"})
    assert UnishieldConfig(environment="production").auth.mode == "accounts"


def test_cross_origin_state_changes_are_refused(api_client):
    client, _ = api_client
    hostile = {"Origin": "https://attacker.example"}
    assert client.post("/replay/stop", headers=hostile).status_code == 403
    assert client.post("/auth/login", json={"username": "admin", "password": "x"}, headers=hostile).status_code == 403
    assert client.get("/alerts", headers=hostile).status_code == 200            # reads carry no side effects
    assert client.post("/replay/stop", headers={"Origin": "http://testserver"}).status_code == 200


def test_api_key_is_not_leaked(api_client, monkeypatch):
    client, _ = api_client
    monkeypatch.setenv("UNISHIELD_ADMIN_API_KEY", "s3cret-key-for-tests")
    reset_config()
    for path in ("/health", "/system/architecture", "/openapi.json", "/auth/me", "/audit"):
        assert "s3cret-key-for-tests" not in client.get(path).text
    client.get("/alerts", headers={"X-API-Key": "s3cret-key-for-tests"})
    client.get("/alerts", headers={"X-API-Key": "s3cret-key-wrong"})
    assert "s3cret" not in client.get("/audit").text
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
    """Every route that changes state is POST/PATCH/DELETE: auth routes or administrator-only; GET never mutates."""
    client, _ = api_client
    expected = {
        ("POST", "/auth/login"): "public", ("POST", "/auth/logout"): "public", ("POST", "/auth/password"): "viewer",
        ("POST", "/replay/start"): "admin", ("POST", "/replay/demo"): "admin", ("POST", "/replay/stop"): "admin",
        ("DELETE", "/alerts"): "admin", ("POST", "/users"): "admin", ("PATCH", "/users/{username}"): "admin",
        ("DELETE", "/users/{username}"): "admin", ("POST", "/export"): "admin", ("POST", "/intel/import"): "admin",
        ("DELETE", "/intel/sources/{source}"): "admin", ("POST", "/intel/purge-expired"): "admin",
    }
    found = {(m.upper(), path): op["x-unishield-role"] for path, ops in client.app.openapi()["paths"].items()
             for m, op in ops.items() if m.upper() in ("POST", "PUT", "PATCH", "DELETE")}
    assert found == expected


def test_api_docs_can_be_turned_off(monkeypatch):
    from unishield.api.app import create_app
    from unishield.storage import AlertRepository

    monkeypatch.setenv("UNISHIELD_API_DOCS", "false")
    reset_config()
    try:
        client = TestClient(create_app(AlertRepository.from_url("sqlite://")))
        for path in ("/docs", "/redoc", "/openapi.json"):
            assert client.get(path).status_code == 404, path
        assert client.app.openapi()["paths"]["/alerts"]["get"]["x-unishield-role"] == "viewer"
    finally:
        reset_config()
