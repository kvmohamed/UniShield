"""Login, cookies, sessions, CSRF, lockout, rate limiting, service tokens, user management and their audit trail."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from tests.conftest import TEST_PASSWORD, login
from unishield.config import get_config

pytestmark = pytest.mark.security

FAILED = "Invalid username or password, or the account is temporarily locked"


def _ctx(client):
    return client.app.state.ctx


def _audit(client, **params):
    response = client.get("/audit", params=params)
    assert response.status_code == 200, response.text
    return response.json()


def _set_cookie(response) -> str:
    return response.headers["set-cookie"]


def _new_client(client, address=("127.0.0.1", 50001), base_url="http://testserver"):
    return TestClient(client.app, client=address, base_url=base_url)


# --- login and cookies -------------------------------------------------------------

def test_login_sets_a_hardened_session_cookie(api_client):
    client, _ = api_client
    fresh = _new_client(client)
    response = fresh.post("/auth/login", json={"username": "admin", "password": TEST_PASSWORD})
    assert response.status_code == 200
    body = response.json()
    assert body["authenticated"] and body["role"] == "admin" and body["user"]["username"] == "admin"
    assert len(body["csrf_token"]) >= 43 and body["expires_at"]
    cookie = _set_cookie(response)
    assert cookie.startswith("unishield_session=")
    for flag in ("HttpOnly", "SameSite=strict", "Path=/", f"Max-Age={get_config().auth.session_ttl_minutes * 60}"):
        assert flag.lower() in cookie.lower(), flag
    assert "secure" not in cookie.lower()                      # plain HTTP in this test
    assert response.headers["Cache-Control"] == "no-store"
    assert TEST_PASSWORD not in response.text


def test_cookie_is_secure_over_https_and_by_policy(api_client, monkeypatch):
    client, _ = api_client
    https = _new_client(client, base_url="https://testserver")
    response = https.post("/auth/login", json={"username": "admin", "password": TEST_PASSWORD})
    assert "; secure" in _set_cookie(response).lower()
    assert https.get("/auth/me").json()["authenticated"]
    monkeypatch.setattr(get_config().auth, "cookie_secure", "always")
    response = _new_client(client).post("/auth/login", json={"username": "admin", "password": TEST_PASSWORD})
    assert "; secure" in _set_cookie(response).lower()
    monkeypatch.setattr(get_config().auth, "cookie_secure", "never")
    response = https.post("/auth/login", json={"username": "admin", "password": TEST_PASSWORD})
    assert "secure" not in _set_cookie(response).lower()


def test_failures_look_the_same_whatever_the_reason(api_client):
    client, _ = api_client
    ctx = _ctx(client)
    ctx.accounts.create_user("disabled1", TEST_PASSWORD, "viewer")
    ctx.accounts.update_user("disabled1", disabled=True)
    fresh = _new_client(client)
    answers = [fresh.post("/auth/login", json={"username": u, "password": p})
               for u, p in (("nobody", TEST_PASSWORD), ("admin", "wrong-password-123"), ("disabled1", TEST_PASSWORD))]
    assert {(r.status_code, r.json()["detail"]) for r in answers} == {(401, FAILED)}
    assert "set-cookie" not in {k.lower() for k in answers[0].headers}
    reasons = [e["details"]["reason"] for e in _audit(client, action="auth.login", outcome="failure")]
    assert reasons == ["disabled", "bad_password", "unknown_user"]


def test_login_needs_a_json_body(api_client):
    """An HTML form on another site can post urlencoded or text/plain bodies, never JSON."""
    client, _ = api_client
    fresh = _new_client(client)
    form = fresh.post("/auth/login", data={"username": "admin", "password": TEST_PASSWORD})
    assert form.status_code == 422
    text_plain = fresh.post("/auth/login", content=f'{{"username": "admin", "password": "{TEST_PASSWORD}"}}',
                            headers={"Content-Type": "text/plain"})
    assert text_plain.status_code == 422


def test_login_replaces_any_existing_session(api_client):
    client, _ = api_client
    fresh = _new_client(client)
    login(fresh, "admin")
    first = fresh.cookies.get("unishield_session")
    login(fresh, "admin")
    second = fresh.cookies.get("unishield_session")
    assert first != second
    stale = _new_client(client)
    stale.cookies.set("unishield_session", first)
    assert stale.get("/alerts").status_code == 401


def test_me_and_logout(api_client):
    client, _ = api_client
    fresh = _new_client(client)
    assert fresh.get("/auth/me").json() == {
        "mode": "accounts", "authenticated": False, "via": None, "user": None, "name": None, "role": None,
        "effective_role": None, "csrf_token": None, "expires_at": None, "idle_timeout_minutes": None}
    body = login(fresh, "admin")
    me = fresh.get("/auth/me").json()
    assert me["authenticated"] and me["via"] == "session" and me["csrf_token"] == body["csrf_token"]
    raw = fresh.cookies.get("unishield_session")
    fresh.headers.pop("X-CSRF-Token")
    assert fresh.post("/auth/logout").status_code == 403                  # logout needs the CSRF token too
    fresh.headers["X-CSRF-Token"] = body["csrf_token"]
    response = fresh.post("/auth/logout")
    assert response.status_code == 200 and 'unishield_session=""' in _set_cookie(response)
    replay = _new_client(client)
    replay.cookies.set("unishield_session", raw)
    assert replay.get("/alerts").status_code == 401                       # the session is gone server-side
    assert [e["action"] for e in _audit(client, action="auth.")][:3] == [
        "auth.logout", "auth.csrf_rejected", "auth.login"]


def test_sessions_expire_when_idle_and_at_their_lifetime(api_client):
    client, _ = api_client
    accounts = _ctx(client).accounts
    fresh = _new_client(client)
    login(fresh, "admin")
    start = datetime.now(timezone.utc).replace(tzinfo=None)
    idle = get_config().auth.session_idle_minutes
    try:
        accounts.clock = lambda: start + timedelta(minutes=idle - 1)
        assert fresh.get("/alerts").status_code == 200
        accounts.clock = lambda: start + timedelta(minutes=2 * idle - 2)   # activity moved the idle deadline
        assert fresh.get("/alerts").status_code == 200
        accounts.clock = lambda: start + timedelta(minutes=3 * idle)
        assert fresh.get("/alerts").status_code == 401
        login(fresh, "admin")
        ttl = get_config().auth.session_ttl_minutes
        accounts.clock = lambda: start + timedelta(minutes=3 * idle + ttl + 1)
        assert fresh.get("/alerts").status_code == 401
    finally:
        del accounts.clock


# --- CSRF ---------------------------------------------------------------------------

@pytest.mark.parametrize("token", [None, "", "wrong-token"])
def test_state_changes_with_a_session_need_the_csrf_token(api_client, token):
    client, _ = api_client
    fresh = _new_client(client)
    login(fresh, "admin")
    del fresh.headers["X-CSRF-Token"]
    headers = {} if token is None else {"X-CSRF-Token": token}
    assert fresh.post("/replay/stop", headers=headers).status_code == 403
    assert fresh.delete("/alerts", headers=headers).status_code == 403
    assert fresh.get("/alerts").status_code == 200                        # reads need no token
    (entry, *_), _total = _audit(client, action="auth.csrf_rejected"), None
    assert entry["actor"] == "admin" and entry["outcome"] == "denied" and entry["target"] == "DELETE /alerts"


def test_csrf_token_of_another_session_is_refused(api_client, client_as):
    client, _ = api_client
    other = client_as("admin")
    stolen = other.headers["X-CSRF-Token"]
    fresh = _new_client(client)
    login(fresh, "admin")
    fresh.headers["X-CSRF-Token"] = stolen
    assert fresh.post("/replay/stop").status_code == 403


def test_service_tokens_need_no_csrf_token(api_client):
    client, _ = api_client
    raw, _ = _ctx(client).accounts.create_token("automation", "admin")
    bot = _new_client(client)
    assert bot.post("/replay/stop", headers={"X-API-Key": raw}).status_code == 200


# --- lockout and rate limiting ------------------------------------------------------------

def test_account_locks_after_repeated_failures_and_admin_can_unlock(api_client):
    client, _ = api_client
    _ctx(client).accounts.create_user("alice", TEST_PASSWORD, "viewer")
    fresh = _new_client(client, address=("198.51.100.7", 1))
    for _ in range(get_config().auth.max_failed_logins):
        assert fresh.post("/auth/login", json={"username": "alice", "password": "not-the-password"}).status_code == 401
    locked = fresh.post("/auth/login", json={"username": "alice", "password": TEST_PASSWORD})
    assert locked.status_code == 401 and locked.json()["detail"] == FAILED
    (lockout,) = _audit(client, action="auth.lockout")
    assert lockout["target"] == "alice" and lockout["client_ip"] == "198.51.100.7"
    assert _audit(client, action="auth.login", outcome="failure")[0]["details"]["reason"] == "locked"
    users = {u["username"]: u for u in client.get("/users").json()}
    assert users["alice"]["locked"] is True
    assert client.patch("/users/alice", json={"unlock": True}).status_code == 200
    assert fresh.post("/auth/login", json={"username": "alice", "password": TEST_PASSWORD}).status_code == 200


def test_failed_logins_are_rate_limited_per_address(api_client, monkeypatch):
    client, _ = api_client
    monkeypatch.setattr(get_config().auth, "login_rate_limit", 3)
    _ctx(client)._limiter = None
    attacker = _new_client(client, address=("203.0.113.66", 1))
    for i in range(3):                                                    # spraying different accounts
        r = attacker.post("/auth/login", json={"username": f"user{i}", "password": "guess-guess-1"})
        assert r.status_code == 401
    blocked = attacker.post("/auth/login", json={"username": "admin", "password": TEST_PASSWORD})
    assert blocked.status_code == 429 and int(blocked.headers["Retry-After"]) > 0
    assert attacker.get("/alerts", headers={"X-API-Key": "us_guess"}).status_code == 429
    other = _new_client(client, address=("198.51.100.8", 1))
    assert other.post("/auth/login", json={"username": "admin", "password": TEST_PASSWORD}).status_code == 200
    failures = _audit(client, action="auth.login", outcome="failure")
    assert len(failures) == 3 and failures[0]["details"]["address_blocked"] is True


# --- password change ---------------------------------------------------------------------

def test_change_own_password(api_client, client_as):
    client, _ = api_client
    viewer = client_as("viewer")
    name = viewer.get("/auth/me").json()["name"]
    second = _new_client(client)
    login(second, name)
    assert viewer.post("/auth/password", json={"current_password": "nope-nope-nope",
                                               "new_password": "brand new password"}).status_code == 403
    assert viewer.post("/auth/password", json={"current_password": TEST_PASSWORD,
                                               "new_password": "short"}).status_code == 422
    ok = viewer.post("/auth/password", json={"current_password": TEST_PASSWORD, "new_password": "brand new password"})
    assert ok.status_code == 200
    assert viewer.get("/alerts").status_code == 200                       # this session stays
    assert second.get("/alerts").status_code == 401                       # others end
    assert _new_client(client).post("/auth/login", json={"username": name, "password": TEST_PASSWORD}).status_code == 401
    login(_new_client(client), name, "brand new password")
    outcomes = [e["outcome"] for e in _audit(client, action="auth.password_change")]
    assert outcomes == ["success", "failure"]


def test_tokens_cannot_change_passwords_or_manage_users(api_client):
    client, _ = api_client
    raw, _ = _ctx(client).accounts.create_token("ci", "admin")
    bot = _new_client(client)
    headers = {"X-API-Key": raw}
    assert bot.get("/users", headers=headers).status_code == 403
    assert bot.post("/users", headers=headers,
                    json={"username": "mallory", "role": "admin", "password": TEST_PASSWORD}).status_code == 403
    assert bot.post("/auth/password", headers=headers,
                    json={"current_password": "x", "new_password": "y" * 12}).status_code == 403
    assert bot.get("/audit", headers=headers).status_code == 200
    assert _ctx(client).accounts.get_user("mallory") is None


# --- service tokens -----------------------------------------------------------------------

def test_service_tokens_are_scoped_revocable_and_expire(api_client):
    client, _ = api_client
    accounts = _ctx(client).accounts
    viewer_token, _ = accounts.create_token("siem", "viewer")
    bot = _new_client(client, address=("198.51.100.20", 1))
    headers = {"X-API-Key": viewer_token}
    assert bot.get("/alerts", headers=headers).status_code == 200
    assert bot.post("/replay/demo", headers=headers).status_code == 403
    assert bot.get("/audit", headers=headers).status_code == 403
    me = bot.get("/auth/me", headers=headers).json()
    assert me["via"] == "token" and me["name"] == "token:siem" and me["role"] == "viewer" and me["csrf_token"] is None
    accounts.revoke_token("siem")
    assert bot.get("/alerts", headers=headers).status_code == 401
    soon, _ = accounts.create_token("short", "viewer", expires_at=datetime.now(timezone.utc) + timedelta(hours=1))
    assert bot.get("/alerts", headers={"X-API-Key": soon}).status_code == 200
    real_clock = accounts.clock
    accounts.clock = lambda: real_clock() + timedelta(hours=2)
    try:
        assert bot.get("/alerts", headers={"X-API-Key": soon}).status_code == 401
    finally:
        accounts.clock = real_clock
    denied = _audit(client, action="access.denied")
    assert {e["actor"] for e in denied} == {"token:siem"} and {e["target"] for e in denied} == {
        "POST /replay/demo", "GET /audit"}
    assert len(_audit(client, action="auth.token", outcome="failure")) == 2


def test_wrong_api_key_is_not_ignored_in_favour_of_a_cookie(api_client):
    client, _ = api_client
    assert client.get("/alerts").status_code == 200
    assert client.get("/alerts", headers={"X-API-Key": "us_not-a-token"}).status_code == 401


# --- user management ------------------------------------------------------------------------

def test_user_management_via_api(api_client):
    client, _ = api_client
    created = client.post("/users", json={"username": "Bob", "role": "viewer", "password": TEST_PASSWORD})
    assert created.status_code == 201 and created.json()["username"] == "bob"
    assert "password" not in str(created.json()).replace("password_changed_at", "")
    assert client.post("/users", json={"username": "bob", "role": "viewer",
                                       "password": TEST_PASSWORD}).status_code == 409
    assert client.post("/users", json={"username": "carol", "role": "viewer", "password": "short"}).status_code == 422
    assert client.post("/users", json={"username": "carol", "role": "root",
                                       "password": TEST_PASSWORD}).status_code == 422

    bob = _new_client(client)
    login(bob, "bob")
    assert bob.get("/alerts").status_code == 200
    assert client.patch("/users/bob", json={"role": "analyst"}).json()["role"] == "analyst"
    assert bob.get("/alerts").status_code == 401                           # role change ends sessions
    login(bob, "bob")
    assert client.patch("/users/bob", json={"disabled": True}).json()["disabled"] is True
    assert bob.get("/alerts").status_code == 401
    assert client.patch("/users/bob", json={"disabled": False, "password": "reset by the admin"}).status_code == 200
    login(bob, "bob", "reset by the admin")

    assert client.patch("/users/admin", json={"role": "viewer"}).status_code == 409   # last administrator
    assert client.delete("/users/admin").status_code == 409
    assert client.patch("/users/ghost", json={"role": "viewer"}).status_code == 404
    assert client.delete("/users/ghost").status_code == 404
    assert client.patch("/users/bad%20name", json={}).status_code == 422
    assert client.delete("/users/bob").status_code == 204
    assert [u["username"] for u in client.get("/users").json()] == ["admin"]

    entries = _audit(client, action="user.")
    assert [(e["action"], e["outcome"], e["target"]) for e in entries][::-1] == [
        ("user.create", "success", "bob"), ("user.create", "failure", "bob"), ("user.create", "failure", "carol"),
        ("user.update", "success", "bob"), ("user.update", "success", "bob"), ("user.update", "success", "bob"),
        ("user.update", "failure", "admin"), ("user.delete", "failure", "admin"), ("user.update", "failure", "ghost"),
        ("user.delete", "failure", "ghost"), ("user.delete", "success", "bob")]
    assert all(e["actor"] == "admin" and e["role"] == "admin" for e in entries)
    assert entries[-4]["details"] == {"role": ["viewer", "analyst"]}


# --- audit of operational actions ---------------------------------------------------------------

def test_replay_and_deletion_are_audited(api_client):
    client, _ = api_client
    client.post("/replay/demo", params={"scenario": "port_scan", "wait": True})
    client.post("/replay/stop")
    deleted = client.delete("/alerts").json()["deleted"]
    entries = {e["action"]: e for e in _audit(client)}
    demo = entries["replay.demo"]
    assert demo["target"] == "synthetic:port_scan:7" and demo["details"]["run_id"].startswith("run-")
    assert demo["details"]["detection_mode"] == "rules" and demo["client_ip"] == "127.0.0.1"
    assert entries["alerts.delete"]["details"] == {"deleted": deleted} and deleted > 0
    assert "replay.stop" not in entries                                    # nothing was running


def test_audit_endpoint_filters_and_is_read_only(api_client, client_as):
    client, _ = api_client
    client_as("viewer").get("/audit")                                       # denied, and audited
    response = client.get("/audit", params={"limit": 1})
    assert int(response.headers["X-Total-Count"]) >= 2 and len(response.json()) == 1
    assert client.get("/audit", params={"outcome": "denied"}).json()[0]["action"] == "access.denied"
    assert client.get("/audit", params={"action": "DROP TABLE"}).status_code == 422
    for method in ("post", "put", "patch", "delete"):
        assert getattr(client, method)("/audit").status_code == 405
    ops = client.app.openapi()["paths"]["/audit"]
    assert set(ops) == {"get"}


def test_intel_and_export_actions_are_audited_and_admin_only(api_client, client_as):
    client, _ = api_client
    viewer = client_as("viewer")
    assert viewer.get("/intel/status").status_code == 200 and viewer.get("/outputs/status").status_code == 200
    assert viewer.post("/intel/import", params={"source": "feed"}, content=b"198.51.100.7\n").status_code == 403
    assert viewer.post("/export").status_code == 403
    assert client.post("/intel/import", params={"source": "feed"}, content=b"198.51.100.7\n").status_code == 200
    assert client.post("/intel/import", params={"source": "bad", "format": "stix"}, content=b"{x").status_code == 400
    assert client.delete("/intel/sources/feed").json()["removed"] == 1
    assert client.post("/export", params={"formats": ["jsonl"]}).status_code == 200
    entries = {(e["action"], e["outcome"], e["target"]): e for e in _audit(client, action="intel.")}
    assert entries[("intel.import", "success", "feed")]["details"]["accepted"] == 1
    assert ("intel.import", "failure", "bad") in entries and ("intel.remove", "success", "feed") in entries
    (export,) = _audit(client, action="export.files")
    assert export["actor"] == "admin" and export["details"]["formats"] == ["jsonl"]
    assert {e["target"] for e in _audit(client, action="access.denied")} == {"POST /intel/import", "POST /export"}
