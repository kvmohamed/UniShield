"""
Role enforcement on every route, generated from the OpenAPI schema.

A route added later is covered automatically: the application refuses to
build if the route has no guard, and these tests call every operation in
the schema as an anonymous caller, as each role, and with service tokens.
"""

from __future__ import annotations

import re

import pytest
from fastapi import APIRouter, Depends, FastAPI

from unishield.api.security import enforce_route_guards, public, require_admin, require_viewer

pytestmark = pytest.mark.security

RANK = {"viewer": 1, "analyst": 2, "admin": 3}
PUBLIC = {("GET", "/dashboard"), ("GET", "/health"), ("POST", "/auth/login"), ("POST", "/auth/logout"),
          ("GET", "/auth/me")}
PATH_VALUES = {"alert_id": "US-NOPE0000", "threat_class": "PORT_SCAN", "username": "nobody", "source": "nofeed"}


def operations(app):
    for path, ops in app.openapi()["paths"].items():
        for method, op in ops.items():
            yield method.upper(), path, op


def concrete(path: str) -> str:
    return re.sub(r"\{(\w+)\}", lambda m: PATH_VALUES[m.group(1)], path)


def call(client, method, path, **kwargs):
    return client.request(method, concrete(path), **kwargs)


def test_every_operation_declares_a_role(api_client):
    client, _ = api_client
    ops = list(operations(client.app))
    assert len(ops) >= 28
    for method, path, op in ops:
        assert op.get("x-unishield-role") in {"public", "viewer", "analyst", "admin"}, (method, path)
    assert {(m, p) for m, p, op in ops if op["x-unishield-role"] == "public"} == PUBLIC


def test_anonymous_callers_are_refused_on_every_guarded_route(api_client, client_as):
    client, _ = api_client
    anonymous = client_as(None, address=("203.0.113.9", 1))
    for method, path, op in operations(client.app):
        if op["x-unishield-role"] == "public":
            continue
        response = call(anonymous, method, path)
        assert response.status_code == 401, (method, path, response.text)


@pytest.mark.parametrize("role", ["viewer", "analyst"])
def test_lower_roles_are_refused(api_client, client_as, role):
    client, _ = api_client
    caller = client_as(role)
    checked = 0
    for method, path, op in operations(client.app):
        required = op["x-unishield-role"]
        if required != "public" and RANK[required] > RANK[role]:
            response = call(caller, method, path)
            assert response.status_code == 403, (role, method, path, response.text)
            checked += 1
    assert checked >= 9


@pytest.mark.parametrize("role", ["viewer", "analyst", "admin"])
def test_sufficient_roles_get_past_the_guard(api_client, client_as, role):
    """Requests may still fail validation (422/404/409/403 for a path outside data/), never authorisation."""
    client, _ = api_client
    caller = client_as(role)
    for method, path, op in operations(client.app):
        required = op["x-unishield-role"]
        if required == "public" or RANK[required] > RANK[role]:
            continue
        response = call(caller, method, path)
        detail = str(response.json().get("detail", "")) if response.status_code >= 400 else ""
        assert response.status_code != 401, (role, method, path)
        assert response.status_code != 403 or "data directories" in detail, (role, method, path, detail)
    client.app.state.ctx.reset()                          # a demo replay may have started


@pytest.mark.parametrize("role", ["viewer", "analyst", "admin"])
def test_service_tokens_follow_their_role_and_never_reach_session_only_routes(api_client, role):
    from fastapi.testclient import TestClient

    client, _ = api_client
    raw, _ = client.app.state.ctx.accounts.create_token(f"bot-{role}", role)
    bot = TestClient(client.app, client=("198.51.100.30", 1), headers={"X-API-Key": raw})
    for method, path, op in operations(client.app):
        required = op["x-unishield-role"]
        if required == "public":
            continue
        response = call(bot, method, path)
        if RANK[required] > RANK[role] or op.get("x-unishield-sessions-only"):
            assert response.status_code == 403, (role, method, path)
        else:
            assert response.status_code not in (401, 403) or "data directories" in response.text, (role, method, path)
    client.app.state.ctx.reset()


def test_application_refuses_unguarded_routes():
    app = FastAPI()

    @app.get("/unguarded")
    def unguarded():
        return {}

    with pytest.raises(RuntimeError, match="no access guard"):
        enforce_route_guards(app)

    router = APIRouter()

    @router.get("/nested")
    def nested():
        return {}

    app = FastAPI()
    app.include_router(router, prefix="/x")
    with pytest.raises(RuntimeError, match="/nested"):
        enforce_route_guards(app)

    app = FastAPI()

    @app.get("/both", dependencies=[Depends(public), Depends(require_admin)])
    def both():
        return {}

    with pytest.raises(RuntimeError, match="more than one guard"):
        enforce_route_guards(app)

    app = FastAPI()

    @app.get("/ok", dependencies=[Depends(require_viewer)])
    def ok():
        return {}

    enforce_route_guards(app)
    assert app.openapi()["paths"]["/ok"]["get"]["x-unishield-role"] == "viewer"
