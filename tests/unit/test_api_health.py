"""
UniShield — Unit Tests for the module-level application without a login

The health check and the login endpoints answer anonymous callers; every
data endpoint asks for a login (accounts mode is the default).
"""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from unishield.api.app import app


@pytest.fixture
def anyio_backend():
    return "asyncio"


async def _get(path: str):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        return await client.get(path)


@pytest.mark.asyncio
async def test_health_endpoint_returns_200():
    response = await _get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] in ("healthy", "degraded")
    assert data["version"] == "0.1.0"


@pytest.mark.asyncio
async def test_health_confirms_security_constraints():
    data = (await _get("/health")).json()
    assert data["read_only_mode"] is True
    assert data["no_payload_decryption"] is True
    assert data["no_active_scanning"] is True
    assert data["no_response_path"] is True


@pytest.mark.asyncio
async def test_health_has_uptime():
    data = (await _get("/health")).json()
    assert data["uptime_seconds"] >= 0


@pytest.mark.asyncio
@pytest.mark.parametrize("path", ["/metrics", "/alerts", "/alerts/summary", "/alerts/NONEXISTENT-ID",
                                  "/replay/status", "/benchmark/latest", "/audit", "/users"])
async def test_data_endpoints_need_a_login(path):
    response = await _get(path)
    assert response.status_code == 401
    assert response.json()["detail"] == "Login required"


@pytest.mark.asyncio
async def test_me_reports_an_anonymous_caller():
    data = (await _get("/auth/me")).json()
    assert data["mode"] == "accounts" and data["authenticated"] is False and data["role"] is None


@pytest.mark.asyncio
async def test_dashboard_page_and_docs_are_served():
    assert (await _get("/dashboard")).status_code == 200
    assert (await _get("/docs")).status_code == 200
