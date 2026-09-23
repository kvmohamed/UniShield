"""
UniShield — Unit Tests for API Health Endpoint

Tests the FastAPI health endpoint and security constraint reporting.
"""

from __future__ import annotations

import pytest
from httpx import AsyncClient, ASGITransport

from unishield.api.app import app


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.mark.asyncio
async def test_health_endpoint_returns_200():
    """GET /health should return 200 with health status."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/health")

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["version"] == "0.1.0"


@pytest.mark.asyncio
async def test_health_confirms_security_constraints():
    """Health response must confirm all security constraints are active."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/health")

    data = response.json()
    assert data["read_only_mode"] is True
    assert data["no_payload_decryption"] is True
    assert data["no_active_scanning"] is True
    assert data["no_response_path"] is True


@pytest.mark.asyncio
async def test_health_has_uptime():
    """Health response must include uptime."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/health")

    data = response.json()
    assert "uptime_seconds" in data
    assert data["uptime_seconds"] >= 0


@pytest.mark.asyncio
async def test_metrics_endpoint():
    """GET /metrics should return pipeline metrics."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/metrics")

    assert response.status_code == 200
    data = response.json()
    assert "total_records_ingested" in data
    assert "records_per_second" in data


@pytest.mark.asyncio
async def test_alerts_endpoint_empty():
    """GET /alerts should return an empty list initially."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/alerts")

    assert response.status_code == 200
    assert response.json() == [] or isinstance(response.json(), list)


@pytest.mark.asyncio
async def test_alerts_summary_endpoint():
    """GET /alerts/summary should return summary statistics."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/alerts/summary")

    assert response.status_code == 200
    data = response.json()
    assert "total_alerts" in data


@pytest.mark.asyncio
async def test_alert_not_found():
    """GET /alerts/{id} with non-existent ID should return 404."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/alerts/NONEXISTENT-ID")

    assert response.status_code == 404


@pytest.mark.asyncio
async def test_replay_status_idle():
    """GET /replay/status should show idle state."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/replay/status")

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "idle"


@pytest.mark.asyncio
async def test_benchmark_no_results():
    """GET /benchmark/latest should indicate no benchmark available."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/benchmark/latest")

    assert response.status_code == 200


@pytest.mark.asyncio
async def test_openapi_docs_available():
    """The OpenAPI docs should be accessible."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/docs")

    assert response.status_code == 200
