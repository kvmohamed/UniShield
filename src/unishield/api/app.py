"""
UniShield — FastAPI Application

Serves the dashboard and the read-only monitoring API; administrative
endpoints control local replay only.

SECURITY NOTICE:
    This API is a passive, read-only interface. It does NOT send packets,
    probe endpoints, decrypt payloads, or issue remediation commands.
    Administrative endpoints (replay, demo, clearing alerts) need the
    X-API-Key header, or a loopback client when no key is configured.
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse

from unishield import __app_name__, __version__
from unishield.api.routers import alerts, replay, system
from unishield.api.security import DASHBOARD_CSP, SECURITY_HEADERS, auth_mode
from unishield.api.state import AppContext
from unishield.config import get_config
from unishield.logging_config import setup_logging
from unishield.storage import AlertRepository

logger = logging.getLogger("unishield.api")

_DASHBOARD = Path(__file__).resolve().parent.parent / "dashboard" / "index.html"


def create_app(repository: AlertRepository | None = None) -> FastAPI:
    """Build the application. ``repository`` defaults to ``database.url`` (created on first use)."""

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        config = get_config()
        setup_logging(log_level=config.log_level)
        logger.info("UniShield API starting (env=%s, read_only=%s, admin auth=%s, detection mode=%s)",
                    config.environment, config.security.read_only_mode, auth_mode(),
                    config.models.detection_mode)
        yield
        ctx: AppContext = _app.state.ctx
        ctx.stop_replay()

    app = FastAPI(
        lifespan=lifespan,
        title=f"{__app_name__} API",
        description=(
            "Passive, read-only cybersecurity monitoring API for unidirectional networks. "
            "This system is a passive defensive research prototype. It does not probe, block, "
            "decrypt, or send commands to monitored systems."
        ),
        version=__version__,
        docs_url="/docs",
        redoc_url="/redoc",
    )
    app.state.ctx = AppContext(repository)

    origins = get_config().api.cors_origins
    if origins:
        app.add_middleware(CORSMiddleware, allow_origins=origins, allow_methods=["GET", "POST", "DELETE"],
                           allow_headers=["X-API-Key", "Content-Type"], expose_headers=["X-Total-Count"])

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        for name, value in SECURITY_HEADERS.items():
            response.headers.setdefault(name, value)
        if request.url.path in ("/", "/dashboard"):
            response.headers["Content-Security-Policy"] = DASHBOARD_CSP
        if request.url.path.startswith(("/alerts", "/incidents", "/metrics", "/replay")):
            response.headers.setdefault("Cache-Control", "no-store")
        return response

    @app.get("/", include_in_schema=False)
    @app.get("/dashboard", tags=["dashboard"], summary="Security dashboard")
    def serve_dashboard():
        if _DASHBOARD.is_file():
            return FileResponse(str(_DASHBOARD), media_type="text/html")
        return JSONResponse(status_code=404, content={"detail": "Dashboard not found"})

    app.include_router(system.router)
    app.include_router(alerts.router)
    app.include_router(replay.router)
    return app


app = create_app()
