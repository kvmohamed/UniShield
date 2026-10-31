"""
UniShield — FastAPI Application

Serves the dashboard and the monitoring API; administrative endpoints
control local replay, stored data and accounts only.

SECURITY NOTICE:
    This API is a passive, read-only interface. It does NOT send packets,
    probe endpoints, decrypt payloads, or issue remediation commands.
    Optional exports and notifications go only to allow-listed analyst-side
    destinations (see unishield.export). Every route needs a login session
    or a service token with a sufficient role (viewer / analyst / admin),
    except /health, the login endpoints and the dashboard page; see
    api/security.py.
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse

from unishield import __app_name__, __version__
from unishield.api.routers import alerts, audit, auth, exports, feedback, intel, live, replay, system, users
from unishield.api.security import (
    CSRF_HEADER,
    DASHBOARD_CSP,
    SAFE_METHODS,
    SECURITY_HEADERS,
    auth_mode,
    enforce_route_guards,
    hsts_header,
    origin_allowed,
    public,
)
from unishield.api.state import AppContext
from unishield.config import get_config
from unishield.logging_config import setup_logging
from unishield.storage import AlertRepository, migrate

logger = logging.getLogger("unishield.api")

_DASHBOARD = Path(__file__).resolve().parent.parent / "dashboard" / "index.html"
_NO_STORE = ("/alerts", "/incidents", "/metrics", "/replay", "/auth", "/users", "/audit", "/threats", "/export",
             "/outputs", "/intel")


def create_app(repository: AlertRepository | None = None) -> FastAPI:
    """Build the application. ``repository`` defaults to ``database.url`` (created on first use)."""

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        config = get_config()
        setup_logging(log_level=config.log_level)
        ctx: AppContext = _app.state.ctx
        if not migrate.is_current(ctx.repository.engine):
            raise RuntimeError(f"Database schema is at revision {migrate.current_revision(ctx.repository.engine)}, "
                               f"expected {migrate.head_revision()}: run 'unishield-admin db upgrade'")
        logger.info("UniShield API starting (env=%s, read_only=%s, auth mode=%s, detection mode=%s)",
                    config.environment, config.security.read_only_mode, auth_mode(),
                    config.models.detection_mode)
        if auth_mode() == "open":
            logger.warning("auth.mode is 'open' (lab only): read endpoints answer without a login")
        elif not ctx.accounts.has_users() and not config.api.admin_api_key:
            logger.warning("No user accounts exist: create an administrator with "
                           "'unishield-admin user create <name> --role admin'")
        ctx.start_services()
        yield
        result = ctx.shutdown(config.api.shutdown_timeout_sec)
        logger.info("UniShield API stopped (%s)", result)

    config = get_config()
    docs = config.api.docs_enabled
    app = FastAPI(
        lifespan=lifespan,
        title=f"{__app_name__} API",
        description=(
            "Passive, read-only cybersecurity monitoring API for unidirectional networks. "
            "This system is a passive defensive research prototype. It does not probe, block, "
            "decrypt, or send commands to monitored systems."
        ),
        version=__version__,
        docs_url="/docs" if docs else None,
        redoc_url="/redoc" if docs else None,
        openapi_url="/openapi.json" if docs else None,
    )
    app.state.ctx = AppContext(repository)

    origins = config.api.cors_origins
    if origins:
        app.add_middleware(CORSMiddleware, allow_origins=origins, allow_credentials=True,
                           allow_methods=["GET", "POST", "PATCH", "DELETE"],
                           allow_headers=["X-API-Key", CSRF_HEADER, "Content-Type"],
                           expose_headers=["X-Total-Count"])

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        if request.method not in SAFE_METHODS and not origin_allowed(request):
            response = JSONResponse(status_code=403, content={"detail": "Cross-origin request refused"})
        else:
            response = await call_next(request)
        for name, value in SECURITY_HEADERS.items():
            response.headers.setdefault(name, value)
        hsts = hsts_header(request)
        if hsts:
            response.headers.setdefault("Strict-Transport-Security", hsts)
        if request.url.path in ("/", "/dashboard"):
            response.headers["Content-Security-Policy"] = DASHBOARD_CSP
        if request.url.path.startswith(_NO_STORE):
            response.headers.setdefault("Cache-Control", "no-store")
        return response

    @app.get("/", include_in_schema=False, dependencies=[Depends(public)])
    @app.get("/dashboard", tags=["dashboard"], summary="Security dashboard (it asks for a login)",
             dependencies=[Depends(public)])
    def serve_dashboard():
        if _DASHBOARD.is_file():
            return FileResponse(str(_DASHBOARD), media_type="text/html")
        return JSONResponse(status_code=404, content={"detail": "Dashboard not found"})

    app.include_router(auth.router)
    app.include_router(system.router)
    app.include_router(alerts.router)
    app.include_router(feedback.router)
    app.include_router(replay.router)
    app.include_router(live.router)
    app.include_router(exports.router)
    app.include_router(intel.router)
    app.include_router(users.router)
    app.include_router(audit.router)
    enforce_route_guards(app)
    return app


app = create_app()
