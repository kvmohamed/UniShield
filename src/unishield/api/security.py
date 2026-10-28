"""
UniShield — API Security

Who is calling (``resolve_principal``):

    X-API-Key header   a service token from ``unishield-admin token create``,
                       or the static UNISHIELD_ADMIN_API_KEY (role
                       ``api.api_key_role``); a wrong key is refused, never
                       ignored in favour of a cookie
    session cookie     an interactive login (``POST /auth/login``)
    neither            anonymous

What they may do: every route declares exactly one guard. ``require_viewer``
/ ``require_analyst`` / ``require_admin`` admit principals whose role is at
least that role (``require_admin_session`` additionally refuses service
tokens, so automation cannot manage accounts); ``public`` marks the few
routes that need no login (health, login, the dashboard page).
``enforce_route_guards`` refuses to build an application with an unguarded
route, and records each route's role in the OpenAPI schema
(``x-unishield-role``), from which the tests check every route.

In ``auth.mode: open`` (lab only) anonymous callers are treated as viewers.

State-changing requests made with a session cookie must echo the session's
CSRF token in ``X-CSRF-Token``; the cookie is HttpOnly and SameSite=Strict,
and any request carrying a foreign ``Origin`` header is refused before it
reaches a route. Responses carry hardening headers, and the dashboard a
strict same-origin Content-Security-Policy.
"""

from __future__ import annotations

import hmac
import logging
from dataclasses import dataclass
from typing import Any, Optional
from urllib.parse import urlsplit

from fastapi import FastAPI, HTTPException, Request
from fastapi.routing import APIRoute

from unishield.accounts import Role, ServiceToken, Session
from unishield.config import get_config

logger = logging.getLogger("unishield.api.security")

SESSION_COOKIE = "unishield_session"
CSRF_HEADER = "X-CSRF-Token"
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})

DASHBOARD_CSP = (
    "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
)

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Opener-Policy": "same-origin",
}


@dataclass(frozen=True)
class Principal:
    kind: str                                # user | token | anonymous
    name: str
    role: Optional[Role]
    session: Optional[Session] = None
    token: Optional[ServiceToken] = None

    @property
    def actor(self) -> str:
        return f"token:{self.name}" if self.kind == "token" else self.name

    @property
    def authenticated(self) -> bool:
        return self.kind != "anonymous"


ANONYMOUS = Principal("anonymous", "anonymous", None)


def auth_mode() -> str:
    return get_config().auth.mode


def client_ip(request: Request) -> Optional[str]:
    return request.client.host if request.client else None


def cookie_secure(request: Request) -> bool:
    policy = get_config().auth.cookie_secure
    return policy == "always" or (policy == "auto" and request.url.scheme == "https")


def origin_allowed(request: Request) -> bool:
    """False if the request names a foreign Origin (a cross-site page); requests without Origin pass."""
    origin = request.headers.get("origin")
    if origin is None:
        return True
    if origin in get_config().api.cors_origins:
        return True
    host = request.headers.get("host", "")
    return bool(host) and urlsplit(origin).netloc.lower() == host.lower()


def audit(request: Request, action: str, outcome: str = "success", *, target: Optional[str] = None,
          details: Optional[dict[str, Any]] = None, principal: Optional[Principal] = None) -> None:
    """Record an audit entry for the caller of ``request``."""
    principal = principal or getattr(request.state, "principal", None) or ANONYMOUS
    ctx = request.app.state.ctx
    ctx.audit.record(action, outcome, actor=principal.actor, actor_type=principal.kind,
                     role=principal.role.value if principal.role else None, target=target,
                     client_ip=client_ip(request), details=details)


def _too_many(retry_after: float) -> HTTPException:
    return HTTPException(status_code=429, detail="Too many failed attempts; try again later",
                         headers={"Retry-After": str(max(1, int(retry_after + 0.999)))})


def resolve_principal(request: Request) -> Principal:
    """Identify the caller (cached per request). Raises 401 for a wrong X-API-Key, 429 when throttled."""
    cached = getattr(request.state, "principal", None)
    if cached is not None:
        return cached
    config = get_config()
    ctx = request.app.state.ctx
    key = request.headers.get("x-api-key")
    principal = ANONYMOUS
    if key is not None:
        ip = client_ip(request) or "unknown"
        wait = ctx.limiter.retry_after(ip)
        if wait:
            raise _too_many(wait)
        static = config.api.admin_api_key
        if static and hmac.compare_digest(key.encode(), static.encode()):
            principal = Principal("token", "env", Role(config.api.api_key_role))
        else:
            token = ctx.accounts.resolve_token(key)
            if token is None:
                # Throttled addresses were refused above, so this records at most
                # auth.login_rate_limit entries per address and window.
                blocked = ctx.limiter.failure(ip)
                audit(request, "auth.token", "failure", principal=ANONYMOUS,
                      details={"reason": "invalid_or_revoked", "address_blocked": blocked})
                raise HTTPException(status_code=401, detail="Invalid, expired or revoked X-API-Key",
                                    headers={"WWW-Authenticate": 'API-Key realm="UniShield"'})
            principal = Principal("token", token.name, token.role, token=token)
    else:
        raw = request.cookies.get(SESSION_COOKIE)
        if raw:
            session = ctx.accounts.resolve_session(raw, config.auth.session_idle_minutes)
            if session is not None:
                principal = Principal("user", session.user.username, session.user.role, session=session)
    request.state.principal = principal
    return principal


class RoleGuard:
    """Dependency admitting principals with at least ``role``; returns the Principal."""

    def __init__(self, role: Role, sessions_only: bool = False):
        self.role = role
        self.sessions_only = sessions_only

    def __repr__(self) -> str:
        return f"RoleGuard({self.role.value}{', sessions only' if self.sessions_only else ''})"

    def __call__(self, request: Request) -> Principal:
        principal = resolve_principal(request)
        if not principal.authenticated:
            if self.role == Role.VIEWER and auth_mode() == "open":
                return principal
            raise HTTPException(status_code=401, detail="Login required",
                                headers={"WWW-Authenticate": 'API-Key realm="UniShield"'})
        target = f"{request.method} {request.url.path}"
        if self.sessions_only and principal.kind != "user":
            audit(request, "access.denied", "denied", target=target,
                  details={"required": f"{self.role.value} login session", "via": principal.kind})
            raise HTTPException(status_code=403, detail="This endpoint needs an interactive login, not a token")
        if not principal.role.allows(self.role):
            audit(request, "access.denied", "denied", target=target, details={"required": self.role.value})
            raise HTTPException(status_code=403, detail=f"Requires the {self.role.value} role")
        if request.method not in SAFE_METHODS and principal.session is not None:
            sent = request.headers.get(CSRF_HEADER.lower(), "")
            if not hmac.compare_digest(sent.encode(), principal.session.csrf_token.encode()):
                audit(request, "auth.csrf_rejected", "denied", target=target)
                raise HTTPException(status_code=403, detail="Missing or invalid CSRF token")
        return principal


class Public:
    """Marks a route that deliberately needs no login."""

    def __repr__(self) -> str:
        return "public"

    def __call__(self) -> None:
        return None


require_viewer = RoleGuard(Role.VIEWER)
require_analyst = RoleGuard(Role.ANALYST)
require_admin = RoleGuard(Role.ADMIN)
require_admin_session = RoleGuard(Role.ADMIN, sessions_only=True)
public = Public()


def route_guard(route: APIRoute) -> RoleGuard | Public | None:
    guards = [d.call for d in route.dependant.dependencies if isinstance(d.call, (RoleGuard, Public))]
    if len(guards) > 1:
        raise RuntimeError(f"Route {sorted(route.methods)} {route.path} declares more than one guard: {guards}")
    return guards[0] if guards else None


def _api_routes(routes) -> list[APIRoute]:
    """APIRoutes of an app or router, descending into included routers (FastAPI keeps them nested)."""
    found = []
    for route in routes:
        if isinstance(route, APIRoute):
            found.append(route)
        elif getattr(route, "original_router", None) is not None:
            found.extend(_api_routes(route.original_router.routes))
    return found


def enforce_route_guards(app: FastAPI) -> None:
    """Refuse an application with an unguarded route; record each route's role in OpenAPI.
    Call it after including every router and before the app serves a request."""
    for route in _api_routes(app.routes):
        guard = route_guard(route)
        if guard is None:
            raise RuntimeError(f"Route {sorted(route.methods)} {route.path} has no access guard: add "
                               f"Depends(require_viewer/analyst/admin) or Depends(public)")
        role = "public" if isinstance(guard, Public) else guard.role.value
        extra = dict(route.openapi_extra or {}, **{"x-unishield-role": role})
        if isinstance(guard, RoleGuard) and guard.sessions_only:
            extra["x-unishield-sessions-only"] = True
        route.openapi_extra = extra
