"""
UniShield — API Security

Administrative endpoints (start/stop replay, demo, clearing alerts) only
control local analysis, but they still change server state, so they need:

    - the ``X-API-Key`` header matching ``UNISHIELD_ADMIN_API_KEY`` (compared
      in constant time), or
    - when no key is configured, a loopback client (127.0.0.1 / ::1).

Read endpoints stay open so the dashboard can poll them. Responses carry
standard hardening headers; the dashboard additionally gets a strict
Content-Security-Policy (same-origin scripts, styles and requests only).
"""

from __future__ import annotations

import hmac
import ipaddress
from typing import Optional

from fastapi import Header, HTTPException, Request

from unishield.config import get_config

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


def _is_loopback(host: Optional[str]) -> bool:
    if not host:
        return False
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def auth_mode() -> str:
    return "api_key" if get_config().api.admin_api_key else "loopback_only"


async def require_admin(request: Request, x_api_key: Optional[str] = Header(default=None)) -> None:
    """FastAPI dependency guarding administrative endpoints."""
    expected = get_config().api.admin_api_key
    if expected:
        if not x_api_key or not hmac.compare_digest(x_api_key.encode(), expected.encode()):
            raise HTTPException(status_code=401, detail="Missing or invalid X-API-Key",
                                headers={"WWW-Authenticate": "API-Key"})
        return
    client = request.client.host if request.client else None
    if not _is_loopback(client):
        raise HTTPException(
            status_code=403,
            detail="Administrative endpoints accept loopback clients only; "
                   "set UNISHIELD_ADMIN_API_KEY to allow remote use with the X-API-Key header",
        )
