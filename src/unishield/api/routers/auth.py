"""
Login endpoints: log in and out, who am I, change my password.

``POST /auth/login`` takes a JSON body (a cross-site HTML form cannot send
one) and sets the session cookie: HttpOnly, SameSite=Strict, Path=/, and
Secure when the request arrived over HTTPS (``auth.cookie_secure``). The
response carries the CSRF token the dashboard must send in ``X-CSRF-Token``
with every state-changing request. Unknown users, wrong passwords, locked
and disabled accounts all get the same answer; the audit log records which.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field

from unishield.accounts import AccountError, passwords
from unishield.api.deps import get_context
from unishield.api.security import (
    ANONYMOUS,
    SESSION_COOKIE,
    Principal,
    audit,
    auth_mode,
    client_ip,
    cookie_secure,
    public,
    require_viewer,
    resolve_principal,
)
from unishield.api.state import AppContext
from unishield.config import get_config

router = APIRouter(prefix="/auth", tags=["auth"])

_FAILED = "Invalid username or password, or the account is temporarily locked"


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=passwords.MAX_PASSWORD_LENGTH)


class PasswordChange(BaseModel):
    current_password: str = Field(min_length=1, max_length=passwords.MAX_PASSWORD_LENGTH)
    new_password: str = Field(min_length=1, max_length=passwords.MAX_PASSWORD_LENGTH)


def _session_body(principal: Principal) -> dict[str, Any]:
    session = principal.session
    return {
        "mode": auth_mode(),
        "authenticated": principal.authenticated,
        "via": {"user": "session", "token": "token"}.get(principal.kind),
        "user": session.user.public() if session else None,
        "name": principal.actor if principal.authenticated else None,
        "role": principal.role.value if principal.role else None,
        "effective_role": (principal.role.value if principal.role
                           else "viewer" if auth_mode() == "open" else None),
        "csrf_token": session.csrf_token if session else None,
        "expires_at": session.expires_at.isoformat() if session else None,
        "idle_timeout_minutes": get_config().auth.session_idle_minutes if session else None,
    }


@router.post("/login", summary="Log in and receive a session cookie", dependencies=[Depends(public)])
def login(body: LoginRequest, request: Request, response: Response,
          ctx: AppContext = Depends(get_context)) -> dict[str, Any]:
    cfg = get_config().auth
    ip = client_ip(request) or "unknown"
    username = body.username.strip().lower()
    wait = ctx.limiter.retry_after(ip)
    if wait:
        raise HTTPException(status_code=429, detail="Too many failed attempts; try again later",
                            headers={"Retry-After": str(max(1, int(wait + 0.999)))})
    result = ctx.accounts.authenticate(username, body.password, cfg.max_failed_logins, cfg.lockout_minutes)
    if not result.ok:
        blocked = ctx.limiter.failure(ip)
        audit(request, "auth.login", "failure", principal=ANONYMOUS, target=username[:64],
              details={"reason": result.reason, "address_blocked": blocked})
        if result.locked_now:
            audit(request, "auth.lockout", "success", principal=ANONYMOUS, target=username,
                  details={"failed_logins": cfg.max_failed_logins, "minutes": cfg.lockout_minutes})
        raise HTTPException(status_code=401, detail=_FAILED)

    old = request.cookies.get(SESSION_COOKIE)
    if old:                                            # never keep a pre-login session id
        previous = ctx.accounts.resolve_session(old, cfg.session_idle_minutes)
        if previous is not None:
            ctx.accounts.delete_session(previous.id)
    raw, session = ctx.accounts.create_session(result.user, cfg.session_ttl_minutes, ip,
                                               request.headers.get("user-agent"))
    response.set_cookie(SESSION_COOKIE, raw, max_age=cfg.session_ttl_minutes * 60, path="/",
                        secure=cookie_secure(request), httponly=True, samesite="strict")
    principal = Principal("user", result.user.username, result.user.role, session=session)
    request.state.principal = principal
    audit(request, "auth.login", "success", principal=principal)
    return _session_body(principal)


@router.post("/logout", summary="End the current session", dependencies=[Depends(public)])
def logout(request: Request, response: Response, ctx: AppContext = Depends(get_context)) -> dict[str, Any]:
    principal = resolve_principal(request)
    if principal.session is not None:
        # CSRF still applies: a foreign page must not be able to log users out.
        require_viewer(request)
        ctx.accounts.delete_session(principal.session.id)
        audit(request, "auth.logout", principal=principal)
    response.delete_cookie(SESSION_COOKIE, path="/", secure=cookie_secure(request), httponly=True,
                           samesite="strict")
    return {"status": "logged_out"}


@router.get("/me", summary="The caller's identity, role and CSRF token", dependencies=[Depends(public)])
def me(request: Request) -> dict[str, Any]:
    return _session_body(resolve_principal(request))


@router.post("/password", summary="Change your own password (ends your other sessions)")
def change_password(body: PasswordChange, request: Request,
                    principal: Principal = Depends(require_viewer),
                    ctx: AppContext = Depends(get_context)) -> dict[str, Any]:
    if principal.session is None:
        raise HTTPException(status_code=403, detail="Change passwords from an interactive login")
    cfg = get_config().auth
    username = principal.session.user.username
    check = ctx.accounts.authenticate(username, body.current_password, cfg.max_failed_logins, cfg.lockout_minutes)
    if not check.ok:
        audit(request, "auth.password_change", "failure", target=username, details={"reason": check.reason})
        if check.locked_now:
            audit(request, "auth.lockout", target=username,
                  details={"failed_logins": cfg.max_failed_logins, "minutes": cfg.lockout_minutes})
        raise HTTPException(status_code=403, detail="Current password is wrong")
    try:
        ctx.accounts.set_password(username, body.new_password, cfg.min_password_length,
                                  keep_session_id=principal.session.id)
    except AccountError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None
    audit(request, "auth.password_change", target=username)
    return {"status": "changed", "other_sessions_ended": True}
