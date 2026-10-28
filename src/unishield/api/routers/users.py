"""
User management (administrators with an interactive login only).

Service tokens cannot reach these routes, so an automation credential cannot
mint or promote accounts. Role, password and disabled-state changes end the
user's sessions; the last active administrator cannot be removed. Every
change is audited.
"""

from __future__ import annotations

from typing import Any, Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, Path, Request, Response
from pydantic import BaseModel, Field

from unishield.accounts import AccountConflict, AccountError, passwords
from unishield.api.deps import get_context
from unishield.api.security import Principal, audit, require_admin_session
from unishield.api.state import AppContext
from unishield.config import get_config

router = APIRouter(prefix="/users", tags=["users"])

RoleName = Literal["viewer", "analyst", "admin"]
_USERNAME = Path(..., min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_.-]+$")


class UserCreate(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    role: RoleName
    password: str = Field(min_length=1, max_length=passwords.MAX_PASSWORD_LENGTH)


class UserUpdate(BaseModel):
    role: Optional[RoleName] = None
    disabled: Optional[bool] = None
    password: Optional[str] = Field(default=None, min_length=1, max_length=passwords.MAX_PASSWORD_LENGTH)
    unlock: bool = False


def _failed(exc: Exception) -> HTTPException:
    if isinstance(exc, AccountError):
        return HTTPException(status_code=422, detail=str(exc))
    message = str(exc)
    return HTTPException(status_code=404 if message.startswith("No user") else 409, detail=message)


@router.get("", summary="List users")
def list_users(ctx: AppContext = Depends(get_context),
               _: Principal = Depends(require_admin_session)) -> list[dict[str, Any]]:
    now = ctx.accounts.now()
    return [u.public(now) for u in ctx.accounts.list_users()]


@router.post("", status_code=201, summary="Create a user")
def create_user(body: UserCreate, request: Request, ctx: AppContext = Depends(get_context),
                principal: Principal = Depends(require_admin_session)) -> dict[str, Any]:
    try:
        user = ctx.accounts.create_user(body.username, body.password, body.role, created_by=principal.actor,
                                        min_password_length=get_config().auth.min_password_length)
    except (AccountError, AccountConflict) as exc:
        audit(request, "user.create", "failure", target=body.username.lower()[:64], details={"error": str(exc)})
        raise _failed(exc) from None
    audit(request, "user.create", target=user.username, details={"role": user.role.value})
    return user.public()


@router.patch("/{username}", summary="Change role, disable/enable, reset password or unlock")
def update_user(body: UserUpdate, request: Request, username: str = _USERNAME,
                ctx: AppContext = Depends(get_context),
                principal: Principal = Depends(require_admin_session)) -> dict[str, Any]:
    cfg = get_config().auth
    changes: dict[str, Any] = {}
    try:
        if body.role is not None or body.disabled is not None:
            before, after = ctx.accounts.update_user(username, role=body.role, disabled=body.disabled)
            if before.role != after.role:
                changes["role"] = [before.role.value, after.role.value]
            if before.disabled != after.disabled:
                changes["disabled"] = [before.disabled, after.disabled]
        if body.password is not None:
            keep = principal.session.id if username.lower() == principal.name else None
            ctx.accounts.set_password(username, body.password, cfg.min_password_length, keep_session_id=keep)
            changes["password_reset"] = True
        if body.unlock:
            ctx.accounts.unlock(username)
            changes["unlocked"] = True
    except (AccountError, AccountConflict) as exc:
        audit(request, "user.update", "failure", target=username.lower(), details={"error": str(exc), **changes})
        raise _failed(exc) from None
    user = ctx.accounts.get_user(username)
    if user is None:
        raise HTTPException(status_code=404, detail=f"No user named {username.lower()!r}")
    if changes:
        audit(request, "user.update", target=user.username, details=changes)
    return user.public()


@router.delete("/{username}", status_code=204, summary="Delete a user (audit entries are kept)")
def delete_user(request: Request, username: str = _USERNAME, ctx: AppContext = Depends(get_context),
                _: Principal = Depends(require_admin_session)) -> Response:
    try:
        user = ctx.accounts.delete_user(username)
    except (AccountError, AccountConflict) as exc:
        audit(request, "user.delete", "failure", target=username.lower(), details={"error": str(exc)})
        raise _failed(exc) from None
    audit(request, "user.delete", target=user.username, details={"role": user.role.value})
    return Response(status_code=204)
