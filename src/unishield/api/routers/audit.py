"""Audit log endpoint (administrators). Read-only: no route changes or removes entries."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal, Optional

from fastapi import APIRouter, Depends, Query, Response

from unishield.api.deps import get_context
from unishield.api.security import require_admin
from unishield.api.state import AppContext
from unishield.storage import AuditQuery

router = APIRouter(tags=["audit"])


@router.get("/audit", summary="Audit log, newest first", dependencies=[Depends(require_admin)])
def list_audit(
    response: Response,
    action: Optional[str] = Query(default=None, max_length=64, pattern=r"^[a-z_.]{1,64}$",
                                  description="exact action, or a prefix ending in '.' (e.g. auth.)"),
    actor: Optional[str] = Query(default=None, max_length=128, pattern=r"^[A-Za-z0-9_.:@-]{1,128}$"),
    outcome: Optional[Literal["success", "failure", "denied"]] = None,
    since: Optional[datetime] = None,
    until: Optional[datetime] = None,
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0, le=10_000_000),
    ctx: AppContext = Depends(get_context),
) -> list[dict[str, Any]]:
    """Filtered, paginated audit entries. The total match count is in the X-Total-Count header."""
    entries, total = ctx.audit.list(AuditQuery(action=action, actor=actor, outcome=outcome, since=since,
                                               until=until, limit=limit, offset=offset))
    response.headers["X-Total-Count"] = str(total)
    return entries
