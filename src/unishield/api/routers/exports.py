"""
Export and output-status endpoints.

POST /export writes stored alerts and their incidents to files (JSON lines,
CEF, STIX 2.1) under ``export.directory`` on the server; it sends nothing
anywhere. GET /outputs/status reports the export, syslog and notification
outputs (counters and configuration, never secrets).
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, Query

from unishield.api.deps import get_context
from unishield.api.security import require_admin
from unishield.api.state import AppContext
from unishield.config import get_config
from unishield.export.files import export_stored

router = APIRouter(tags=["exports"])

ExportFormat = Literal["jsonl", "cef", "stix"]


@router.post("/export", summary="Export stored alerts and incidents to files", dependencies=[Depends(require_admin)])
def export_now(
    formats: Optional[list[ExportFormat]] = Query(default=None, description="Default: export.formats"),
    since: Optional[datetime] = Query(default=None, description="window_end >= since (traffic time)"),
    until: Optional[datetime] = Query(default=None, description="window_end < until (traffic time)"),
    run_id: Optional[str] = Query(default=None, max_length=64, pattern=r"^[A-Za-z0-9_-]{1,64}$"),
    include_incidents: Optional[bool] = Query(default=None, description="Default: export.include_incidents"),
    max_alerts: int = Query(default=100_000, ge=1, le=1_000_000),
    ctx: AppContext = Depends(get_context),
) -> dict[str, Any]:
    """Write one set of export files to ``<export.directory>/on-demand`` and list them."""
    try:
        return export_stored(ctx.repository, get_config(), formats=formats, since=since, until=until,
                             run_id=run_id, include_incidents=include_incidents, max_alerts=max_alerts)
    except OSError as exc:
        raise HTTPException(status_code=500, detail=f"Export failed: {exc.strerror or type(exc).__name__}") from exc


@router.get("/outputs/status", summary="Export, syslog and notification status")
def outputs_status(ctx: AppContext = Depends(get_context)) -> dict[str, Any]:
    return ctx.outputs.status()
