"""Alert, incident and timeline endpoints (read-only except DELETE /alerts)."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Response

from unishield.api.deps import get_context
from unishield.api.security import require_admin
from unishield.api.state import AppContext
from unishield.correlation.correlator import AlertCorrelator
from unishield.schemas.alert import Alert, AlertSummary, Severity, ThreatClass
from unishield.storage import AlertQuery

router = APIRouter(tags=["alerts"])

_IP_PATTERN = r"^[0-9A-Fa-f:.]{2,64}$|^[0-9a-f]{8,64}$"      # IPv4 / IPv6 / anonymised hash


@router.get("/alerts", response_model=list[Alert], summary="List alerts")
def list_alerts(
    response: Response,
    threat_class: Optional[ThreatClass] = Query(default=None),
    severity: Optional[Severity] = Query(default=None),
    source_ip: Optional[str] = Query(default=None, max_length=64, pattern=_IP_PATTERN),
    destination_ip: Optional[str] = Query(default=None, max_length=64, pattern=_IP_PATTERN),
    detector: Optional[str] = Query(default=None, max_length=64, pattern=r"^[a-z_]{1,64}$"),
    run_id: Optional[str] = Query(default=None, max_length=64, pattern=r"^[A-Za-z0-9_-]{1,64}$"),
    since: Optional[datetime] = Query(default=None, description="window_end >= since (traffic time)"),
    until: Optional[datetime] = Query(default=None, description="window_end < until (traffic time)"),
    min_confidence: Optional[float] = Query(default=None, ge=0, le=1),
    sort: Literal["window_end", "timestamp", "severity", "confidence", "threat_class"] = "window_end",
    order: Literal["asc", "desc"] = "desc",
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0, le=10_000_000),
    ctx: AppContext = Depends(get_context),
) -> list[Alert]:
    """Filtered, sorted, paginated alerts. The total match count is in the X-Total-Count header."""
    items, total = ctx.repository.list(AlertQuery(
        threat_class=threat_class, severity=severity, source_ip=source_ip, destination_ip=destination_ip,
        detector_name=detector, run_id=run_id, since=since, until=until, min_confidence=min_confidence,
        sort=sort, descending=order == "desc", limit=limit, offset=offset,
    ))
    response.headers["X-Total-Count"] = str(total)
    return items


@router.get("/alerts/summary", response_model=AlertSummary, summary="Alert summary statistics")
def alerts_summary(ctx: AppContext = Depends(get_context)) -> AlertSummary:
    return ctx.repository.summary()


@router.get("/alerts/timeline", summary="Alert counts per severity over traffic time")
def alerts_timeline(bucket_sec: int = Query(default=60, ge=1, le=86_400),
                    ctx: AppContext = Depends(get_context)) -> dict[str, Any]:
    return {"bucket_sec": bucket_sec, "buckets": ctx.repository.timeline(bucket_sec)}


@router.get("/alerts/{alert_id}", response_model=Alert, summary="Get alert by ID")
def get_alert(alert_id: str, ctx: AppContext = Depends(get_context)) -> Alert:
    if len(alert_id) > 32:
        raise HTTPException(status_code=404, detail="Alert not found")
    alert = ctx.repository.get(alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert


@router.delete("/alerts", summary="Delete all stored alerts", dependencies=[Depends(require_admin)])
def delete_alerts(ctx: AppContext = Depends(get_context)) -> dict[str, Any]:
    if ctx.running:
        raise HTTPException(status_code=409, detail="Stop the running replay first")
    return {"deleted": ctx.repository.delete_all()}


@router.get("/threats/{threat_class}", response_model=list[Alert], summary="Alerts of one threat class")
def get_threats(threat_class: ThreatClass, limit: int = Query(default=100, ge=1, le=1000),
                ctx: AppContext = Depends(get_context)) -> list[Alert]:
    items, _ = ctx.repository.list(AlertQuery(threat_class=threat_class, limit=limit))
    return items


@router.get("/incidents", summary="Alerts grouped into incidents by entity and time")
def incidents(gap_sec: int = Query(default=300, ge=10, le=86_400),
              min_alerts: int = Query(default=2, ge=1, le=100),
              ctx: AppContext = Depends(get_context)) -> dict[str, Any]:
    alerts = ctx.repository.all(limit=20_000)
    correlator = AlertCorrelator(correlation_window_sec=gap_sec, min_alerts_for_incident=min_alerts)
    found = correlator.correlate(alerts)
    return {"incidents": found, "alerts_considered": len(alerts)}
