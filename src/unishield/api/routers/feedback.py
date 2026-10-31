"""
Analyst feedback: explanations, verdicts, suppression rules and labelled exports.

Reading (explanations, verdicts, rules, the review summary) needs a viewer;
recording a verdict, creating or switching a suppression rule and exporting
labels need an analyst; deleting a rule needs an administrator. Every change
is audited. Suppression rules always expire and never drop alerts: matching
alerts are stored with ``suppressed_by`` and listed with
``GET /alerts?suppressed=only``.
"""

from __future__ import annotations

import csv
import io
import json
from typing import Any, Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from pydantic import BaseModel, Field

from unishield.api.deps import get_context
from unishield.api.security import audit, require_admin, require_analyst, require_viewer
from unishield.api.state import AppContext
from unishield.explain import explain
from unishield.schemas.alert import Alert, ThreatClass

router = APIRouter(tags=["feedback"])

Verdict = Literal["true_positive", "benign_true_positive", "false_positive"]
_EXPORT_COLUMNS = ("alert_id", "window_start", "window_end", "threat_class", "severity", "confidence",
                   "detector_name", "source_ip", "destination_ip", "source_type", "run_id", "verdict", "note",
                   "analyst", "reviewed_at")


class VerdictIn(BaseModel):
    verdict: Verdict
    note: Optional[str] = Field(default=None, max_length=2000)


class SuppressionIn(BaseModel):
    threat_class: ThreatClass
    source: Optional[str] = Field(default=None, max_length=64, description="IP, CIDR range or address hash")
    destination: Optional[str] = Field(default=None, max_length=64, description="IP, CIDR range or address hash")
    detector: Optional[str] = Field(default=None, max_length=64, pattern=r"^[a-z_]{1,64}$")
    reason: str = Field(min_length=5, max_length=500)
    days: int = Field(default=30, ge=1, le=365, description="expiry; at most feedback.max_suppression_days")
    from_alert_id: Optional[str] = Field(default=None, max_length=32)


class SuppressionPatch(BaseModel):
    enabled: bool


def _alert(ctx: AppContext, alert_id: str) -> Alert:
    alert = ctx.repository.get(alert_id) if len(alert_id) <= 32 else None
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert


def _actor(request: Request) -> str:
    principal = getattr(request.state, "principal", None)
    return principal.actor if principal is not None else "unknown"


@router.get("/alerts/{alert_id}/explanation", summary="Why the alert fired, in plain language",
            dependencies=[Depends(require_viewer)])
def alert_explanation(alert_id: str, ctx: AppContext = Depends(get_context)) -> dict[str, Any]:
    alert = _alert(ctx, alert_id)
    result = explain(alert)
    if alert.suppressed_by is not None:
        rule = ctx.suppressions.get(alert.suppressed_by)
        result["context"].append(f"Suppressed by rule {alert.suppressed_by}"
                                 + (f" ({rule['reason']}, by {rule['created_by']})." if rule else "."))
    return result


@router.get("/alerts/{alert_id}/verdict", summary="The analyst verdict on an alert",
            dependencies=[Depends(require_viewer)])
def get_verdict(alert_id: str, ctx: AppContext = Depends(get_context)) -> dict[str, Any]:
    _alert(ctx, alert_id)
    return ctx.feedback.get(alert_id) or {"alert_id": alert_id, "verdict": None}


@router.put("/alerts/{alert_id}/verdict", summary="Record a verdict (true/benign/false positive)",
            dependencies=[Depends(require_analyst)])
def put_verdict(alert_id: str, body: VerdictIn, request: Request,
                ctx: AppContext = Depends(get_context)) -> dict[str, Any]:
    alert = _alert(ctx, alert_id)
    previous = ctx.feedback.get(alert_id)
    saved = ctx.feedback.set_verdict(alert_id, body.verdict, _actor(request), body.note)
    audit(request, "alert.verdict", target=alert_id,
          details={"verdict": body.verdict, "previous": previous["verdict"] if previous else None,
                   "threat_class": alert.threat_class.value, "detector": alert.detector_name})
    return saved


@router.delete("/alerts/{alert_id}/verdict", summary="Remove the verdict from an alert",
               dependencies=[Depends(require_analyst)])
def delete_verdict(alert_id: str, request: Request, ctx: AppContext = Depends(get_context)) -> dict[str, Any]:
    _alert(ctx, alert_id)
    removed = ctx.feedback.clear(alert_id)
    if removed:
        audit(request, "alert.verdict.clear", target=alert_id)
    return {"alert_id": alert_id, "removed": removed}


@router.get("/feedback/verdicts", summary="Verdicts of several alerts", dependencies=[Depends(require_viewer)])
def verdicts(alert_id: list[str] = Query(default=[], max_length=200),
             ctx: AppContext = Depends(get_context)) -> dict[str, Any]:
    ids = [a for a in alert_id if len(a) <= 32]
    return {k: v["verdict"] for k, v in ctx.feedback.get_many(ids).items()}


@router.get("/feedback/summary", summary="Reviewed precision per detector and threat class",
            dependencies=[Depends(require_viewer)])
def feedback_summary(ctx: AppContext = Depends(get_context)) -> dict[str, Any]:
    return ctx.feedback.summary()


@router.get("/feedback/export", summary="Labelled alerts (reviewed by analysts) as CSV or JSON lines",
            dependencies=[Depends(require_analyst)])
def feedback_export(request: Request, format: Literal["csv", "jsonl"] = "csv", verdict: Optional[Verdict] = None,
                    ctx: AppContext = Depends(get_context)) -> Response:
    rows = ctx.feedback.labelled(verdict)
    if format == "jsonl":
        body = "".join(json.dumps(r, default=str) + "\n" for r in rows)
        media = "application/x-ndjson"
    else:
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=_EXPORT_COLUMNS, extrasaction="ignore", lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
        body, media = buf.getvalue(), "text/csv"
    audit(request, "feedback.export", details={"format": format, "verdict": verdict, "rows": len(rows)})
    return Response(body, media_type=media,
                    headers={"Content-Disposition": f'attachment; filename="unishield-labels.{format}"'})


@router.get("/suppressions", summary="Suppression rules", dependencies=[Depends(require_viewer)])
def list_suppressions(include_expired: bool = True, ctx: AppContext = Depends(get_context)) -> list[dict[str, Any]]:
    return ctx.suppressions.list(include_expired)


@router.post("/suppressions", summary="Suppress future alerts of one class for a source/destination",
             dependencies=[Depends(require_analyst)])
def create_suppression(body: SuppressionIn, request: Request,
                       ctx: AppContext = Depends(get_context)) -> dict[str, Any]:
    if body.from_alert_id is not None:
        _alert(ctx, body.from_alert_id)
    try:
        rule = ctx.suppressions.create(
            threat_class=body.threat_class.value, source=body.source, destination=body.destination,
            detector_name=body.detector, reason=body.reason, days=body.days, created_by=_actor(request),
            from_alert_id=body.from_alert_id)
    except ValueError as exc:
        audit(request, "suppression.create", "failure", details={"error": str(exc)})
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    audit(request, "suppression.create", target=str(rule["id"]),
          details={k: rule[k] for k in ("threat_class", "source", "destination", "detector_name", "reason",
                                        "expires_at", "from_alert_id")})
    return rule


@router.patch("/suppressions/{rule_id}", summary="Switch a suppression rule on or off",
              dependencies=[Depends(require_analyst)])
def patch_suppression(rule_id: int, body: SuppressionPatch, request: Request,
                      ctx: AppContext = Depends(get_context)) -> dict[str, Any]:
    rule = ctx.suppressions.set_enabled(rule_id, body.enabled)
    if rule is None:
        raise HTTPException(status_code=404, detail="Suppression rule not found")
    audit(request, "suppression.update", target=str(rule_id), details={"enabled": body.enabled})
    return rule


@router.delete("/suppressions/{rule_id}", summary="Delete a suppression rule", dependencies=[Depends(require_admin)])
def delete_suppression(rule_id: int, request: Request, ctx: AppContext = Depends(get_context)) -> dict[str, Any]:
    if not ctx.suppressions.delete(rule_id):
        raise HTTPException(status_code=404, detail="Suppression rule not found")
    audit(request, "suppression.delete", target=str(rule_id))
    return {"deleted": rule_id}
