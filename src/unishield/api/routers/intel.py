"""
Threat-intelligence endpoints: import operator-supplied indicator files and
report what is loaded. Nothing is downloaded: the file content is the
request body (plain text, CSV or a STIX 2.1 bundle), e.g.

    curl -X POST -H "X-API-Key: $KEY" --data-binary @feodo.csv \\
         "http://127.0.0.1:8000/intel/import?source=feodo&filename=feodo.csv"

Status needs the viewer role; imports, removals and purges need an
administrator (see api.security) and are audited. Indicators take effect
for the next replay.
"""

from __future__ import annotations

from typing import Any, Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from starlette.concurrency import run_in_threadpool

from unishield.api.deps import get_context
from unishield.api.security import audit, require_admin, require_viewer
from unishield.api.state import AppContext
from unishield.config import get_config
from unishield.intel.indicators import IndicatorError, parse_expiry
from unishield.intel.store import parse_options

router = APIRouter(tags=["intel"])

_SOURCE = r"^[A-Za-z0-9][A-Za-z0-9 ._:-]{0,127}$"


@router.get("/intel/status", summary="Imported threat-intelligence indicators per kind and source",
            dependencies=[Depends(require_viewer)])
def intel_status(ctx: AppContext = Depends(get_context)) -> dict[str, Any]:
    config = get_config()
    status = ctx.intel.status()
    status["enabled"] = config.intel.enabled
    status["escalate_severity"] = config.intel.escalate_severity
    status["anonymized_matching"] = config.security.anonymize_ips
    return status


@router.post("/intel/import", summary="Import an indicator file (request body)", dependencies=[Depends(require_admin)])
async def intel_import(
    request: Request,
    source: str = Query(..., pattern=_SOURCE, description="Source name; re-importing replaces it"),
    fmt: Literal["auto", "text", "csv", "stix"] = Query(default="auto", alias="format"),
    kind: Optional[Literal["ip", "cidr", "domain", "ja3"]] = Query(default=None, alias="type"),
    expires: Optional[str] = Query(default=None, max_length=40, description="Expiry for entries without one"),
    mode: Literal["replace", "append"] = Query(default="replace"),
    filename: Optional[str] = Query(default=None, max_length=256, description="Original name (format detection)"),
    ctx: AppContext = Depends(get_context),
) -> dict[str, Any]:
    config = get_config()
    limit = config.intel.max_file_mb * 1024 * 1024
    declared = request.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > limit:
        raise HTTPException(status_code=413, detail=f"File exceeds {config.intel.max_file_mb} MB (intel.max_file_mb)")
    body = await request.body()
    if len(body) > limit:
        raise HTTPException(status_code=413, detail=f"File exceeds {config.intel.max_file_mb} MB (intel.max_file_mb)")
    if not body.strip():
        raise HTTPException(status_code=400, detail="Empty request body: send the indicator file as the body")
    text = body.decode("utf-8-sig", errors="replace")
    try:
        options = parse_options(config, parse_expiry(expires) if expires else None)
        summary = await run_in_threadpool(ctx.intel.import_text, text, source, fmt=fmt, filename=filename,
                                          mode=mode, options=options, kind_hint=kind)
    except IndicatorError as exc:
        await run_in_threadpool(audit, request, "intel.import", "failure", target=source,
                                details={"error": str(exc)[:200], "filename": filename})
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    await run_in_threadpool(audit, request, "intel.import", target=source, details={
        key: summary.get(key) for key in ("format", "mode", "accepted", "rejected", "sha256") if key in summary})
    return summary


@router.delete("/intel/sources/{source}", summary="Remove every indicator of a source",
               dependencies=[Depends(require_admin)])
def intel_remove(source: str, request: Request, ctx: AppContext = Depends(get_context)) -> dict[str, Any]:
    if len(source) > 128:
        raise HTTPException(status_code=404, detail="Unknown source")
    removed = ctx.intel.remove_source(source)
    audit(request, "intel.remove", target=source, details={"removed": removed})
    return {"source": source, "removed": removed}


@router.post("/intel/purge-expired", summary="Delete expired indicators", dependencies=[Depends(require_admin)])
def intel_purge(request: Request, ctx: AppContext = Depends(get_context)) -> dict[str, Any]:
    purged = ctx.intel.purge_expired()
    audit(request, "intel.purge_expired", target="intel_indicators", details={"purged": purged})
    return {"purged": purged}
