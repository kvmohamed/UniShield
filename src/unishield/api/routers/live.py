"""
Live input endpoints: start a receive-only flow-export collector or Zeek
follow mode as the running analysis, and report its counters.

The collector's address, port and allowed exporters come from the ``live``
section of the configuration only; the API cannot choose an interface. The
Zeek directory must lie under the data directories the replay API may read.
Starting needs an administrator and is audited; stopping uses POST
/replay/stop (one run at a time, file or live).
"""

from __future__ import annotations

from typing import Any, Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from unishield.api.deps import get_context
from unishield.api.routers.replay import resolve_replay_path
from unishield.api.security import audit, require_admin, require_viewer
from unishield.api.state import AppContext
from unishield.config import get_config

router = APIRouter(tags=["live"])

DetectionMode = Literal["rules", "hybrid", "ml"]


def _start_live(request: Request, ctx: AppContext, reader, source: str, fmt: str, clear: bool,
                mode: Optional[str]) -> dict[str, Any]:
    if ctx.running:
        raise HTTPException(status_code=409, detail="A run is already active; stop it with POST /replay/stop")
    try:
        started = ctx.start_replay(reader, source, fmt, clear=clear, detection_mode=mode,
                                   allowed_lateness_sec=get_config().live.allowed_lateness_sec)
    except RuntimeError as exc:
        audit(request, "live.start", "failure", target=source, details={"error": str(exc)})
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    audit(request, "live.start", target=source, details={"run_id": started["run_id"], "format": fmt})
    return started


@router.post("/live/netflow/start", summary="Start the receive-only NetFlow/IPFIX collector",
             dependencies=[Depends(require_admin)])
def live_netflow_start(
    request: Request,
    clear: bool = Query(default=False, description="Delete stored alerts first"),
    mode: Optional[DetectionMode] = Query(default=None),
    ctx: AppContext = Depends(get_context),
) -> dict[str, Any]:
    """Listen for NetFlow v5/v9 and IPFIX on the configured address (receive only; nothing is sent)."""
    from unishield.ingest.collector import FlowExportCollector

    cfg = get_config().live
    collector = FlowExportCollector(cfg.netflow_bind, cfg.netflow_port, allowed_exporters=cfg.allowed_exporters,
                                    tick_interval=cfg.tick_interval_sec)
    try:
        host, port = collector.open()
    except OSError as exc:
        audit(request, "live.start", "failure", target=f"netflow:{cfg.netflow_bind}:{cfg.netflow_port}",
              details={"error": str(exc)})
        raise HTTPException(status_code=409, detail=f"Cannot listen on {cfg.netflow_bind}:{cfg.netflow_port}: "
                                                    f"{exc.strerror or exc}") from exc
    try:
        started = _start_live(request, ctx, collector, f"live:netflow:{host}:{port}", "flow_export", clear, mode)
    except HTTPException:
        collector.close()
        raise
    started["listening"] = f"{host}:{port}"
    return started


@router.post("/live/zeek/start", summary="Follow a Zeek log directory as Zeek writes it",
             dependencies=[Depends(require_admin)])
def live_zeek_start(
    request: Request,
    directory: str = Query(..., max_length=4096, description="Zeek log directory under the data directory"),
    from_start: Optional[bool] = Query(default=None, description="Read existing lines first "
                                                                 "(default: live.zeek_from_start)"),
    clear: bool = Query(default=False),
    mode: Optional[DetectionMode] = Query(default=None),
    ctx: AppContext = Depends(get_context),
) -> dict[str, Any]:
    from unishield.ingest.zeek_follow import ZeekFollowReader

    path = resolve_replay_path(directory)
    if not path.is_dir():
        raise HTTPException(status_code=400, detail="Give the Zeek log directory (it contains conn.log)")
    cfg = get_config().live
    reader = ZeekFollowReader(path, from_start=cfg.zeek_from_start if from_start is None else from_start,
                              poll_interval=cfg.zeek_poll_interval_sec)
    return _start_live(request, ctx, reader, f"live:zeek:{path}", "zeek_follow", clear, mode)


@router.get("/live/status", summary="Counters of the live input", dependencies=[Depends(require_viewer)])
def live_status(ctx: AppContext = Depends(get_context)) -> dict[str, Any]:
    return ctx.live_status()
