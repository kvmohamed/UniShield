"""
Replay endpoints: analyse a local file or a synthetic scenario.

Replay reads files under the configured data directories and runs the
pipeline locally. Nothing is sent on any network. Starting and stopping
replays requires an administrator (see api.security) and is audited.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from unishield.api.deps import get_context
from unishield.api.security import audit, require_admin, require_viewer
from unishield.api.state import AppContext
from unishield.config import get_config
from unishield.data.sample_generator import SCENARIO_NAMES, SimulatedReader, build_scenario, generate_mixed_scenario
from unishield.ingest.detect import UnsupportedFormatError, open_reader

router = APIRouter(tags=["replay"])

DetectionMode = Literal["rules", "hybrid", "ml"]


def _allowed_roots() -> list[Path]:
    """Directories the replay API may read: paths.data_dir + ingest.allowed_dirs."""
    config = get_config()
    return [Path(root).expanduser().resolve() for root in [config.paths.data_dir, *config.ingest.allowed_dirs]]


def _input_size_bytes(path: Path) -> int:
    if path.is_dir():
        return sum(p.stat().st_size for p in path.glob("*.log") if p.is_file())
    return path.stat().st_size


def resolve_replay_path(file_path: str) -> Path:
    """
    Resolve a requested input path and enforce the allow-list and size limit.
    The allow-list is checked before existence so the API does not reveal
    which files exist elsewhere on disk.
    """
    if "\x00" in file_path:
        raise HTTPException(status_code=400, detail="Invalid path")
    resolved = Path(file_path).expanduser().resolve()
    if not any(resolved == root or resolved.is_relative_to(root) for root in _allowed_roots()):
        raise HTTPException(
            status_code=403,
            detail="Path is outside the allowed data directories "
                   "(paths.data_dir / ingest.allowed_dirs in configs/config.yaml)",
        )
    if not resolved.exists():
        raise HTTPException(status_code=404, detail="Not found")
    limit_mb = get_config().ingest.max_file_size_mb
    if _input_size_bytes(resolved) > limit_mb * 1024 * 1024:
        raise HTTPException(status_code=413, detail=f"Input exceeds {limit_mb} MB limit")
    return resolved


def _start(request: Request, ctx: AppContext, reader, source: str, fmt: str, clear: bool,
           mode: Optional[str], action: str) -> dict[str, Any]:
    try:
        started = ctx.start_replay(reader, source, fmt, clear=clear, detection_mode=mode)
    except RuntimeError as exc:
        audit(request, action, "failure", target=source, details={"error": str(exc)})
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    audit(request, action, target=source, details={
        "run_id": started["run_id"], "format": fmt, "detection_mode": started["detection_mode"],
        "alerts_deleted": started["alerts_deleted"]})
    return started


@router.post("/replay/start", summary="Analyse a local traffic file", dependencies=[Depends(require_admin)])
def replay_start(
    request: Request,
    file_path: str = Query(..., max_length=4096, description="Path under the data directory"),
    clear: bool = Query(default=True, description="Delete stored alerts before the run"),
    mode: Optional[DetectionMode] = Query(default=None, description="Detection mode (default: config)"),
    ctx: AppContext = Depends(get_context),
) -> dict[str, Any]:
    """Analyse a PCAP/PCAPNG, Zeek (JSON/TSV, file or directory) or flow CSV/JSON file. Read-only."""
    if ctx.running:
        raise HTTPException(status_code=409, detail="Replay already running")
    path = resolve_replay_path(file_path)
    try:
        reader, fmt = open_reader(path)
    except UnsupportedFormatError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return _start(request, ctx, reader, str(path), fmt, clear, mode, "replay.start")


@router.post("/replay/demo", summary="Analyse synthetic attack traffic", dependencies=[Depends(require_admin)])
def replay_demo(
    request: Request,
    scenario: str = Query(default="mixed", description=f"'mixed' or one of: {', '.join(SCENARIO_NAMES)}"),
    seed: int = Query(default=7, ge=0, le=2**31 - 1),
    wait: bool = Query(default=False, description="Block until the run finishes (max 120 s)"),
    clear: bool = Query(default=True),
    mode: Optional[DetectionMode] = Query(default=None),
    normal: int = Query(default=300, ge=10, le=5000, description="mixed only"),
    ddos: int = Query(default=6000, ge=0, le=20000, description="mixed only"),
    scan: int = Query(default=150, ge=0, le=5000, description="mixed only"),
    beacon: int = Query(default=25, ge=0, le=500, description="mixed only"),
    exfil: int = Query(default=30, ge=0, le=500, description="mixed only"),
    ctx: AppContext = Depends(get_context),
) -> dict[str, Any]:
    """Generate labelled synthetic traffic and run the pipeline on it (runs in the background)."""
    if scenario == "mixed":
        flows = generate_mixed_scenario(normal_count=normal, ddos_count=ddos, scan_count=scan,
                                        beacon_count=beacon, exfil_count=exfil, seed=seed)
        expected = None
    elif scenario in SCENARIO_NAMES:
        built = build_scenario(scenario, seed)
        flows, expected = built.flows, sorted(built.expected_classes)
    else:
        raise HTTPException(status_code=422, detail=f"Unknown scenario; choose 'mixed' or one of {SCENARIO_NAMES}")
    started = _start(request, ctx, SimulatedReader(flows), f"synthetic:{scenario}:{seed}", "simulated", clear, mode,
                     "replay.demo")
    started.update(total_flows=len(flows), expected_classes=expected)
    if wait:
        ctx.wait(120)
        started["status"] = ctx.replay["status"]
        started["result"] = ctx.replay.get("result")
        started["alerts_count"] = ctx.replay["alerts_generated"]
    return started


@router.post("/replay/stop", summary="Stop the running replay", dependencies=[Depends(require_admin)])
def replay_stop(request: Request, ctx: AppContext = Depends(get_context)) -> dict[str, Any]:
    run_id = ctx.replay.get("run_id")
    if ctx.stop_replay():
        audit(request, "replay.stop", target=run_id)
        return {"status": "stopping"}
    return {"status": "idle", "message": "No active replay"}


@router.get("/replay/status", summary="Replay status", dependencies=[Depends(require_viewer)])
def replay_status(ctx: AppContext = Depends(get_context)) -> dict[str, Any]:
    return ctx.status()


@router.get("/replay/runs", summary="Recent analysis runs", dependencies=[Depends(require_viewer)])
def replay_runs(limit: int = Query(default=20, ge=1, le=200), ctx: AppContext = Depends(get_context)) -> list[dict]:
    return ctx.repository.runs(limit)
