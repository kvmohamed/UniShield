"""System endpoints: health, metrics, traffic analytics, architecture status, assets, reports."""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import psutil
from fastapi import APIRouter, Depends, Query, Response

from unishield import __version__
from unishield.api.deps import get_context
from unishield.api.security import auth_mode, public, require_viewer
from unishield.api.state import AppContext
from unishield.assets import AssetInventory
from unishield.config import assets_source, get_config, threshold_sources
from unishield.processing.pipeline import DETECTION_MODES, default_detectors
from unishield.schemas.metrics import HealthStatus, PipelineMetrics

router = APIRouter(tags=["system"])

_PROCESS = psutil.Process()
_PROCESS.cpu_percent(None)                   # prime the CPU counter


def _reports_dir() -> Path:
    return Path(get_config().paths.reports_dir)


def _read_json(path: Path) -> dict[str, Any] | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


@router.get("/health", response_model=HealthStatus, summary="System health check",
            dependencies=[Depends(public)], responses={503: {"description": "Storage unavailable"}})
def health_check(response: Response, ctx: AppContext = Depends(get_context)) -> HealthStatus:
    """
    ``healthy``, ``degraded`` (working, but a component needs attention: see
    ``degraded_components``) or ``unhealthy`` (storage unavailable; HTTP 503,
    so container and service health checks fail).
    """
    config = get_config()
    state = ctx.health()
    pipeline = ctx.pipeline
    if state["status"] == "unhealthy":
        response.status_code = 503
    return HealthStatus(
        status=state["status"],
        version=__version__,
        uptime_seconds=round(time.time() - ctx.started, 2),
        timestamp=datetime.now(timezone.utc),
        read_only_mode=config.security.read_only_mode,
        no_payload_decryption=config.security.no_payload_decryption,
        no_active_scanning=config.security.no_active_scanning,
        no_response_path=config.security.no_response_path,
        auth_mode=auth_mode(),
        tls=config.tls.enabled,
        database_connected=state["storage_ok"],
        pipeline_active=ctx.running,
        detectors_loaded=len(pipeline.detectors) if pipeline else 0,
        models_loaded=sum(1 for d in pipeline.detectors if d.name == "ml_detector") if pipeline else 0,
        components=state["components"],
        degraded_components=state["degraded"],
    )


@router.get("/metrics", response_model=PipelineMetrics, summary="Pipeline and process metrics",
            dependencies=[Depends(require_viewer)])
def get_metrics(ctx: AppContext = Depends(get_context)) -> PipelineMetrics:
    pipeline = ctx.pipeline
    metrics = pipeline.get_metrics() if pipeline else PipelineMetrics()
    state = ctx.status()
    elapsed = state.get("elapsed_seconds") or 0.0
    updates: dict[str, Any] = {
        "cpu_percent": round(_PROCESS.cpu_percent(None), 1),
        "memory_mb": round(_PROCESS.memory_info().rss / 1_048_576, 1),
        "memory_percent": round(_PROCESS.memory_percent(), 2),
        "uptime_seconds": round(time.time() - ctx.started, 2),
    }
    if elapsed > 0:
        updates["records_per_second"] = round(metrics.total_records_ingested / elapsed, 2)
        updates["alerts_per_second"] = round(metrics.total_alerts_generated / elapsed, 4)
    if pipeline:
        updates["models_loaded"] = sum(1 for d in pipeline.detectors if d.name == "ml_detector")
    return metrics.model_copy(update=updates)


@router.get("/metrics/traffic", summary="Per-window traffic and alert counts of the current/last run",
            dependencies=[Depends(require_viewer)])
def traffic(limit: int = Query(default=500, ge=1, le=10_000), ctx: AppContext = Depends(get_context)) -> dict[str, Any]:
    result = ctx.pipeline.result if ctx.pipeline else None
    series = list(result.window_series)[-limit:] if result else []
    totals = {
        "windows": len(result.window_series) if result else 0,
        "flows": sum(w["flows"] for w in series),
        "packets": sum(w["packets"] for w in series),
        "bytes": sum(w["bytes"] for w in series),
    }
    return {
        "run_id": ctx.replay.get("run_id"),
        "series": [dict(w, window_start=w["window_start"].isoformat(), window_end=w["window_end"].isoformat())
                   for w in series],
        "totals": totals,
        "top_sources": ctx.repository.top_entities("source_ip"),
        "top_destinations": ctx.repository.top_entities("destination_ip"),
    }


def _state_detail(ctx: AppContext, config) -> str:
    store = ctx.pipeline.state_store if ctx.pipeline else None
    if store is None:
        return f"snapshot file {config.state.path}"
    last = store.last_save.get("at", "none yet")
    return f"snapshot file {store.path}, {store.saves} saves, last {last}"


@router.get("/system/architecture", summary="Component status for the architecture view",
            dependencies=[Depends(require_viewer)])
def architecture(ctx: AppContext = Depends(get_context)) -> dict[str, Any]:
    from unishield.models.registry import ModelRegistry

    config = get_config()
    pipeline = ctx.pipeline
    detectors = pipeline.detectors if pipeline else default_detectors("rules")
    extractors = [e.name for e in pipeline.extractors] if pipeline else [
        "volume_features", "scan_features", "beaconing_features", "exfiltration_features",
        "dns_features", "encrypted_session_features", "intel_features"]
    try:
        models = [{k: m.get(k) for k in ("name", "version", "algorithm", "created_at")}
                  for m in ModelRegistry().list()]
    except Exception:                                    # pragma: no cover - unreadable registry
        models = []
    db_ok = ctx.repository.ping()
    outputs = ctx.outputs.status()
    intel = ctx.intel.status()
    channels = [d["name"] for d in outputs["syslog"]["destinations"]] + [c["name"] for c in outputs["notifications"]]
    return {
        "notice": "This system is a passive defensive research prototype. It does not probe, block, "
                  "decrypt, or send commands to monitored systems.",
        "security": config.security.model_dump(include={"read_only_mode", "no_payload_decryption",
                                                        "no_active_scanning", "no_response_path",
                                                        "anonymize_ips"}),
        "stages": [
            {"name": "ingest", "status": "running" if ctx.running else "ready",
             "detail": "PCAP/PCAPNG (scapy, offline), Zeek JSON/TSV, flow CSV/JSON, synthetic"},
            {"name": "sessionizer", "status": "ready",
             "detail": f"idle {config.sessionizer.idle_timeout_sec}s, active {config.sessionizer.active_timeout_sec}s"},
            {"name": "windowing", "status": "ready",
             "detail": f"{config.processing.window_size_sec}s windows every {config.processing.slide_interval_sec}s, "
                       f"lateness {config.processing.allowed_lateness_sec}s"},
            {"name": "features", "status": "ready", "detail": ", ".join(extractors)},
            {"name": "detection", "status": "running" if ctx.running else "ready",
             "detail": f"mode {pipeline.detection_mode if pipeline else config.models.detection_mode}"},
            {"name": "storage", "status": "connected" if db_ok else "unavailable",
             "detail": f"{ctx.repository.backend}, {ctx.repository.count()} alerts"},
            {"name": "state", "status": "enabled" if config.state.enabled else "disabled",
             "detail": _state_detail(ctx, config)},
            {"name": "api", "status": "running", "detail": f"auth mode: {auth_mode()}"},
            {"name": "threat intel", "status": "ready" if config.intel.enabled else "disabled",
             "detail": f"{intel['active_total']} active indicators from {len(intel['sources'])} sources "
                       f"(offline imports only)"},
            {"name": "exports", "status": "running" if outputs["files"]["enabled"] else "on demand",
             "detail": f"{', '.join(outputs['files']['formats'])} → {outputs['files']['directory']}"},
            {"name": "analyst-side outputs", "status": "running" if channels else "disabled",
             "detail": (f"{', '.join(channels)} → allow-listed analyst destinations only" if channels
                        else "syslog / email / webhook off; nothing is sent anywhere")},
        ],
        "outputs": outputs,
        "intel": intel,
        "detectors": [{"name": d.name, "version": d.version, "threat_classes": [c.value for c in d.threat_classes][:12],
                       "windows_analysed": d.windows_analysed, "alerts_generated": d.alerts_generated}
                      for d in detectors],
        "detection_modes": list(DETECTION_MODES),
        "models": models,
        "thresholds_sources": threshold_sources(),
        "assets_source": assets_source(),
    }


@router.get("/system/assets", summary="Asset inventory and what its role policies changed")
def asset_inventory(ctx: AppContext = Depends(get_context)) -> dict[str, Any]:
    """
    The loaded asset inventory, the effective role policies, and for the
    current/last run the alerts the policies downgraded or suppressed
    (counts plus the most recent suppressed alerts).
    """
    pipeline = ctx.pipeline
    inventory = pipeline.asset_policy.inventory if pipeline else AssetInventory.from_config()
    policy = pipeline.asset_policy if pipeline else None
    return {
        "source": assets_source(),
        "assets": inventory.describe(),
        "policies": {role: {side: {c.value: a for c, a in classes.items()} for side, classes in sides.items()}
                     for role, sides in inventory.policies.items()},
        "run_id": ctx.replay.get("run_id"),
        "policy_effects": policy.stats() if policy else None,
        "recent_suppressed": list(policy.recent_suppressed) if policy else [],
    }


@router.get("/benchmark/latest", summary="Latest measured benchmark (reports/benchmark.json)",
            dependencies=[Depends(require_viewer)])
def benchmark_latest() -> dict[str, Any]:
    data = _read_json(_reports_dir() / "benchmark.json")
    if data is None:
        return {"status": "no_benchmark_available",
                "message": "Run python scripts/benchmark_pipeline.py to produce one"}
    return dict(data, status="ok")


@router.get("/evaluation/latest", summary="Latest model evaluation (reports/model_evaluation.json)",
            dependencies=[Depends(require_viewer)])
def evaluation_latest() -> dict[str, Any]:
    data = _read_json(_reports_dir() / "model_evaluation.json")
    if data is None:
        return {"status": "no_evaluation_available",
                "message": "Run python scripts/evaluate_models.py to produce one"}
    results = data.get("results", {})
    keep = ("precision", "recall", "f1", "false_positive_rate", "pr_auc", "episodes", "episodes_detected",
            "delay_median_sec")
    return {
        "status": "ok",
        "context": data.get("context", {}),
        "windows": results.get("windows"),
        "threshold": results.get("threshold"),
        "approaches": {k: {m: v.get(m) for m in keep} for k, v in results.get("approaches", {}).items()},
    }
