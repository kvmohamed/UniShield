"""
UniShield — FastAPI Application

Main API application with health, metrics, alerts, and replay endpoints.

SECURITY NOTICE:
    This API is a passive, read-only interface. It does NOT send packets,
    probe endpoints, decrypt payloads, or issue remediation commands.
    Administrative endpoints control only local replay and analysis.
"""

from __future__ import annotations

import time
from datetime import datetime
from typing import Any

from pathlib import Path as _Path

from fastapi import FastAPI, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse

from unishield import __app_name__, __version__
from unishield.config import get_config
from unishield.schemas.alert import Alert, AlertSummary, Severity, ThreatClass
from unishield.schemas.metrics import BenchmarkResult, HealthStatus, PipelineMetrics

# ---------------------------------------------------------------------------
# Application startup time (for uptime calculation)
# ---------------------------------------------------------------------------
_start_time = time.time()

# ---------------------------------------------------------------------------
# In-memory stores (replaced by database in Phase 7)
# ---------------------------------------------------------------------------
_alerts: list[Alert] = []
_metrics = PipelineMetrics()
_benchmark: BenchmarkResult | None = None

# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------

app = FastAPI(
    title=f"{__app_name__} API",
    description=(
        "Passive, read-only cybersecurity monitoring API for unidirectional networks. "
        "This system does NOT probe, block, decrypt, or send commands to monitored systems."
    ),
    version=__version__,
    docs_url="/docs",
    redoc_url="/redoc",
)

# CORS — open in development, restrict in production
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

# Dashboard file path
_DASHBOARD_DIR = _Path(__file__).resolve().parent.parent / "dashboard"


@app.get("/", tags=["dashboard"], include_in_schema=False)
@app.get("/dashboard", tags=["dashboard"], summary="Security Dashboard")
async def serve_dashboard():
    """Serve the UniShield security monitoring dashboard."""
    html_path = _DASHBOARD_DIR / "index.html"
    if html_path.exists():
        return FileResponse(str(html_path), media_type="text/html")
    return JSONResponse(
        status_code=404,
        content={"detail": "Dashboard not found. Expected at: " + str(html_path)},
    )


# ===================================================================
# GET /health
# ===================================================================

@app.get(
    "/health",
    response_model=HealthStatus,
    tags=["system"],
    summary="System health check",
    description="Returns system health status including security constraint confirmations.",
)
async def health_check() -> HealthStatus:
    """Return current health status with security constraint verification."""
    config = get_config()
    uptime = time.time() - _start_time

    return HealthStatus(
        status="healthy",
        version=__version__,
        uptime_seconds=round(uptime, 2),
        timestamp=datetime.utcnow(),
        read_only_mode=config.security.read_only_mode,
        no_payload_decryption=config.security.no_payload_decryption,
        no_active_scanning=config.security.no_active_scanning,
        no_response_path=config.security.no_response_path,
        database_connected=False,  # Updated in Phase 7
        pipeline_active=False,  # Updated in Phase 3
        detectors_loaded=0,  # Updated in Phase 3
        models_loaded=0,  # Updated in Phase 5
    )


# ===================================================================
# GET /metrics
# ===================================================================

@app.get(
    "/metrics",
    response_model=PipelineMetrics,
    tags=["system"],
    summary="Pipeline processing metrics",
)
async def get_metrics() -> PipelineMetrics:
    """Return current pipeline processing statistics."""
    return _metrics


# ===================================================================
# GET /alerts
# ===================================================================

@app.get(
    "/alerts",
    response_model=list[Alert],
    tags=["alerts"],
    summary="List alerts",
    description="Retrieve alerts with optional filtering by threat class, severity, and pagination.",
)
async def list_alerts(
    threat_class: ThreatClass | None = Query(default=None, description="Filter by threat class"),
    severity: Severity | None = Query(default=None, description="Filter by severity"),
    limit: int = Query(default=100, ge=1, le=1000, description="Max results"),
    offset: int = Query(default=0, ge=0, description="Pagination offset"),
) -> list[Alert]:
    """Return filtered and paginated alerts."""
    filtered = _alerts

    if threat_class:
        filtered = [a for a in filtered if a.threat_class == threat_class]
    if severity:
        filtered = [a for a in filtered if a.severity == severity]

    return filtered[offset: offset + limit]


# ===================================================================
# GET /alerts/summary
# ===================================================================

@app.get(
    "/alerts/summary",
    response_model=AlertSummary,
    tags=["alerts"],
    summary="Alert summary statistics",
)
async def alerts_summary() -> AlertSummary:
    """Return aggregate statistics over all current alerts."""
    if not _alerts:
        return AlertSummary()

    by_threat: dict[str, int] = {}
    by_severity: dict[str, int] = {}
    by_detector: dict[str, int] = {}
    total_conf = 0.0
    total_latency = 0.0
    latency_count = 0

    for a in _alerts:
        by_threat[a.threat_class.value] = by_threat.get(a.threat_class.value, 0) + 1
        by_severity[a.severity.value] = by_severity.get(a.severity.value, 0) + 1
        by_detector[a.detector_name] = by_detector.get(a.detector_name, 0) + 1
        total_conf += a.confidence
        if a.detection_latency_ms is not None:
            total_latency += a.detection_latency_ms
            latency_count += 1

    timestamps = [a.timestamp for a in _alerts]

    return AlertSummary(
        total_alerts=len(_alerts),
        by_threat_class=by_threat,
        by_severity=by_severity,
        by_detector=by_detector,
        avg_confidence=round(total_conf / len(_alerts), 4),
        avg_detection_latency_ms=round(total_latency / max(latency_count, 1), 2),
        time_range_start=min(timestamps),
        time_range_end=max(timestamps),
    )


# ===================================================================
# GET /alerts/{alert_id}
# ===================================================================

@app.get(
    "/alerts/{alert_id}",
    response_model=Alert,
    tags=["alerts"],
    summary="Get alert by ID",
)
async def get_alert(alert_id: str) -> Alert | JSONResponse:
    """Return a single alert by its ID."""
    for alert in _alerts:
        if alert.alert_id == alert_id:
            return alert
    return JSONResponse(status_code=404, content={"detail": f"Alert '{alert_id}' not found"})


# ===================================================================
# GET /threats/{threat_class}
# ===================================================================

@app.get(
    "/threats/{threat_class}",
    response_model=list[Alert],
    tags=["alerts"],
    summary="Alerts for a specific threat class",
)
async def get_threats(threat_class: ThreatClass) -> list[Alert]:
    """Return all alerts matching a specific threat class."""
    return [a for a in _alerts if a.threat_class == threat_class]


# ===================================================================
# POST /replay/start
# ===================================================================

import threading
from pathlib import Path

from unishield.data.sample_generator import (
    SimulatedReader,
    generate_mixed_scenario,
)
from unishield.processing.pipeline import Pipeline, PipelineResult

# Replay state
_replay_state: dict = {
    "status": "idle",
    "file_path": None,
    "progress": 0.0,
    "records_processed": 0,
    "alerts_generated": 0,
    "result": None,
    "thread": None,
}

_pipeline: Pipeline | None = None


def _run_replay_in_background(reader, file_path: str) -> None:
    """Run the pipeline in a background thread."""
    global _pipeline
    _pipeline = Pipeline(alert_callback=add_alert)
    _replay_state["status"] = "running"
    _replay_state["file_path"] = file_path

    try:
        result = _pipeline.run(reader)
        _replay_state["result"] = result.summary()
        _replay_state["records_processed"] = result.total_records
        _replay_state["alerts_generated"] = result.total_alerts
        _replay_state["progress"] = 100.0
        _replay_state["status"] = "completed"
    except Exception as e:
        _replay_state["status"] = f"error: {e}"


@app.post(
    "/replay/start",
    tags=["replay"],
    summary="Start traffic replay",
    description="Start replaying a PCAP or log file. Does NOT send packets — processes locally only.",
)
async def replay_start(file_path: str = Query(..., description="Path to PCAP/log file")) -> dict:
    """
    Start replay of a traffic file for analysis.
    NOTE: This does NOT send any packets. It reads the file locally.
    """
    if _replay_state["status"] == "running":
        return {"status": "error", "message": "Replay already running"}

    clear_alerts()

    p = Path(file_path)
    if not p.exists():
        return {"status": "error", "message": f"File not found: {file_path}"}

    # Detect reader based on extension
    from unishield.ingest.flow_reader import FlowReader
    from unishield.ingest.zeek_reader import ZeekReader

    suffix = p.suffix.lower()
    if suffix in (".json", ".jsonl"):
        # Try Zeek first, fall back to flow JSON
        try:
            reader = ZeekReader(p)
            if reader.validate_source():
                pass
            else:
                reader = FlowReader(p)
        except Exception:
            reader = FlowReader(p)
    elif suffix == ".csv":
        reader = FlowReader(p)
    else:
        return {"status": "error", "message": f"Unsupported format: {suffix}"}

    thread = threading.Thread(
        target=_run_replay_in_background,
        args=(reader, file_path),
        daemon=True,
    )
    _replay_state["thread"] = thread
    thread.start()

    return {"status": "started", "file_path": file_path}


# ===================================================================
# POST /replay/demo — Run demo with synthetic data
# ===================================================================

@app.post(
    "/replay/demo",
    tags=["replay"],
    summary="Run demo with synthetic attack traffic",
    description="Generates synthetic traffic with embedded attacks and runs the detection pipeline.",
)
async def replay_demo(
    normal: int = Query(default=200, ge=10, le=5000),
    ddos: int = Query(default=300, ge=0, le=5000),
    scan: int = Query(default=100, ge=0, le=5000),
    beacon: int = Query(default=25, ge=0, le=500),
    exfil: int = Query(default=30, ge=0, le=500),
) -> dict:
    """
    Run the full pipeline on synthetic data with embedded attacks.
    Returns the pipeline result summary including all alerts.
    """
    if _replay_state["status"] == "running":
        return {"status": "error", "message": "Replay already running"}

    clear_alerts()

    flows = generate_mixed_scenario(
        normal_count=normal,
        ddos_count=ddos,
        scan_count=scan,
        beacon_count=beacon,
        exfil_count=exfil,
    )
    reader = SimulatedReader(flows)

    thread = threading.Thread(
        target=_run_replay_in_background,
        args=(reader, "synthetic_demo"),
        daemon=True,
    )
    _replay_state["thread"] = thread
    thread.start()

    # Wait briefly for it to finish (synthetic data is fast)
    thread.join(timeout=30)

    return {
        "status": _replay_state["status"],
        "total_flows": len(flows),
        "result": _replay_state.get("result"),
        "alerts_count": len(_alerts),
    }


# ===================================================================
# POST /replay/stop
# ===================================================================

@app.post(
    "/replay/stop",
    tags=["replay"],
    summary="Stop traffic replay",
)
async def replay_stop() -> dict:
    """Stop any active replay."""
    if _pipeline:
        _pipeline.stop()
        _replay_state["status"] = "stopped"
        return {"status": "stopped"}
    return {"status": "idle", "message": "No active replay"}


# ===================================================================
# GET /replay/status
# ===================================================================

@app.get(
    "/replay/status",
    tags=["replay"],
    summary="Get replay status",
)
async def replay_status() -> dict:
    """Return the current replay status."""
    return {
        "status": _replay_state["status"],
        "file_path": _replay_state["file_path"],
        "progress": _replay_state["progress"],
        "records_processed": _replay_state["records_processed"],
        "alerts_generated": _replay_state["alerts_generated"],
        "result": _replay_state.get("result"),
    }


# ===================================================================
# GET /benchmark/latest
# ===================================================================

@app.get(
    "/benchmark/latest",
    tags=["system"],
    summary="Latest benchmark results",
)
async def benchmark_latest() -> BenchmarkResult | dict:
    """Return the latest benchmark results."""
    if _benchmark is not None:
        return _benchmark
    return {"status": "no_benchmark_available", "message": "Run a benchmark first"}


# ===================================================================
# Internal helpers (used by pipeline in later phases)
# ===================================================================

def add_alert(alert: Alert) -> None:
    """Add an alert to the in-memory store. Called by the detection pipeline."""
    _alerts.append(alert)


def update_metrics(metrics: PipelineMetrics) -> None:
    """Update the current pipeline metrics snapshot."""
    global _metrics
    _metrics = metrics


def get_alert_store() -> list[Alert]:
    """Return the current in-memory alert store (for testing/dashboard)."""
    return _alerts


def clear_alerts() -> None:
    """Clear all alerts (for testing)."""
    _alerts.clear()

