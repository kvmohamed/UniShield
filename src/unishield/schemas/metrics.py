"""
UniShield — System Metrics Schema

Tracks pipeline processing statistics, throughput, latency,
and resource usage for benchmarking and dashboard display.
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field

from unishield.schemas.timeutil import utc_now


class PipelineMetrics(BaseModel):
    """Real-time pipeline processing statistics."""

    timestamp: datetime = Field(
        default_factory=utc_now,
        description="When these metrics were captured",
    )

    # --- Throughput ---
    total_records_ingested: int = Field(default=0, ge=0)
    total_records_processed: int = Field(default=0, ge=0)
    total_alerts_generated: int = Field(default=0, ge=0)
    records_per_second: float = Field(default=0.0, ge=0.0)
    alerts_per_second: float = Field(default=0.0, ge=0.0)

    # --- Latency (milliseconds) ---
    latency_p50_ms: float = Field(default=0.0, ge=0.0)
    latency_p95_ms: float = Field(default=0.0, ge=0.0)
    latency_p99_ms: float = Field(default=0.0, ge=0.0)
    latency_avg_ms: float = Field(default=0.0, ge=0.0)

    # --- Resource usage ---
    cpu_percent: float = Field(default=0.0, ge=0.0)
    memory_mb: float = Field(default=0.0, ge=0.0)
    memory_percent: float = Field(default=0.0, ge=0.0)

    # --- Queue ---
    queue_size: int = Field(default=0, ge=0)
    queue_capacity: int = Field(default=10000, ge=0)
    dropped_records: int = Field(default=0, ge=0)
    malformed_records: int = Field(default=0, ge=0)

    # --- Windows ---
    active_windows: int = Field(default=0, ge=0)
    window_size_sec: int = Field(default=10, ge=1)
    slide_interval_sec: int = Field(default=5, ge=1)

    # --- Status ---
    is_processing: bool = Field(default=False)
    uptime_seconds: float = Field(default=0.0, ge=0.0)
    detectors_loaded: int = Field(default=0, ge=0)
    models_loaded: int = Field(default=0, ge=0)


class HealthStatus(BaseModel):
    """System health check response."""

    status: str = Field(
        default="healthy",
        description="healthy | degraded (see degraded_components) | unhealthy (storage unavailable)",
    )
    version: str = Field(default="0.1.0")
    uptime_seconds: float = Field(default=0.0, ge=0.0)
    timestamp: datetime = Field(default_factory=utc_now)

    # Security status — always True for UniShield
    read_only_mode: bool = Field(
        default=True,
        description="Confirms the system is in passive read-only mode",
    )
    no_payload_decryption: bool = Field(
        default=True,
        description="Confirms no payload decryption is performed",
    )
    no_active_scanning: bool = Field(
        default=True,
        description="Confirms no active network scanning is performed",
    )
    no_response_path: bool = Field(
        default=True,
        description="Confirms no response is sent to monitored networks",
    )

    auth_mode: str = Field(default="accounts", description="accounts | open (lab only)")

    # Component status
    database_connected: bool = Field(default=False)
    pipeline_active: bool = Field(default=False)
    detectors_loaded: int = Field(default=0, ge=0)
    models_loaded: int = Field(default=0, ge=0)

    components: dict[str, str] = Field(
        default_factory=lambda: {
            "ingest": "idle",
            "processing": "idle",
            "detection": "idle",
            "storage": "idle",
            "api": "running",
        }
    )
    degraded_components: list[str] = Field(default_factory=list)


class BenchmarkResult(BaseModel):
    """Results from a performance benchmark run."""

    benchmark_id: str
    timestamp: datetime = Field(default_factory=utc_now)
    duration_seconds: float
    total_records: int
    records_per_second: float

    # Latency distribution
    latency_p50_ms: float
    latency_p95_ms: float
    latency_p99_ms: float
    latency_max_ms: float

    # Resource usage
    peak_cpu_percent: float
    peak_memory_mb: float
    avg_memory_mb: float

    # Quality
    total_alerts: int
    alerts_per_second: float
    dropped_records: int
    malformed_records: int

    # Environment
    machine_info: Optional[str] = None
    dataset_name: Optional[str] = None
    notes: Optional[str] = None
