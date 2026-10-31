"""
UniShield — Standardised Alert Schema

All detectors produce alerts conforming to this schema.
Alerts are validated via Pydantic before storage or API delivery.

IMPORTANT:
- confidence is a float in [0, 1]. Rule-based thresholds should NOT
  be labelled "probabilities" unless explicitly calibrated.
- evidence contains detector-specific supporting data.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator

from unishield.schemas.timeutil import ensure_utc, utc_now


class ThreatClass(str, Enum):
    """Supported threat classifications."""
    DDOS_VOLUMETRIC = "DDOS_VOLUMETRIC"
    DDOS_PROTOCOL = "DDOS_PROTOCOL"
    SYN_FLOOD = "SYN_FLOOD"
    UDP_FLOOD = "UDP_FLOOD"
    PORT_SCAN = "PORT_SCAN"
    HOST_SCAN = "HOST_SCAN"
    RECONNAISSANCE = "RECONNAISSANCE"
    C2_BEACONING = "C2_BEACONING"
    DATA_EXFILTRATION = "DATA_EXFILTRATION"
    DNS_TUNNELLING = "DNS_TUNNELLING"
    DGA_DETECTED = "DGA_DETECTED"
    ENCRYPTED_SESSION_ANOMALY = "ENCRYPTED_SESSION_ANOMALY"
    STATISTICAL_ANOMALY = "STATISTICAL_ANOMALY"
    INTEL_MATCH = "INTEL_MATCH"
    BRUTE_FORCE = "BRUTE_FORCE"
    SPAM_ACTIVITY = "SPAM_ACTIVITY"


class Severity(str, Enum):
    """Alert severity levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class SourceType(str, Enum):
    """How the analysed traffic was obtained."""
    PCAP_FILE = "pcap_file"
    PCAP_REPLAY = "pcap_replay"
    ZEEK_LOG = "zeek_log"
    FLOW_CSV = "flow_csv"
    FLOW_JSON = "flow_json"
    LIVE_CAPTURE = "live_capture"
    FLOW_EXPORT = "flow_export"
    SIMULATED = "simulated"


def _generate_alert_id() -> str:
    """Generate a prefixed alert ID."""
    short = uuid.uuid4().hex[:8].upper()
    return f"US-{short}"


class Alert(BaseModel):
    """
    Standard alert produced by any UniShield detector.

    Every alert must include supporting evidence and MITRE ATT&CK
    technique IDs where applicable. Confidence is always [0, 1].
    """

    alert_id: str = Field(
        default_factory=_generate_alert_id,
        description="Unique alert identifier (e.g. US-A1B2C3D4)",
    )
    timestamp: datetime = Field(
        default_factory=utc_now,
        description="When the alert was generated (UTC)",
    )
    window_start: datetime = Field(
        ...,
        description="Start of the analysis window",
    )
    window_end: datetime = Field(
        ...,
        description="End of the analysis window",
    )

    # --- Endpoints ---
    source_ip: Optional[str] = Field(
        default=None,
        description="Source IP (or hash if anonymised)",
    )
    source_ip_hash: Optional[str] = Field(
        default=None,
        description="Hashed source IP when anonymisation is enabled",
    )
    destination_ip: Optional[str] = Field(
        default=None,
        description="Destination IP (or hash if anonymised)",
    )
    destination_ip_hash: Optional[str] = Field(
        default=None,
        description="Hashed destination IP when anonymisation is enabled",
    )

    flow_id: Optional[str] = Field(
        default=None,
        description="Associated flow record ID",
    )

    # --- Classification ---
    threat_class: ThreatClass = Field(
        ...,
        description="Type of threat detected",
    )
    severity: Severity = Field(
        ...,
        description="Alert severity level",
    )
    confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Detection confidence in [0, 1]. NOT a probability unless calibrated.",
    )

    # --- Detector metadata ---
    detector_name: str = Field(
        ...,
        description="Name of the detector that produced this alert",
    )
    model_version: str = Field(
        default="v1.0.0",
        description="Version of the detection model or ruleset",
    )

    # --- Evidence ---
    evidence: dict[str, Any] = Field(
        default_factory=dict,
        description="Supporting features/metrics that triggered the alert",
    )

    # --- MITRE ATT&CK ---
    mitre_techniques: list[str] = Field(
        default_factory=list,
        description="Applicable MITRE ATT&CK technique IDs",
    )

    # --- Performance ---
    detection_latency_ms: Optional[float] = Field(
        default=None,
        ge=0.0,
        description="Time from record ingestion to alert generation (ms)",
    )

    # --- Source ---
    source_type: SourceType = Field(
        default=SourceType.PCAP_FILE,
        description="How the traffic was obtained",
    )

    # --- Processing-stage wall-clock times (end-to-end latency) ---
    window_closed_at: Optional[datetime] = Field(
        default=None,
        description="Wall-clock time the alert's window closed and analysis began (UTC)",
    )
    emitted_at: Optional[datetime] = Field(
        default=None,
        description="Wall-clock time the pipeline emitted the alert (UTC)",
    )
    stored_at: Optional[datetime] = Field(
        default=None,
        description="Wall-clock time the alert was written to storage (UTC)",
    )
    run_id: Optional[str] = Field(
        default=None,
        description="Replay/analysis run that produced the alert",
    )
    suppressed_by: Optional[int] = Field(
        default=None,
        description="Analyst suppression rule that matched: the alert is stored but hidden by default and "
                    "not delivered to outputs",
    )

    @field_validator("timestamp", "window_start", "window_end")
    @classmethod
    def normalise_utc(cls, v: datetime) -> datetime:
        """Store every alert time as timezone-aware UTC."""
        return ensure_utc(v)

    @field_validator("window_closed_at", "emitted_at", "stored_at")
    @classmethod
    def normalise_optional_utc(cls, v: Optional[datetime]) -> Optional[datetime]:
        return ensure_utc(v) if v is not None else None

    @field_validator("confidence")
    @classmethod
    def clamp_confidence(cls, v: float) -> float:
        """Ensure confidence is strictly within [0, 1]."""
        return max(0.0, min(1.0, v))

    @field_validator("mitre_techniques")
    @classmethod
    def validate_mitre(cls, v: list[str]) -> list[str]:
        """Basic validation that MITRE IDs look correct (T#### or T####.###)."""
        import re
        pattern = re.compile(r"^T\d{4}(\.\d{3})?$")
        for technique in v:
            if not pattern.match(technique):
                raise ValueError(
                    f"Invalid MITRE ATT&CK technique ID: '{technique}'. "
                    "Expected format: T1234 or T1234.001"
                )
        return v

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "alert_id": "US-A1B2C3D4",
                "timestamp": "2026-09-30T10:30:00Z",
                "window_start": "2026-09-30T10:29:50Z",
                "window_end": "2026-09-30T10:30:00Z",
                "source_ip": "192.168.1.100",
                "destination_ip": "10.0.0.1",
                "flow_id": "a1b2c3d4",
                "threat_class": "PORT_SCAN",
                "severity": "HIGH",
                "confidence": 0.92,
                "detector_name": "scan_rule_detector",
                "model_version": "v1.0.0",
                "evidence": {
                    "unique_destination_ports": 85,
                    "unique_destination_hosts": 12,
                    "connection_rate": 210.4,
                    "fanout_score": 0.91,
                },
                "mitre_techniques": ["T1046"],
                "detection_latency_ms": 842.0,
                "source_type": "pcap_replay",
            }
        }
    )


class AlertSummary(BaseModel):
    """Summary statistics for alerts."""
    total_alerts: int = 0
    by_threat_class: dict[str, int] = Field(default_factory=dict)
    by_severity: dict[str, int] = Field(default_factory=dict)
    by_detector: dict[str, int] = Field(default_factory=dict)
    avg_confidence: float = 0.0
    avg_detection_latency_ms: float = 0.0
    time_range_start: Optional[datetime] = None
    time_range_end: Optional[datetime] = None
    suppressed_alerts: int = 0              # matched an analyst suppression rule; not in the counts above
