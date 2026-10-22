"""
UniShield — Configuration Module

Loads settings from YAML files, then applies environment-variable
overrides (from the process environment or a ``.env`` file).
All security constraints are validated at startup.

Precedence (highest first):
    1. Environment variables listed in ``ENV_OVERRIDES``
    2. ``configs/config.yaml``
    3. Model defaults below
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any, Literal, Optional

import yaml
from dotenv import load_dotenv
from pydantic import BaseModel, Field, field_validator

logger = logging.getLogger("unishield.config")


# ---------------------------------------------------------------------------
# Path resolution
# ---------------------------------------------------------------------------

def _project_root() -> Path:
    """Return the source-checkout root (parent of src/). Only meaningful for
    editable installs; packaged installs fall back to the working directory."""
    return Path(__file__).resolve().parent.parent.parent


def config_dir() -> Path:
    """
    Locate the configs directory.

    Order: ``UNISHIELD_CONFIG_DIR`` → ``./configs`` (working directory) →
    ``<source checkout>/configs``. Works for editable installs, packaged
    installs run from the project directory, and the Docker image.
    """
    env_dir = os.getenv("UNISHIELD_CONFIG_DIR")
    if env_dir:
        return Path(env_dir)
    for candidate in (Path.cwd() / "configs", _project_root() / "configs"):
        if candidate.is_dir():
            return candidate
    return Path.cwd() / "configs"


def _resolve_config_path(filename: str) -> Path:
    """Resolve a file inside the configs directory."""
    return config_dir() / filename


def load_yaml(path: Path) -> dict[str, Any]:
    """Load a YAML file and return its contents as a dict."""
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


# ---------------------------------------------------------------------------
# Security constraints — immutable at runtime
# ---------------------------------------------------------------------------

class SecurityConfig(BaseModel):
    """
    Core security constraints. These are ALWAYS enforced.
    read_only_mode, no_payload_decryption, no_active_scanning, and
    no_response_path must all be True. Any attempt to set them to False
    will raise a validation error. They have no environment override.
    """
    read_only_mode: bool = True
    no_payload_decryption: bool = True
    no_active_scanning: bool = True
    no_response_path: bool = True
    anonymize_ips: bool = False
    ip_hash_salt: str = "change-this-salt"

    @field_validator(
        "read_only_mode",
        "no_payload_decryption",
        "no_active_scanning",
        "no_response_path",
    )
    @classmethod
    def must_be_true(cls, v: bool, info) -> bool:  # noqa: N805
        if not v:
            raise ValueError(
                f"Security constraint '{info.field_name}' must always be True. "
                "UniShield operates in read-only, passive-only mode."
            )
        return v


# ---------------------------------------------------------------------------
# Sub-configs
# ---------------------------------------------------------------------------

class APIConfig(BaseModel):
    host: str = "127.0.0.1"
    port: int = 8000
    workers: int = 1
    reload: bool = False
    # Key for administrative endpoints (replay, demo, clearing alerts), sent as
    # the X-API-Key header. Set it only through UNISHIELD_ADMIN_API_KEY. When it
    # is unset, administrative endpoints accept loopback clients only.
    admin_api_key: Optional[str] = Field(default=None, repr=False)
    cors_origins: list[str] = Field(default_factory=list)   # the dashboard is same-origin


class DatabaseConfig(BaseModel):
    url: str = "sqlite:///./data/unishield.db"
    echo: bool = False
    pool_size: int = 5


class ProcessingConfig(BaseModel):
    window_size_sec: int = 10
    slide_interval_sec: int = 5
    # Records may arrive this much (traffic time) out of order before they are
    # dropped as late. Raising it delays every window's analysis by the same amount.
    allowed_lateness_sec: float = Field(default=0.0, ge=0)
    max_queue_size: int = 10000
    max_alert_batch: int = 100
    max_records_in_memory: int = 50000


class IngestConfig(BaseModel):
    supported_formats: list[str] = Field(
        default=["pcap", "pcapng", "zeek_json", "zeek_tsv", "flow_csv", "flow_json"]
    )
    max_file_size_mb: int = 500
    # The replay API only opens files inside these directories (relative paths
    # are resolved against the working directory). paths.data_dir is always allowed.
    allowed_dirs: list[str] = Field(default_factory=list)


class NetworkConfig(BaseModel):
    """Which addresses belong to the monitored network (used for direction)."""
    home_networks: list[str] = Field(
        default=["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"]
    )


class SessionizerConfig(BaseModel):
    """Packet → bidirectional flow aggregation (PCAP input)."""
    idle_timeout_sec: float = Field(default=5.0, gt=0)
    active_timeout_sec: float = Field(default=10.0, gt=0)
    closing_grace_sec: float = Field(default=1.0, ge=0)
    max_active_flows: int = Field(default=100_000, gt=0)


class ModelsConfig(BaseModel):
    default_version: str = "v1.0.0"
    saved_dir: str = "./models/saved"
    metadata_dir: str = "./models/metadata"
    # rules | hybrid | ml — see processing.pipeline.default_detectors
    detection_mode: Literal["rules", "hybrid", "ml"] = "rules"
    window_model: str = "window_rf"         # registry name used by hybrid / ml modes
    ml_alert_probability: float = Field(default=0.9, gt=0, le=1)


class IntelConfig(BaseModel):
    """Offline threat intelligence (scripts/import_intel.py, POST /intel/import). Nothing is fetched."""
    enabled: bool = True                     # match imported indicators during detection
    escalate_severity: bool = True           # raise other alerts one level when they involve a listed indicator
    max_file_mb: int = Field(default=50, gt=0)
    max_indicators: int = Field(default=1_000_000, gt=0)   # per import
    min_cidr_prefix_v4: int = Field(default=8, ge=0, le=32)     # reject broader networks
    min_cidr_prefix_v6: int = Field(default=32, ge=0, le=128)
    default_ttl_days: Optional[int] = Field(default=None, gt=0)   # expiry for indicators without one


class ExportConfig(BaseModel):
    """
    Alert/incident files for the analyst side (JSON lines, CEF, STIX 2.1).
    On-demand exports (POST /export, scripts/export_alerts.py) are always
    available; ``continuous`` also writes new alerts as they are stored.
    """
    directory: str = "./exports"
    continuous: bool = False
    formats: list[Literal["jsonl", "cef", "stix"]] = Field(default_factory=lambda: ["jsonl", "cef", "stix"])
    include_incidents: bool = True
    incident_gap_sec: int = Field(default=300, ge=10)        # same meaning as GET /incidents?gap_sec
    incident_min_alerts: int = Field(default=2, ge=1)
    rotate_max_mb: float = Field(default=10.0, gt=0)
    rotate_max_stix_objects: int = Field(default=5000, ge=10)
    backup_count: int = Field(default=20, ge=0)               # rotated files kept per stream; 0 keeps all
    stix_indicator_valid_days: int = Field(default=30, ge=0)  # valid_until of exported indicators; 0: none


class PathsConfig(BaseModel):
    data_dir: str = "./data"
    raw_dir: str = "./data/raw"
    processed_dir: str = "./data/processed"
    samples_dir: str = "./data/samples"
    config_dir: str = "./configs"
    reports_dir: str = "./reports"
    logs_dir: str = "./logs"


# ---------------------------------------------------------------------------
# Unified config object
# ---------------------------------------------------------------------------

class UnishieldConfig(BaseModel):
    """Aggregated configuration for the entire application."""
    app_name: str = "UniShield"
    version: str = "0.1.0"
    environment: str = "development"
    debug: bool = True
    log_level: str = "INFO"

    security: SecurityConfig = SecurityConfig()
    api: APIConfig = APIConfig()
    database: DatabaseConfig = DatabaseConfig()
    processing: ProcessingConfig = ProcessingConfig()
    ingest: IngestConfig = IngestConfig()
    network: NetworkConfig = NetworkConfig()
    sessionizer: SessionizerConfig = SessionizerConfig()
    models: ModelsConfig = ModelsConfig()
    intel: IntelConfig = IntelConfig()
    export: ExportConfig = ExportConfig()
    paths: PathsConfig = PathsConfig()


# ---------------------------------------------------------------------------
# Environment overrides
# ---------------------------------------------------------------------------

# Supported environment variables → config field path. Security flags are
# deliberately absent: they cannot be changed from the environment.
ENV_OVERRIDES: dict[str, tuple[str, ...]] = {
    "UNISHIELD_ENV": ("environment",),
    "UNISHIELD_DEBUG": ("debug",),
    "UNISHIELD_LOG_LEVEL": ("log_level",),
    "UNISHIELD_API_HOST": ("api", "host"),
    "UNISHIELD_API_PORT": ("api", "port"),
    "UNISHIELD_WINDOW_SIZE_SEC": ("processing", "window_size_sec"),
    "UNISHIELD_SLIDE_INTERVAL_SEC": ("processing", "slide_interval_sec"),
    "UNISHIELD_ANONYMIZE_IPS": ("security", "anonymize_ips"),
    "UNISHIELD_IP_HASH_SALT": ("security", "ip_hash_salt"),
    "UNISHIELD_LOGS_DIR": ("paths", "logs_dir"),
    "UNISHIELD_DATA_DIR": ("paths", "data_dir"),
    "UNISHIELD_DETECTION_MODE": ("models", "detection_mode"),
    "UNISHIELD_DB_URL": ("database", "url"),
    "UNISHIELD_ADMIN_API_KEY": ("api", "admin_api_key"),
    "UNISHIELD_EXPORT_DIR": ("export", "directory"),
    "UNISHIELD_EXPORT_CONTINUOUS": ("export", "continuous"),
}


def _apply_env_overrides(merged: dict[str, Any]) -> dict[str, Any]:
    """Overlay supported environment variables onto the merged config dict.
    Values stay strings; Pydantic coerces them to the field types."""
    for var, path in ENV_OVERRIDES.items():
        value = os.getenv(var)
        if value is None or value == "":
            continue
        node = merged
        for key in path[:-1]:
            node = node.setdefault(key, {})
        node[path[-1]] = value
    return merged


# ---------------------------------------------------------------------------
# Global config loader (singleton)
# ---------------------------------------------------------------------------

_config: UnishieldConfig | None = None


def load_config(config_path: Path | None = None) -> UnishieldConfig:
    """
    Load and validate the application configuration.

    Merges YAML config with environment overrides.
    Security constraints are validated — the system will refuse
    to start if read-only mode is disabled.
    """
    global _config

    if _config is not None:
        return _config

    # Pick up a local .env without overriding variables already set.
    env_file = Path.cwd() / ".env"
    if env_file.is_file():
        load_dotenv(env_file, override=False)

    if config_path is None:
        config_path = _resolve_config_path("config.yaml")

    raw: dict[str, Any] = {}
    if config_path.exists():
        raw = load_yaml(config_path)
    else:
        logger.warning("Config file not found at %s; using built-in defaults", config_path)

    # Flatten the "app" section to top-level fields
    app_section = raw.pop("app", {})
    merged = {
        "app_name": app_section.get("name", "UniShield"),
        "version": app_section.get("version", "0.1.0"),
        "environment": app_section.get("environment", "development"),
        "debug": app_section.get("debug", True),
        "log_level": app_section.get("log_level", "INFO"),
        **raw,
    }

    _config = UnishieldConfig(**_apply_env_overrides(merged))
    return _config


def get_config() -> UnishieldConfig:
    """Return the loaded config, loading defaults if not yet initialised."""
    global _config
    if _config is None:
        return load_config()
    return _config


def reset_config() -> None:
    """Reset the global config (used in testing)."""
    global _config
    _config = None


# ---------------------------------------------------------------------------
# Threshold loader
# ---------------------------------------------------------------------------

_thresholds: dict[str, Any] | None = None


def load_thresholds(path: Path | None = None) -> dict[str, Any]:
    """Load detection thresholds from YAML."""
    global _thresholds
    if _thresholds is not None:
        return _thresholds

    if path is None:
        path = _resolve_config_path("thresholds.yaml")

    if path.exists():
        _thresholds = load_yaml(path)
    else:
        logger.warning(
            "Thresholds file not found at %s; detectors will use built-in defaults", path
        )
        _thresholds = {}

    return _thresholds


def get_thresholds() -> dict[str, Any]:
    """Return loaded thresholds, loading defaults if necessary."""
    global _thresholds
    if _thresholds is None:
        return load_thresholds()
    return _thresholds


def reset_thresholds() -> None:
    """Reset cached thresholds (used in testing)."""
    global _thresholds
    _thresholds = None
