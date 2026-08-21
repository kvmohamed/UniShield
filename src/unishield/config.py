"""
UniShield — Configuration Module

Loads settings from YAML files and environment variables.
All security constraints are validated at startup.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field, field_validator
from pydantic_settings import BaseSettings


# ---------------------------------------------------------------------------
# Path resolution
# ---------------------------------------------------------------------------

def _project_root() -> Path:
    """Return the project root (parent of src/)."""
    return Path(__file__).resolve().parent.parent.parent


def _resolve_config_path(filename: str) -> Path:
    """Resolve a config file path relative to the project root."""
    config_dir = os.getenv("UNISHIELD_CONFIG_DIR", str(_project_root() / "configs"))
    return Path(config_dir) / filename


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
    will raise a validation error.
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
    reload: bool = True


class DatabaseConfig(BaseModel):
    url: str = "sqlite+aiosqlite:///./data/unishield.db"
    echo: bool = False
    pool_size: int = 5


class ProcessingConfig(BaseModel):
    window_size_sec: int = 10
    slide_interval_sec: int = 5
    max_queue_size: int = 10000
    max_alert_batch: int = 100
    max_records_in_memory: int = 50000


class IngestConfig(BaseModel):
    supported_formats: list[str] = Field(
        default=["pcap", "pcapng", "zeek_json", "flow_csv", "flow_json"]
    )
    max_file_size_mb: int = 500


class ModelsConfig(BaseModel):
    default_version: str = "v1.0.0"
    saved_dir: str = "./models/saved"
    metadata_dir: str = "./models/metadata"


class PathsConfig(BaseModel):
    data_dir: str = "./data"
    raw_dir: str = "./data/raw"
    processed_dir: str = "./data/processed"
    samples_dir: str = "./data/samples"
    config_dir: str = "./configs"
    reports_dir: str = "./reports"


class DashboardConfig(BaseModel):
    port: int = 8501
    theme: str = "dark"


# ---------------------------------------------------------------------------
# App-level settings (loaded from env + YAML)
# ---------------------------------------------------------------------------

class AppSettings(BaseSettings):
    """Top-level environment-driven settings."""
    env: str = Field(default="development", alias="UNISHIELD_ENV")
    debug: bool = Field(default=True, alias="UNISHIELD_DEBUG")
    log_level: str = Field(default="INFO", alias="UNISHIELD_LOG_LEVEL")

    class Config:
        env_prefix = "UNISHIELD_"
        env_file = ".env"
        extra = "ignore"


# ---------------------------------------------------------------------------
# Unified config object
# ---------------------------------------------------------------------------

class UnishieldConfig(BaseModel):
    """Aggregated configuration for the entire application."""
    app_name: str = "UniShield"
    version: str = "0.1.0"
    environment: str = "development"
    debug: bool = True

    security: SecurityConfig = SecurityConfig()
    api: APIConfig = APIConfig()
    database: DatabaseConfig = DatabaseConfig()
    processing: ProcessingConfig = ProcessingConfig()
    ingest: IngestConfig = IngestConfig()
    models: ModelsConfig = ModelsConfig()
    paths: PathsConfig = PathsConfig()
    dashboard: DashboardConfig = DashboardConfig()


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

    if config_path is None:
        config_path = _resolve_config_path("config.yaml")

    raw: dict[str, Any] = {}
    if config_path.exists():
        raw = load_yaml(config_path)

    # Flatten the "app" section to top-level fields
    app_section = raw.pop("app", {})
    merged = {
        "app_name": app_section.get("name", "UniShield"),
        "version": app_section.get("version", "0.1.0"),
        "environment": app_section.get("environment", "development"),
        "debug": app_section.get("debug", True),
        **raw,
    }

    _config = UnishieldConfig(**merged)
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
