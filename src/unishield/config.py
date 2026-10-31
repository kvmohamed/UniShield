"""
UniShield — Configuration Module

Loads settings from YAML files, then applies environment-variable
overrides (from the process environment or a ``.env`` file).
All security constraints are validated at startup.

Precedence (highest first):
    1. Environment variables listed in ``ENV_OVERRIDES``
    2. ``configs/config.yaml``
    3. Model defaults below

Site files (section ``site``): ``assets.yaml`` (asset inventory, validated
by ``AssetInventoryConfig``) and an optional thresholds overlay such as
``thresholds.site.yaml``, merged over ``thresholds.yaml`` key by key.
"""

from __future__ import annotations

import copy
import ipaddress
import logging
import os
from pathlib import Path
from typing import Any, Literal, Optional

import yaml
from dotenv import load_dotenv
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from unishield.schemas.alert import ThreatClass

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


def resolve_site_path(name: str) -> Path:
    """A site file named in the config: absolute, or relative to the configs directory."""
    path = Path(name).expanduser()
    return path if path.is_absolute() else config_dir() / path


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
    # Static service token for automation, sent as the X-API-Key header. Set it
    # only through UNISHIELD_ADMIN_API_KEY; it acts with api_key_role. Named,
    # revocable tokens: unishield-admin token create.
    admin_api_key: Optional[str] = Field(default=None, repr=False)
    api_key_role: Literal["viewer", "analyst", "admin"] = "admin"
    cors_origins: list[str] = Field(default_factory=list)   # the dashboard is same-origin
    # Reverse proxies whose X-Forwarded-For / X-Forwarded-Proto headers are
    # trusted (client address for rate limiting and the audit log; https for
    # Secure cookies and HSTS). Comma-separated addresses or "*" (never "*"
    # when clients can reach UniShield directly).
    forwarded_allow_ips: str = "127.0.0.1"
    # On shutdown (SIGTERM / Ctrl+C) wait this long for a running replay to stop
    # and record its state; uvicorn also waits this long for open requests.
    shutdown_timeout_sec: int = Field(default=15, ge=1, le=600)
    # Interactive API docs (/docs, /redoc, /openapi.json). They need no login and
    # Swagger UI loads its scripts from a CDN: turn them off in production.
    docs_enabled: bool = True


class AuthConfig(BaseModel):
    """Accounts, sessions and login protection (docs/deployment.md)."""
    # accounts: every endpoint except /health, /auth/login, /auth/me and the
    #           dashboard page needs a login session or a service token.
    # open:     LAB ONLY. Read endpoints need no login; replay, deleting data,
    #           user management and the audit log still need an administrator.
    #           Refused when environment is "production".
    mode: Literal["accounts", "open"] = "accounts"
    session_ttl_minutes: int = Field(default=480, ge=5, le=10_080)      # absolute session lifetime
    session_idle_minutes: int = Field(default=30, ge=1, le=1_440)       # sign out after this much inactivity
    max_failed_logins: int = Field(default=5, ge=1, le=100)             # consecutive failures before lockout
    lockout_minutes: int = Field(default=15, ge=1, le=1_440)
    login_rate_limit: int = Field(default=10, ge=1, le=10_000)          # failed logins per client address...
    login_rate_window_sec: int = Field(default=300, ge=10, le=86_400)   # ...within this window
    min_password_length: int = Field(default=12, ge=8, le=128)
    # Secure flag on the session cookie: auto = when the request arrived over
    # HTTPS (directly or via a trusted proxy's X-Forwarded-Proto).
    cookie_secure: Literal["auto", "always", "never"] = "auto"


class TLSConfig(BaseModel):
    """HTTPS served by uvicorn itself. Alternatively terminate TLS at a reverse proxy (docs/deployment.md)."""
    certfile: Optional[str] = None          # PEM certificate chain (may also contain the key)
    keyfile: Optional[str] = None           # PEM private key
    # Only from UNISHIELD_TLS_KEYFILE_PASSWORD, never in a file.
    keyfile_password: Optional[str] = Field(default=None, repr=False)
    # Strict-Transport-Security on HTTPS responses (direct TLS or a trusted
    # proxy's X-Forwarded-Proto: https); 0 disables it.
    hsts_max_age: int = Field(default=31_536_000, ge=0)
    hsts_include_subdomains: bool = False

    @property
    def enabled(self) -> bool:
        return bool(self.certfile)

    @model_validator(mode="after")
    def _key_needs_certificate(self) -> "TLSConfig":
        if self.keyfile and not self.certfile:
            raise ValueError("tls.keyfile is set but tls.certfile is not")
        return self


class RetentionConfig(BaseModel):
    """Housekeeping run by the API every ``interval_minutes`` (and by ``unishield-admin retention run``)."""
    # Delete alerts stored more than this many days ago, and finished runs
    # older than that. None keeps them forever. The audit log is never purged.
    alert_days: Optional[int] = Field(default=None, ge=1, le=36_500)
    interval_minutes: int = Field(default=60, ge=1, le=10_080)


class DatabaseConfig(BaseModel):
    url: str = "sqlite:///./data/unishield.db"
    echo: bool = False
    pool_size: int = 5
    # Apply pending schema migrations when the API starts. When false, run
    # ``unishield-admin db upgrade`` yourself; the API refuses to start on an
    # outdated schema.
    auto_migrate: bool = True


class ProcessingConfig(BaseModel):
    window_size_sec: int = 10
    slide_interval_sec: int = 5
    # Records may arrive this much (traffic time) out of order before they are
    # dropped as late. Raising it delays every window's analysis by the same amount.
    allowed_lateness_sec: float = Field(default=0.0, ge=0)
    max_queue_size: int = 10000
    max_alert_batch: int = 100
    max_records_in_memory: int = 50000
    # PipelineResult.alerts keeps the most recent alerts only (counts cover the whole run;
    # stored alerts are in the database). Bounds memory on long runs.
    max_alerts_in_memory: int = Field(default=100_000, gt=0)


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


_NAME_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$"
_ENV_NAME_PATTERN = r"^[A-Z_][A-Z0-9_]{0,127}$"
SeverityName = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


class TLSOptions(BaseModel):
    ca_file: Optional[str] = None            # trust only this CA bundle (default: system store)
    cert_file: Optional[str] = None          # client certificate (mutual TLS)
    key_file: Optional[str] = None
    verify: bool = True                      # verify certificate and host name


class SyslogDestination(BaseModel):
    """One analyst-side syslog receiver (SIEM). The host must be in outbound.allowed_destinations."""
    name: str = Field(pattern=_NAME_PATTERN)
    host: str = Field(min_length=1, max_length=253)
    port: Optional[int] = Field(default=None, ge=1, le=65535)     # default 514 (udp/tcp), 6514 (tls)
    protocol: Literal["udp", "tcp", "tls"] = "udp"
    message_format: Literal["cef", "json"] = "cef"
    min_severity: SeverityName = "INFO"
    include_incidents: bool = True
    redact_ips: bool = False
    max_message_bytes: Optional[int] = Field(default=None, ge=480, le=1_048_576)
    tls: TLSOptions = TLSOptions()


class SyslogConfig(BaseModel):
    enabled: bool = False
    facility: Literal["kern", "user", "mail", "daemon", "auth", "syslog", "lpr", "news", "uucp", "cron",
                      "authpriv", "ftp", "local0", "local1", "local2", "local3", "local4", "local5",
                      "local6", "local7"] = "local4"
    app_name: str = Field(default="unishield", max_length=48)
    hostname: Optional[str] = Field(default=None, max_length=255)   # default: this machine's name
    sd_id: str = Field(default="unishield@32473", max_length=32)     # 32473: documentation PEN (RFC 5612)
    destinations: list[SyslogDestination] = Field(default_factory=list)


class NotificationSettings(BaseModel):
    """Severity filter, rate limit, digest and content of one notification channel."""
    min_severity: SeverityName = "HIGH"
    min_interval_sec: float = Field(default=300, ge=0)       # at most one message per interval...
    max_per_hour: int = Field(default=12, ge=1)              # ...and this many per rolling hour
    digest_max_alerts: int = Field(default=50, ge=1)         # alerts listed in a digest (the rest counted)
    redact_ips: bool = False
    fields: list[str] = Field(default_factory=lambda: [
        "alert_id", "window_end", "threat_class", "severity", "confidence", "detector_name",
        "source_ip", "destination_ip", "mitre_techniques", "summary"])

    @field_validator("fields")
    @classmethod
    def known_fields(cls, v: list[str]) -> list[str]:
        from unishield.export.notify import ALLOWED_FIELDS

        unknown = sorted(set(v) - set(ALLOWED_FIELDS))
        if unknown:
            raise ValueError(f"unknown notification fields {unknown}; choose from {list(ALLOWED_FIELDS)}")
        return v


class EmailConfig(NotificationSettings):
    enabled: bool = False
    smtp_host: str = ""                      # analyst-side relay; must be in outbound.allowed_destinations
    smtp_port: Optional[int] = Field(default=None, ge=1, le=65535)   # default 587 / 465 / 25
    security: Literal["starttls", "ssl", "none"] = "starttls"
    username: Optional[str] = None
    password_env: Optional[str] = Field(default="UNISHIELD_SMTP_PASSWORD", pattern=_ENV_NAME_PATTERN)
    sender: str = ""
    recipients: list[str] = Field(default_factory=list)
    subject_prefix: str = Field(default="[UniShield]", max_length=64)
    tls: TLSOptions = TLSOptions()


class WebhookDestination(NotificationSettings):
    name: str = Field(pattern=_NAME_PATTERN)
    url: str = Field(min_length=8, max_length=2048)          # http(s)://host[:port]/path, host allow-listed
    headers_from_env: dict[str, str] = Field(default_factory=dict)   # header → environment variable
    tls: TLSOptions = TLSOptions()

    @field_validator("headers_from_env")
    @classmethod
    def env_names(cls, v: dict[str, str]) -> dict[str, str]:
        import re

        for header, variable in v.items():
            if not re.match(r"^[A-Za-z0-9-]{1,64}$", header) or not re.match(_ENV_NAME_PATTERN, variable):
                raise ValueError(f"headers_from_env: invalid header {header!r} or variable name {variable!r}")
        return v


class WebhookConfig(BaseModel):
    enabled: bool = False
    destinations: list[WebhookDestination] = Field(default_factory=list)


class OutboundConfig(BaseModel):
    """
    Delivery to the analyst network only: syslog to a SIEM, email to a relay,
    JSON webhooks. All off by default. Destinations must be listed in
    ``allowed_destinations`` and lie outside ``network.home_networks``;
    this is checked at load time and before every connection.
    """
    allowed_destinations: list[str] = Field(default_factory=list)   # analyst-side IPs, CIDRs, host names
    connect_timeout_sec: float = Field(default=5.0, gt=0, le=60)
    queue_size: int = Field(default=10_000, ge=10)
    syslog: SyslogConfig = SyslogConfig()
    email: EmailConfig = EmailConfig()
    webhook: WebhookConfig = WebhookConfig()


class PathsConfig(BaseModel):
    data_dir: str = "./data"
    raw_dir: str = "./data/raw"
    processed_dir: str = "./data/processed"
    samples_dir: str = "./data/samples"
    config_dir: str = "./configs"
    reports_dir: str = "./reports"
    logs_dir: str = "./logs"


DEFAULT_ASSETS_FILE = "assets.yaml"


class SiteConfig(BaseModel):
    """Per-site files; relative paths are resolved against the configs directory."""
    assets_file: Optional[str] = DEFAULT_ASSETS_FILE    # asset inventory (roles of known hosts)
    thresholds_file: Optional[str] = None               # overlay over thresholds.yaml, e.g. thresholds.site.yaml


class LiveConfig(BaseModel):
    """Live, receive-only inputs (ingest/collector.py, ingest/zeek_follow.py)."""
    netflow_bind: str = "127.0.0.1"                     # interface facing the exporters (receive only)
    netflow_port: int = Field(default=2055, gt=0, lt=65536)
    allowed_exporters: list[str] = Field(default_factory=list)   # CIDRs; empty = any exporter
    zeek_from_start: bool = False                       # follow from the end of existing logs (like tail -F)
    zeek_poll_interval_sec: float = Field(default=1.0, gt=0, le=60)
    tick_interval_sec: float = Field(default=1.0, gt=0, le=60)
    # Flow exports report a flow after it ends (active/inactive timeouts), so
    # records arrive late; windows wait this long before closing.
    allowed_lateness_sec: float = Field(default=120.0, ge=0, le=3600)

    @field_validator("allowed_exporters")
    @classmethod
    def valid_networks(cls, v: list[str]) -> list[str]:
        import ipaddress

        for net in v:
            ipaddress.ip_network(net, strict=False)
        return v


class FeedbackConfig(BaseModel):
    """Analyst verdicts and suppression rules (storage/feedback.py)."""
    max_suppression_days: int = Field(default=90, ge=1, le=365)   # every suppression rule expires


class StateConfig(BaseModel):
    """Restart-safe detector state (see processing/state_store.py)."""
    enabled: bool = False
    path: str = "./data/state/pipeline_state.json"
    snapshot_interval_sec: float = Field(default=300.0, gt=0)


# ---------------------------------------------------------------------------
# Asset inventory (configs/assets.yaml)
# ---------------------------------------------------------------------------

AssetRole = Literal[
    "dns_resolver", "backup_server", "vulnerability_scanner", "update_server",
    "cdn_or_proxy", "monitoring", "mail_server", "server",
]
PolicyAction = Literal["alert", "info", "suppress"]


class AssetEntry(BaseModel):
    """One host or network and the roles it has."""
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=128)
    addresses: list[str] = Field(min_length=1)          # IP addresses or CIDR networks
    roles: list[AssetRole] = Field(min_length=1)
    description: str = ""

    @field_validator("addresses")
    @classmethod
    def valid_networks(cls, v: list[str]) -> list[str]:
        out = []
        for address in v:
            try:
                out.append(str(ipaddress.ip_network(str(address).strip(), strict=False)))
            except ValueError as exc:
                raise ValueError(f"invalid address or network {address!r}: {exc}") from None
        return out


class RolePolicy(BaseModel):
    """Action per threat class when the role holder is the alert's source or destination."""
    model_config = ConfigDict(extra="forbid")

    source: dict[ThreatClass, PolicyAction] = Field(default_factory=dict)
    destination: dict[ThreatClass, PolicyAction] = Field(default_factory=dict)


class AssetInventoryConfig(BaseModel):
    """Validated contents of the asset inventory file."""
    model_config = ConfigDict(extra="forbid")

    version: Literal[1] = 1
    assets: list[AssetEntry] = Field(default_factory=list)
    # Overrides of the built-in role policies (assets.DEFAULT_ROLE_POLICIES), merged per class.
    policies: dict[AssetRole, RolePolicy] = Field(default_factory=dict)

    @model_validator(mode="after")
    def unique_names(self) -> "AssetInventoryConfig":
        seen: set[str] = set()
        for entry in self.assets:
            if entry.name in seen:
                raise ValueError(f"duplicate asset name {entry.name!r}")
            seen.add(entry.name)
        return self


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
    auth: AuthConfig = AuthConfig()
    tls: TLSConfig = TLSConfig()
    database: DatabaseConfig = DatabaseConfig()
    retention: RetentionConfig = RetentionConfig()
    processing: ProcessingConfig = ProcessingConfig()
    ingest: IngestConfig = IngestConfig()
    network: NetworkConfig = NetworkConfig()
    sessionizer: SessionizerConfig = SessionizerConfig()
    models: ModelsConfig = ModelsConfig()
    intel: IntelConfig = IntelConfig()
    export: ExportConfig = ExportConfig()
    outbound: OutboundConfig = OutboundConfig()
    paths: PathsConfig = PathsConfig()
    site: SiteConfig = SiteConfig()
    state: StateConfig = StateConfig()
    live: LiveConfig = LiveConfig()
    feedback: FeedbackConfig = FeedbackConfig()

    @model_validator(mode="after")
    def outbound_only_to_analyst_side(self) -> "UnishieldConfig":
        """Refuse outbound destinations that are not allow-listed or lie in the monitored network."""
        from unishield.export.policy import validate_outbound

        validate_outbound(self)
        return self

    @model_validator(mode="after")
    def _open_mode_is_lab_only(self) -> "UnishieldConfig":
        if self.auth.mode == "open" and self.environment.lower() == "production":
            raise ValueError("auth.mode 'open' is for labs only and cannot be used with environment 'production'")
        return self


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
    "UNISHIELD_API_DOCS": ("api", "docs_enabled"),
    "UNISHIELD_API_RELOAD": ("api", "reload"),
    "UNISHIELD_FORWARDED_ALLOW_IPS": ("api", "forwarded_allow_ips"),
    "UNISHIELD_TLS_CERTFILE": ("tls", "certfile"),
    "UNISHIELD_TLS_KEYFILE": ("tls", "keyfile"),
    "UNISHIELD_TLS_KEYFILE_PASSWORD": ("tls", "keyfile_password"),
    "UNISHIELD_WINDOW_SIZE_SEC": ("processing", "window_size_sec"),
    "UNISHIELD_SLIDE_INTERVAL_SEC": ("processing", "slide_interval_sec"),
    "UNISHIELD_ANONYMIZE_IPS": ("security", "anonymize_ips"),
    "UNISHIELD_IP_HASH_SALT": ("security", "ip_hash_salt"),
    "UNISHIELD_LOGS_DIR": ("paths", "logs_dir"),
    "UNISHIELD_DATA_DIR": ("paths", "data_dir"),
    "UNISHIELD_DETECTION_MODE": ("models", "detection_mode"),
    "UNISHIELD_DB_URL": ("database", "url"),
    "UNISHIELD_ALERT_RETENTION_DAYS": ("retention", "alert_days"),
    "UNISHIELD_ADMIN_API_KEY": ("api", "admin_api_key"),
    "UNISHIELD_EXPORT_DIR": ("export", "directory"),
    "UNISHIELD_EXPORT_CONTINUOUS": ("export", "continuous"),
    "UNISHIELD_API_KEY_ROLE": ("api", "api_key_role"),
    "UNISHIELD_AUTH_MODE": ("auth", "mode"),
    "UNISHIELD_COOKIE_SECURE": ("auth", "cookie_secure"),
    "UNISHIELD_ASSETS_FILE": ("site", "assets_file"),
    "UNISHIELD_THRESHOLDS_FILE": ("site", "thresholds_file"),
    "UNISHIELD_STATE_ENABLED": ("state", "enabled"),
    "UNISHIELD_STATE_FILE": ("state", "path"),
    "UNISHIELD_NETFLOW_BIND": ("live", "netflow_bind"),
    "UNISHIELD_NETFLOW_PORT": ("live", "netflow_port"),
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
_threshold_sources: list[str] = []


def site_thresholds_path() -> Optional[Path]:
    """The configured site thresholds overlay (``site.thresholds_file``), if any."""
    name = get_config().site.thresholds_file
    return resolve_site_path(name) if name else None


def _same_kind(default: Any, value: Any) -> bool:
    if isinstance(default, bool) or isinstance(value, bool):
        return isinstance(default, bool) and isinstance(value, bool)
    if isinstance(default, (int, float)):
        return isinstance(value, (int, float))
    return isinstance(value, type(default))


def merge_thresholds(base: dict[str, Any], overlay: dict[str, Any], source: str = "overlay") -> dict[str, Any]:
    """
    ``base`` with the values of ``overlay`` replacing it key by key.

    Every overlay key must already exist in ``base`` with a value of the same
    kind, so a typo cannot be ignored silently. Empty mappings in ``base``
    (``ja3_blocklist``) are free-form and replaced whole. Top-level keys
    starting with ``_`` are metadata (learning provenance) and skipped.
    """
    merged = copy.deepcopy(base)

    def merge(target: dict[str, Any], values: Any, prefix: str) -> None:
        if not isinstance(values, dict):
            raise ValueError(f"{source}: '{prefix}' must be a mapping")
        for key, value in values.items():
            name = f"{prefix}.{key}" if prefix else str(key)
            if key not in target:
                raise ValueError(f"{source}: unknown threshold '{name}' (not in thresholds.yaml)")
            default = target[key]
            if isinstance(default, dict) and default:
                merge(default, value, name)
            elif not _same_kind(default, value):
                raise ValueError(f"{source}: '{name}' must be a {type(default).__name__}, got {value!r}")
            else:
                target[key] = copy.deepcopy(value)

    merge(merged, {k: v for k, v in overlay.items() if not str(k).startswith("_")}, "")
    return merged


def load_thresholds(path: Path | None = None, site_path: Path | None = None,
                    use_site: bool = True) -> dict[str, Any]:
    """
    Load detection thresholds from YAML, then merge the site overlay over
    them (``site_path``, else ``site.thresholds_file`` / ``UNISHIELD_THRESHOLDS_FILE``;
    none with ``use_site=False``). A configured overlay that is missing or
    invalid raises an error.
    """
    global _thresholds, _threshold_sources
    if _thresholds is not None:
        return _thresholds

    if path is None:
        path = _resolve_config_path("thresholds.yaml")

    sources: list[str] = []
    if path.exists():
        thresholds = load_yaml(path)
        sources.append(str(path))
    else:
        logger.warning(
            "Thresholds file not found at %s; detectors will use built-in defaults", path
        )
        thresholds = {}

    if site_path is None and use_site:
        site_path = site_thresholds_path()
    if site_path is not None:
        if not site_path.is_file():
            raise FileNotFoundError(f"Site thresholds file not found: {site_path}")
        thresholds = merge_thresholds(thresholds, load_yaml(site_path), source=str(site_path))
        sources.append(str(site_path))
        logger.info("Site thresholds loaded from %s", site_path)

    _thresholds, _threshold_sources = thresholds, sources
    return _thresholds


def threshold_sources() -> list[str]:
    """Files the loaded thresholds came from (defaults first, then the site overlay)."""
    get_thresholds()
    return list(_threshold_sources)


def get_thresholds() -> dict[str, Any]:
    """Return loaded thresholds, loading defaults if necessary."""
    global _thresholds
    if _thresholds is None:
        return load_thresholds()
    return _thresholds


def reset_thresholds() -> None:
    """Reset cached thresholds (used in testing)."""
    global _thresholds, _threshold_sources
    _thresholds = None
    _threshold_sources = []


# ---------------------------------------------------------------------------
# Asset inventory loader
# ---------------------------------------------------------------------------

_assets: AssetInventoryConfig | None = None
_assets_source: Optional[str] = None


def load_assets(path: Path | None = None) -> AssetInventoryConfig:
    """
    Load and validate the asset inventory (``site.assets_file`` /
    ``UNISHIELD_ASSETS_FILE`` unless ``path`` is given). A missing default
    ``assets.yaml`` means no assets; a missing file that was named explicitly,
    or an invalid one, raises an error.
    """
    global _assets, _assets_source
    if _assets is not None:
        return _assets

    name = get_config().site.assets_file
    if path is None and not name:
        _assets, _assets_source = AssetInventoryConfig(), None
        return _assets
    explicit = path is not None or name != DEFAULT_ASSETS_FILE
    path = path if path is not None else resolve_site_path(name)
    if not path.is_file():
        if explicit:
            raise FileNotFoundError(f"Asset inventory not found: {path}")
        logger.info("No asset inventory at %s; no asset roles apply", path)
        _assets, _assets_source = AssetInventoryConfig(), None
        return _assets
    try:
        _assets = AssetInventoryConfig(**load_yaml(path))
    except ValueError as exc:
        raise ValueError(f"Invalid asset inventory {path}: {exc}") from exc
    _assets_source = str(path)
    logger.info("Asset inventory loaded from %s: %d entries", path, len(_assets.assets))
    return _assets


def get_assets() -> AssetInventoryConfig:
    """Return the loaded asset inventory, loading it if necessary."""
    return _assets if _assets is not None else load_assets()


def assets_source() -> Optional[str]:
    """File the asset inventory came from (None when there is none)."""
    get_assets()
    return _assets_source


def reset_assets() -> None:
    """Reset the cached asset inventory (used in testing)."""
    global _assets, _assets_source
    _assets, _assets_source = None, None
