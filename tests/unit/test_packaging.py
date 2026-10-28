"""Deployment files stay consistent with the code: entry point, shutdown timing, proxy headers, state dir."""

from __future__ import annotations

import configparser
import re
from pathlib import Path

import yaml

from unishield.config import APIConfig

ROOT = Path(__file__).resolve().parents[2]
SHUTDOWN = APIConfig().shutdown_timeout_sec


def _unit() -> configparser.ConfigParser:
    parser = configparser.ConfigParser(strict=False, interpolation=None)
    parser.optionxform = str
    parser.read_string((ROOT / "deploy/systemd/unishield.service").read_text(encoding="utf-8"))
    return parser


def test_systemd_unit_runs_the_entry_point_unprivileged_with_time_to_stop():
    service = _unit()["Service"]
    assert service["ExecStart"].endswith("python -m unishield.main")
    assert "unishield-admin db upgrade" in service["ExecStartPre"]
    assert service["User"] == "unishield" and service["NoNewPrivileges"] == "yes"
    assert service["CapabilityBoundingSet"] == "" and service["ProtectSystem"] == "strict"
    assert service["KillSignal"] == "SIGTERM" and int(service["TimeoutStopSec"]) > 2 * SHUTDOWN
    env = (ROOT / "deploy/systemd/unishield.env").read_text(encoding="utf-8")
    assert "UNISHIELD_ENV=production" in env and "UNISHIELD_AUTH_MODE=accounts" in env
    assert not re.search(r"^UNISHIELD_ADMIN_API_KEY=", env, re.M)          # no shipped credentials


def test_reverse_proxy_examples_forward_scheme_and_client_address():
    nginx = (ROOT / "deploy/nginx/unishield.conf").read_text(encoding="utf-8")
    assert "proxy_set_header X-Forwarded-Proto $scheme;" in nginx
    assert "proxy_set_header X-Forwarded-For   $remote_addr;" in nginx
    assert "proxy_pass http://127.0.0.1:8000;" in nginx and "return 301 https://" in nginx
    caddy = (ROOT / "deploy/caddy/Caddyfile").read_text(encoding="utf-8")
    assert "reverse_proxy 127.0.0.1:8000" in caddy
    assert APIConfig().forwarded_allow_ips == "127.0.0.1"


def test_container_uses_the_entry_point_and_a_writable_state_dir():
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert 'CMD ["python", "-m", "unishield.main"]' in dockerfile
    assert "mkdir -p logs data state exports" in dockerfile
    assert "chown -R unishield:unishield /app/logs /app/state /app/exports" in dockerfile
    compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))["services"]["api"]
    assert int(compose["stop_grace_period"].rstrip("s")) > 2 * SHUTDOWN
    assert compose["environment"]["UNISHIELD_DB_URL"] == "sqlite:////app/state/unishield.db"
    assert {"unishield-state:/app/state", "unishield-exports:/app/exports"} <= set(compose["volumes"])
    assert compose["environment"]["UNISHIELD_EXPORT_DIR"] == "/app/exports"
    assert all(p.startswith("127.0.0.1:") for p in compose["ports"])
