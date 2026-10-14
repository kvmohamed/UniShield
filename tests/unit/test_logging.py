"""
UniShield — Unit Tests for Logging Setup

Logging must be configured by the API startup hook (so it also applies
when the app is launched directly with uvicorn) and write to the
configured logs directory.
"""

from __future__ import annotations

import logging

import pytest
from fastapi.testclient import TestClient

from unishield import logging_config
from unishield.config import reset_config


@pytest.fixture
def isolated_logging(monkeypatch, tmp_path):
    monkeypatch.setenv("UNISHIELD_LOGS_DIR", str(tmp_path / "logs"))
    monkeypatch.setattr(logging_config, "_configured", False)
    reset_config()
    yield tmp_path / "logs"
    # Close file handlers so the temp directory can be removed on Windows.
    for name in ("unishield", "unishield.ingest", "unishield.detectors", "unishield.api"):
        log = logging.getLogger(name)
        for handler in list(log.handlers):
            handler.close()
            log.removeHandler(handler)
    reset_config()


def test_setup_logging_writes_to_configured_dir(isolated_logging):
    logging_config.setup_logging()
    logging.getLogger("unishield.test").info("hello from test")
    for handler in logging.getLogger("unishield").handlers:
        handler.flush()
    log_file = isolated_logging / "unishield.log"
    assert log_file.exists()
    assert "hello from test" in log_file.read_text(encoding="utf-8")


def test_setup_logging_is_idempotent(isolated_logging):
    logging_config.setup_logging()
    handlers_before = list(logging.getLogger("unishield").handlers)
    logging_config.setup_logging()
    assert logging.getLogger("unishield").handlers == handlers_before


def test_api_startup_configures_logging(isolated_logging):
    from unishield.api.app import app

    with TestClient(app) as client:
        assert client.get("/health").status_code == 200
    assert logging_config._configured is True
    assert (isolated_logging / "unishield.log").exists()
