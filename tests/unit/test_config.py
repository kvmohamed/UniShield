"""
UniShield — Unit Tests for Configuration

Tests config loading, security constraint enforcement,
threshold loading, and config reset.
"""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

from unishield.config import (
    ENV_OVERRIDES,
    SecurityConfig,
    UnishieldConfig,
    config_dir,
    load_config,
    reset_config,
    load_thresholds,
    reset_thresholds,
)


class TestSecurityConfig:
    """Security constraints must always be True."""

    def test_default_security_config(self):
        sec = SecurityConfig()
        assert sec.read_only_mode is True
        assert sec.no_payload_decryption is True
        assert sec.no_active_scanning is True
        assert sec.no_response_path is True

    def test_cannot_disable_read_only(self):
        with pytest.raises(Exception, match="must always be True"):
            SecurityConfig(read_only_mode=False)

    def test_cannot_disable_no_payload_decryption(self):
        with pytest.raises(Exception, match="must always be True"):
            SecurityConfig(no_payload_decryption=False)

    def test_cannot_disable_no_active_scanning(self):
        with pytest.raises(Exception, match="must always be True"):
            SecurityConfig(no_active_scanning=False)

    def test_cannot_disable_no_response_path(self):
        with pytest.raises(Exception, match="must always be True"):
            SecurityConfig(no_response_path=False)

    def test_anonymisation_optional(self):
        sec = SecurityConfig(anonymize_ips=True)
        assert sec.anonymize_ips is True

        sec2 = SecurityConfig(anonymize_ips=False)
        assert sec2.anonymize_ips is False


class TestUnishieldConfig:
    """Test aggregated config loading."""

    def setup_method(self):
        reset_config()

    def test_default_config(self):
        config = UnishieldConfig()
        assert config.app_name == "UniShield"
        assert config.version == "0.1.0"
        assert config.security.read_only_mode is True
        assert config.api.port == 8000
        assert config.processing.window_size_sec == 10
        assert config.processing.slide_interval_sec == 5

    def test_load_config_from_yaml(self):
        config_path = Path(__file__).resolve().parent.parent.parent / "configs" / "config.yaml"
        if config_path.exists():
            reset_config()
            config = load_config(config_path)
            assert config.app_name == "UniShield"
            assert config.security.read_only_mode is True

    def test_config_singleton(self):
        reset_config()
        c1 = load_config()
        c2 = load_config()
        assert c1 is c2


class TestThresholds:
    """Test threshold loading."""

    def setup_method(self):
        reset_thresholds()

    def test_load_thresholds(self):
        thresholds_path = (
            Path(__file__).resolve().parent.parent.parent / "configs" / "thresholds.yaml"
        )
        if thresholds_path.exists():
            t = load_thresholds(thresholds_path)
            assert "ddos" in t
            assert "scanning" in t
            assert "beaconing" in t
            assert "exfiltration" in t
            assert t["ddos"]["packets_per_second"] > 0

    def test_nonexistent_thresholds_file(self):
        reset_thresholds()
        t = load_thresholds(Path("/nonexistent/thresholds.yaml"))
        assert t == {}


@pytest.fixture
def clean_env(monkeypatch):
    """Isolate config tests from the developer's environment and .env file."""
    for var in [*ENV_OVERRIDES, "UNISHIELD_CONFIG_DIR"]:
        monkeypatch.delenv(var, raising=False)
    reset_config()
    reset_thresholds()
    yield monkeypatch
    reset_config()
    reset_thresholds()


def _write_config(directory: Path, body: str) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "config.yaml"
    path.write_text(body, encoding="utf-8")
    return path


class TestEnvironmentOverrides:
    """UNISHIELD_* variables override YAML; security flags cannot be overridden."""

    def test_env_overrides_yaml(self, clean_env):
        clean_env.setenv("UNISHIELD_API_PORT", "9001")
        clean_env.setenv("UNISHIELD_WINDOW_SIZE_SEC", "20")
        clean_env.setenv("UNISHIELD_DEBUG", "false")
        config = load_config()
        assert config.api.port == 9001
        assert config.processing.window_size_sec == 20
        assert config.debug is False

    def test_invalid_env_value_rejected(self, clean_env):
        clean_env.setenv("UNISHIELD_API_PORT", "not-a-port")
        with pytest.raises(Exception, match="api.port|port"):
            load_config()

    def test_security_flags_have_no_env_override(self, clean_env):
        assert not any(path[0] == "security" and path[-1] in {
            "read_only_mode", "no_payload_decryption", "no_active_scanning", "no_response_path",
        } for path in ENV_OVERRIDES.values())
        clean_env.setenv("UNISHIELD_READ_ONLY_MODE", "false")
        assert load_config().security.read_only_mode is True

    def test_dotenv_file_loaded_from_working_directory(self, clean_env, tmp_path):
        (tmp_path / ".env").write_text("UNISHIELD_API_PORT=8123\n", encoding="utf-8")
        clean_env.chdir(tmp_path)
        assert load_config().api.port == 8123

    def test_process_env_beats_dotenv(self, clean_env, tmp_path):
        (tmp_path / ".env").write_text("UNISHIELD_API_PORT=8123\n", encoding="utf-8")
        clean_env.setenv("UNISHIELD_API_PORT", "8999")
        clean_env.chdir(tmp_path)
        assert load_config().api.port == 8999


class TestConfigLocation:
    """Config directory is found for editable, packaged and Docker layouts."""

    def test_config_dir_env_var(self, clean_env, tmp_path):
        _write_config(tmp_path / "custom", "api:\n  port: 1234\n")
        clean_env.setenv("UNISHIELD_CONFIG_DIR", str(tmp_path / "custom"))
        assert config_dir() == tmp_path / "custom"
        assert load_config().api.port == 1234

    def test_working_directory_configs_used(self, clean_env, tmp_path):
        """Packaged installs (e.g. Docker) read ./configs from the working directory."""
        _write_config(tmp_path / "configs", "api:\n  port: 4321\n")
        clean_env.chdir(tmp_path)
        assert config_dir() == tmp_path / "configs"
        assert load_config().api.port == 4321

    def test_missing_config_warns_and_uses_defaults(self, clean_env, tmp_path, caplog):
        clean_env.setenv("UNISHIELD_CONFIG_DIR", str(tmp_path / "empty"))
        with caplog.at_level(logging.WARNING, logger="unishield.config"):
            config = load_config()
        assert config.api.port == 8000
        assert "Config file not found" in caplog.text

    def test_missing_thresholds_warns(self, clean_env, tmp_path, caplog):
        with caplog.at_level(logging.WARNING, logger="unishield.config"):
            assert load_thresholds(tmp_path / "nope.yaml") == {}
        assert "Thresholds file not found" in caplog.text
