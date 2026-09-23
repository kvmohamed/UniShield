"""
UniShield — Unit Tests for Configuration

Tests config loading, security constraint enforcement,
threshold loading, and config reset.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from unishield.config import (
    SecurityConfig,
    UnishieldConfig,
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
