"""Site thresholds overlay: merged over thresholds.yaml key by key, validated, never written back."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest
import yaml

from unishield.config import (
    ENV_OVERRIDES,
    get_thresholds,
    load_thresholds,
    merge_thresholds,
    reset_config,
    reset_thresholds,
    threshold_sources,
)
from unishield.detectors.scan_detector import ScanDetector

ROOT = Path(__file__).resolve().parents[2]
BASE = ROOT / "configs" / "thresholds.yaml"


@pytest.fixture
def clean_env(monkeypatch):
    for var in [*ENV_OVERRIDES, "UNISHIELD_CONFIG_DIR"]:
        monkeypatch.delenv(var, raising=False)
    reset_config()
    reset_thresholds()
    yield monkeypatch
    reset_config()
    reset_thresholds()


def write(path: Path, data) -> Path:
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    return path


class TestMerge:
    base = {
        "scanning": {"unique_dest_ports": 25, "failed_connection_ratio": 0.5,
                     "severity_levels": {"high": {"unique_dest_ports": 50}}},
        "encrypted": {"ja3_blocklist": {}, "outdated_tls_versions": ["SSLv3"], "realert_after_sec": 900},
        "flags": {"enabled": True},
    }

    def test_leaves_are_replaced_and_the_rest_kept(self):
        merged = merge_thresholds(self.base, {"scanning": {"unique_dest_ports": 40,
                                                           "severity_levels": {"high": {"unique_dest_ports": 80}}}})
        assert merged["scanning"] == {"unique_dest_ports": 40, "failed_connection_ratio": 0.5,
                                      "severity_levels": {"high": {"unique_dest_ports": 80}}}
        assert self.base["scanning"]["unique_dest_ports"] == 25          # input not mutated

    def test_int_and_float_are_interchangeable(self):
        assert merge_thresholds(self.base, {"scanning": {"unique_dest_ports": 37.5}})["scanning"]["unique_dest_ports"] == 37.5

    def test_free_form_mappings_and_lists_are_replaced_whole(self):
        merged = merge_thresholds(self.base, {"encrypted": {"ja3_blocklist": {"abc": "tool"},
                                                            "outdated_tls_versions": ["TLSv1.0"]}})
        assert merged["encrypted"]["ja3_blocklist"] == {"abc": "tool"}
        assert merged["encrypted"]["outdated_tls_versions"] == ["TLSv1.0"]

    def test_metadata_keys_are_ignored(self):
        merged = merge_thresholds(self.base, {"_learned": {"anything": 1}, "scanning": {"unique_dest_ports": 30}})
        assert "_learned" not in merged and merged["scanning"]["unique_dest_ports"] == 30

    @pytest.mark.parametrize("overlay, message", [
        ({"scaning": {"unique_dest_ports": 30}}, "unknown threshold 'scaning'"),
        ({"scanning": {"unique_ports": 30}}, "unknown threshold 'scanning.unique_ports'"),
        ({"scanning": {"severity_levels": {"extreme": {}}}}, "scanning.severity_levels.extreme"),
        ({"scanning": {"unique_dest_ports": "many"}}, "must be a int"),
        ({"scanning": {"unique_dest_ports": True}}, "must be a int"),
        ({"flags": {"enabled": 1}}, "must be a bool"),
        ({"scanning": 5}, "must be a mapping"),
        ({"encrypted": {"outdated_tls_versions": "SSLv3"}}, "must be a list"),
    ])
    def test_mistakes_are_errors(self, overlay, message):
        with pytest.raises(ValueError, match=message):
            merge_thresholds(self.base, overlay, source="site.yaml")


class TestLoading:
    def test_default_has_no_overlay(self, clean_env):
        get_thresholds()
        (source,) = threshold_sources()
        assert source.endswith("thresholds.yaml")

    def test_overlay_named_in_environment(self, clean_env, tmp_path):
        site = write(tmp_path / "thresholds.site.yaml", {"scanning": {"unique_dest_ports": 40},
                                                         "_learned": {"scanning.unique_dest_ports": {}}})
        clean_env.setenv("UNISHIELD_THRESHOLDS_FILE", str(site))
        before = hashlib.sha256(BASE.read_bytes()).hexdigest()
        t = get_thresholds()
        assert t["scanning"]["unique_dest_ports"] == 40
        assert t["scanning"]["horizontal_scan_hosts"] == yaml.safe_load(BASE.read_text())["scanning"]["horizontal_scan_hosts"]
        assert threshold_sources()[-1] == str(site)
        assert ScanDetector()._thresholds["unique_dest_ports"] == 40     # detectors read the merged values
        assert hashlib.sha256(BASE.read_bytes()).hexdigest() == before   # thresholds.yaml is never written

    def test_relative_name_resolves_against_the_configs_directory(self, clean_env, tmp_path):
        configs = tmp_path / "configs"
        configs.mkdir()
        (configs / "config.yaml").write_text("site:\n  thresholds_file: thresholds.site.yaml\n", encoding="utf-8")
        (configs / "thresholds.yaml").write_text(BASE.read_text(encoding="utf-8"), encoding="utf-8")
        write(configs / "thresholds.site.yaml", {"dns": {"dga_min_domains": 25}})
        clean_env.setenv("UNISHIELD_CONFIG_DIR", str(configs))
        assert get_thresholds()["dns"]["dga_min_domains"] == 25

    def test_explicit_site_path_argument(self, clean_env, tmp_path):
        site = write(tmp_path / "s.yaml", {"ddos": {"packets_per_second": 20000}})
        assert load_thresholds(BASE, site_path=site)["ddos"]["packets_per_second"] == 20000

    def test_missing_overlay_is_an_error(self, clean_env, tmp_path):
        clean_env.setenv("UNISHIELD_THRESHOLDS_FILE", str(tmp_path / "missing.yaml"))
        with pytest.raises(FileNotFoundError, match="Site thresholds file not found"):
            get_thresholds()

    def test_invalid_overlay_is_an_error(self, clean_env, tmp_path):
        site = write(tmp_path / "bad.yaml", {"ddos": {"packets_per_secnd": 1}})
        clean_env.setenv("UNISHIELD_THRESHOLDS_FILE", str(site))
        with pytest.raises(ValueError, match="ddos.packets_per_secnd"):
            get_thresholds()
