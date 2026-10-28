"""Learning mode: what is recorded, how suggestions are made, the overlay it writes, CLI and API."""

from __future__ import annotations

import runpy
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import yaml

from unishield.assets import AssetInventory
from unishield.config import get_thresholds, merge_thresholds, reset_config, reset_thresholds, threshold_sources
from unishield.data.sample_generator import SimulatedReader, save_sample_flows
from unishield.data.site_traffic import SITE_HOSTS, SiteTraffic, site_assets
from unishield.evaluation.learning import (
    LEARNED,
    BaselineLearner,
    LearnedThreshold,
    learn,
    render_report,
    render_site_thresholds,
)
from unishield.processing.pipeline import Pipeline

ROOT = Path(__file__).resolve().parents[2]
DEFAULTS = yaml.safe_load((ROOT / "configs" / "thresholds.yaml").read_text(encoding="utf-8"))
META = {"generated_at": "2026-10-22T00:00:00+00:00", "inputs": ["test"], "records": 10, "windows": 2,
        "first_event": "a", "last_event": "b", "percentile": 99.9, "allow_tighten": False, "assets": 0,
        "threshold_sources": []}


def site_flows(hours: float, seed: int, rate: float = 2.0):
    traffic, flows = SiteTraffic(rate_per_sec=rate, seed=seed), []
    while traffic.now < traffic.start + timedelta(hours=hours):
        flows += traffic.next_chunk(5.0)
    return flows


@pytest.fixture(scope="module")
def learned_without_assets():
    run = learn([("site", SimulatedReader(site_flows(1.5, seed=4)))], thresholds=get_thresholds(),
                threshold_sources=threshold_sources(), assets=AssetInventory())
    return run, {s.key: s for s in run.learner.suggest(DEFAULTS)}


class TestSuggestionArithmetic:
    upper = LearnedThreshold("x.y", "test", integer=True, floor=10)

    def one(self, spec, samples, current, **kw):
        return BaselineLearner._suggest_one(spec, samples, kw.pop("pct", 99.9), kw.pop("margin", spec.margin),
                                            current, current, kw.pop("allow_tighten", False), [])

    def test_loosens_when_benign_traffic_comes_close(self):
        s = self.one(self.upper, [10] * 999 + [40], 25)
        assert (s.observed, s.suggested, s.changed, s.still_reaching) == (40, 60, True, 0)

    def test_keeps_the_current_value_when_there_is_headroom(self):
        s = self.one(self.upper, [1, 2, 3], 25)
        assert s.suggested == 25 and not s.changed and "headroom" in s.reason

    def test_tightening_is_opt_in_and_floored(self):
        s = self.one(self.upper, [1, 2, 3], 25, allow_tighten=True)
        assert s.suggested == 10 and s.changed                         # 3 x 1.5 = 4.5, floor 10

    def test_cap_and_rounding(self):
        capped = LearnedThreshold("a.b", "t", margin=1.05, cap=0.95)
        assert self.one(capped, [0.93], 0.6).suggested == 0.95
        assert self.one(LearnedThreshold("a.b", "t"), [3.14159], 1.0).suggested == 4.72   # 4.712 rounded up

    def test_lower_direction_goes_below_the_most_regular_pair(self):
        cv = LearnedThreshold("b.cv", "t", direction="lower", margin=0.8, floor=0.05)
        s = self.one(cv, [0.2, 0.5], 0.3, pct=0.1)
        assert s.observed == 0.2 and s.suggested == 0.16 and s.still_reaching == 0
        floored = self.one(cv, [0.01, 0.5], 0.3, pct=0.1)
        assert floored.suggested == 0.05 and floored.still_reaching == 1 and "floor" in floored.reason
        assert self.one(cv, [0.5], 0.3, pct=0.1).suggested == 0.3

    def test_no_samples_keeps_the_value(self):
        s = self.one(self.upper, [], 25)
        assert s.suggested == 25 and s.observed is None and "no samples" in s.reason


class TestLearningOnSiteTraffic:
    def test_unlisted_benign_hosts_raise_thresholds_and_are_named(self, learned_without_assets):
        _, s = learned_without_assets
        ports = s["scanning.unique_dest_ports"]
        assert ports.changed and ports.observed == 150 and ports.suggested == 225
        assert ports.top[0][0] == SITE_HOSTS["vulnerability_scanner"]
        assert s["exfiltration.min_upload_mb"].top[0][0].startswith(SITE_HOSTS["backup_client"])
        assert s["beaconing.regularity_cv_threshold"].suggested == 0.05      # monitoring polls are perfectly regular
        assert not s["ddos.packets_per_second"].changed

    def test_with_the_inventory_nothing_needs_raising(self):
        run = learn([("site", SimulatedReader(site_flows(1.5, seed=4)))], thresholds=get_thresholds(),
                    threshold_sources=threshold_sources(), assets=AssetInventory(site_assets()))
        changed = [x.key for x in run.learner.suggest(DEFAULTS) if x.changed]
        # the score thresholds depend on window-to-window noise, not on asset roles
        assert [k for k in changed if not k.startswith(("statistical.", "anomaly."))] == []
        assert run.learner.excluded["scanning (asset role)"] > 0
        assert run.learner.would_alert == {} and run.learner.info_alerts["PORT_SCAN"] > 0

    def test_every_threshold_is_recorded_per_window(self, learned_without_assets):
        run, _ = learned_without_assets
        for spec in LEARNED:
            if not spec.key.startswith(("statistical.", "anomaly.", "beaconing.")):
                assert run.learner.series[spec.key].seen == run.learner.windows

    def test_the_learned_overlay_removes_the_false_alarm(self, learned_without_assets, tmp_path, monkeypatch):
        run, s = learned_without_assets
        text = render_site_thresholds(list(s.values()), DEFAULTS, DEFAULTS, run.meta("now", 99.9, False))
        site = tmp_path / "thresholds.site.yaml"
        site.write_text(text, encoding="utf-8")
        fresh = site_flows(1.0, seed=9)
        before = [a for a in Pipeline().run(SimulatedReader(fresh)).alerts if a.threat_class.value == "PORT_SCAN"]
        monkeypatch.setenv("UNISHIELD_THRESHOLDS_FILE", str(site))
        reset_config()
        reset_thresholds()
        try:
            after = [a for a in Pipeline().run(SimulatedReader(fresh)).alerts if a.threat_class.value == "PORT_SCAN"]
        finally:
            monkeypatch.delenv("UNISHIELD_THRESHOLDS_FILE")
            reset_config()
            reset_thresholds()
        assert before and after == []


class TestOverlayFile:
    def test_overlay_loads_and_documents_every_value(self, learned_without_assets):
        run, s = learned_without_assets
        text = render_site_thresholds(list(s.values()), DEFAULTS, DEFAULTS, run.meta("now", 99.9, False))
        data = yaml.safe_load(text)
        merged = merge_thresholds(DEFAULTS, data)
        assert merged["scanning"]["unique_dest_ports"] == 225
        assert merged["ddos"] == DEFAULTS["ddos"]                          # unchanged values are comments only
        assert "# ddos:    (no changes)" in text and "# packets_per_second: 10000" in text
        provenance = data["_learned"]["values"]
        assert set(provenance) == {spec.key for spec in LEARNED}
        assert provenance["scanning.unique_dest_ports"].items() >= {
            "percentile": 99.9, "observed": 150, "default": 25, "suggested": 225}.items()

    def test_values_of_an_active_overlay_are_carried_over(self, learned_without_assets):
        run, s = learned_without_assets
        current = merge_thresholds(DEFAULTS, {"dns": {"subdomain_uniqueness": 0.9},
                                              "ddos": {"severity_levels": {"high": {"packets_per_second": 30000}}}})
        text = render_site_thresholds(list(s.values()), DEFAULTS, current, run.meta("now", 99.9, False))
        merged = merge_thresholds(DEFAULTS, yaml.safe_load(text))
        assert merged["dns"]["subdomain_uniqueness"] == 0.9
        assert merged["ddos"]["severity_levels"]["high"]["packets_per_second"] == 30000

    def test_report_names_hosts_and_unlearned_thresholds(self, learned_without_assets):
        run, s = learned_without_assets
        text = render_report(run.learner, list(s.values()), run.meta("now", 99.9, False))
        assert "## Who drove the raised values" in text and SITE_HOSTS["vulnerability_scanner"] in text
        assert "## Beacon-like pairs" in text and "`dns.subdomain_uniqueness`" in text
        assert "assumes the period contained no attack" in text


class TestCli:
    def run(self, monkeypatch, *argv):
        monkeypatch.setattr(sys, "argv", ["learn_baseline.py", *map(str, argv)])
        try:
            runpy.run_path(str(ROOT / "scripts" / "learn_baseline.py"), run_name="__main__")
        except SystemExit as exc:
            return exc.code
        return 0

    def test_refuses_to_write_thresholds_yaml_or_overwrite(self, monkeypatch, tmp_path, capsys):
        assert self.run(monkeypatch, "--synthetic-hours", 1, "--out", ROOT / "configs" / "thresholds.yaml") == 2
        assert "refusing to write thresholds.yaml" in capsys.readouterr().err
        existing = tmp_path / "site.yaml"
        existing.write_text("ddos: {}\n")
        assert self.run(monkeypatch, "--synthetic-hours", 1, "--out", existing) == 2
        assert existing.read_text() == "ddos: {}\n"

    def test_learns_from_files_and_saves_state(self, monkeypatch, tmp_path):
        flows = site_flows(0.5, seed=5)
        a = save_sample_flows(flows[: len(flows) // 2], tmp_path / "day1.jsonl")
        b = save_sample_flows(flows[len(flows) // 2:], tmp_path / "day2.jsonl")
        out, report, state = tmp_path / "s.yaml", tmp_path / "r.md", tmp_path / "state.json"
        assert self.run(monkeypatch, a, b, "--out", out, "--report", report, "--state-out", state) == 0
        assert yaml.safe_load(out.read_text(encoding="utf-8"))["_learned"]["inputs"] == [str(a), str(b)]
        assert "## Learning data" in report.read_text(encoding="utf-8") and state.is_file()


def test_api_learning_run_stores_no_alerts(api_client):
    client, data_dir = api_client
    path = save_sample_flows(site_flows(0.5, seed=6), data_dir / "site.jsonl")
    assert client.get("/learning/latest").json()["status"] == "no_learning_run"
    started = client.post("/replay/start", params={"file_path": str(path), "learning": True}).json()
    assert started["learning"] is True
    client.app.state.ctx.wait(120)
    body = client.get("/learning/latest").json()
    assert body["status"] == "completed" and body["windows"] > 0
    assert "scanning.unique_dest_ports" in body["changed"]
    merge_thresholds(DEFAULTS, yaml.safe_load(body["thresholds_site_yaml"]))
    assert "# UniShield — Learning Report" in body["report_markdown"]
    assert client.get("/alerts").json() == [] and body["would_alert"]


def test_timestamps_in_meta_are_iso(learned_without_assets):
    run, _ = learned_without_assets
    meta = run.meta("now", 99.9, False)
    assert datetime.fromisoformat(meta["first_event"]) < datetime.fromisoformat(meta["last_event"])
    assert datetime.fromisoformat(meta["first_event"]).tzinfo == timezone.utc


def test_learning_routes_need_their_roles(client_as):
    assert client_as(None).get("/learning/latest").status_code == 401
    viewer = client_as("viewer")
    assert viewer.get("/learning/latest").status_code == 200
    assert viewer.post("/replay/start", params={"file_path": "x", "learning": True}).status_code == 403
