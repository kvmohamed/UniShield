"""Continuous synthetic site traffic: ordered, seeded, at the requested rate, with its benign behaviours."""

from __future__ import annotations

from collections import Counter
from datetime import timedelta

from unishield.assets import AssetInventory
from unishield.data.sample_generator import SimulatedReader
from unishield.data.site_traffic import SITE_HOSTS, SiteTraffic, site_assets
from unishield.processing.pipeline import Pipeline


def take(traffic: SiteTraffic, hours: float, chunk: float = 5.0):
    flows, end = [], traffic.start + timedelta(hours=hours)
    while traffic.now < end:
        flows += traffic.next_chunk(chunk)
    return flows


def test_stream_is_time_ordered_and_seeded():
    a = take(SiteTraffic(rate_per_sec=10, seed=1, attack_every_sec=600), 0.5)
    b = take(SiteTraffic(rate_per_sec=10, seed=1, attack_every_sec=600), 0.5)
    assert all(x.timestamp <= y.timestamp for x, y in zip(a, a[1:]))
    assert [(f.timestamp, f.source_ip, f.destination_ip) for f in a] == \
        [(f.timestamp, f.source_ip, f.destination_ip) for f in b]


def test_background_rate_is_close_to_the_request():
    traffic = SiteTraffic(rate_per_sec=50, seed=2, profile="plain")
    flows = take(traffic, 0.25, chunk=1.0)
    span = (flows[-1].timestamp - flows[0].timestamp).total_seconds()
    assert 45 <= len(flows) / span <= 55


def test_site_behaviours_and_attacks_are_scheduled():
    traffic = SiteTraffic(rate_per_sec=2, seed=3, attack_every_sec=900)
    flows = take(traffic, 1.5)
    sources = Counter(f.source_ip for f in flows)
    assert 20 * 180 <= sources[SITE_HOSTS["monitoring"]] <= 20 * 181       # 20 servers every 30 s
    probes = [f for f in flows if f.source_ip == SITE_HOSTS["vulnerability_scanner"]
              and f.destination_ip in SITE_HOSTS["scan_targets"]]
    assert len(probes) == 600                                            # 150 ports x 4 hosts
    assert sum(f.orig_bytes for f in flows if f.destination_ip == SITE_HOSTS["backup_server"]) > 100_000_000
    assert sum(traffic.injected.values()) in (5, 6) and traffic.injected["port_scan"] == 1   # every 15 min


def test_matching_inventory_leaves_no_benign_alert_above_info():
    flows = take(SiteTraffic(rate_per_sec=1, seed=3), 1.5)
    noisy = Pipeline().run(SimulatedReader(flows))
    tuned = Pipeline(assets=AssetInventory(site_assets())).run(SimulatedReader(flows))
    assert {a.threat_class.value for a in noisy.alerts} >= {"C2_BEACONING", "PORT_SCAN", "DATA_EXFILTRATION"}
    assert [a for a in tuned.alerts if a.severity.value != "INFO"] == []
    assert tuned.summary()["asset_policy"]["suppressed"] >= 1


def test_short_soak_run_samples_and_reports(tmp_path):
    from unishield.evaluation.soak import SoakConfig, render_markdown, run_soak

    report = run_soak(SoakConfig(duration_sec=4, rate=1500, speedup=30, sample_every_sec=1,
                                 attack_every_sec=60, state_path=str(tmp_path / "state.json"),
                                 snapshot_interval_sec=1))
    s = report["summary"]
    assert len(report["samples"]) >= 4 and s["errors"] == 0 and s["records"] > 3000
    assert s["traffic_seconds"] > 90 and s["state"]["saves"] >= 2
    assert all(x["rss_mb"] > 0 for x in report["samples"])
    text = render_markdown(report, commit="abc1234")
    assert "## Summary" in text and "abc1234" in text and "Records processed" in text
