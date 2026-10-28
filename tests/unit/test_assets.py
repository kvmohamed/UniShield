"""Asset inventory: validation, lookup, and the effect of every role policy (never silent)."""

from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import yaml

from unishield.assets import AssetInventory, AssetPolicy, alert_sources
from unishield.config import (
    AssetInventoryConfig,
    get_assets,
    load_assets,
    reset_assets,
    reset_config,
)
from unishield.data.sample_generator import (
    C2_SERVER,
    EXFIL_DEST,
    SimulatedReader,
    build_scenario,
    generate_dga_traffic,
    generate_dns_tunnel_traffic,
    generate_normal_traffic,
)
from unishield.features.exfiltration import ExfiltrationFeatureExtractor
from unishield.processing.pipeline import Pipeline
from unishield.schemas.alert import Alert, Severity, ThreatClass
from unishield.schemas.flow import FlowDirection, NormalisedFlow, ProtocolType

ROOT = Path(__file__).resolve().parents[2]
T0 = datetime(2026, 1, 1, tzinfo=timezone.utc)
SCANNERS = "198.18.0.96/28"            # covers the generator's scanner addresses (198.18.0.100-102)
RESOLVER = "10.0.9.53"


def inventory(*entries, policies=None, salt=None) -> AssetInventory:
    assets = [{"name": f"a{i}", "addresses": addrs, "roles": roles} for i, (addrs, roles) in enumerate(entries)]
    return AssetInventory(AssetInventoryConfig(assets=assets, policies=policies or {}), salt)


def run(flows, inv, **kw):
    pipeline = Pipeline(assets=inv, **kw)
    result = pipeline.run(SimulatedReader(sorted(flows, key=lambda f: f.timestamp)))
    return result, pipeline


def by_class(result, threat):
    return [a for a in result.alerts if a.threat_class.value == threat]


@pytest.fixture
def clean_assets():
    reset_assets()
    reset_config()
    yield
    reset_assets()
    reset_config()


# --------------------------------------------------------------- validation

class TestInventoryConfig:
    def test_addresses_are_normalised(self):
        cfg = AssetInventoryConfig(assets=[{"name": "n", "addresses": ["10.0.0.5/24", "2001:DB8::1"],
                                            "roles": ["server"]}])
        assert cfg.assets[0].addresses == ["10.0.0.0/24", "2001:db8::1/128"]

    @pytest.mark.parametrize("bad, message", [
        ({"assets": [{"name": "x", "addresses": ["10.0.0.300"], "roles": ["server"]}]}, "invalid address"),
        ({"assets": [{"name": "x", "addresses": ["10.0.0.1"], "roles": ["firewall"]}]}, "roles"),
        ({"assets": [{"name": "x", "addresses": ["10.0.0.1"], "roles": []}]}, "roles"),
        ({"assets": [{"name": "x", "addresses": [], "roles": ["server"]}]}, "addresses"),
        ({"assets": [{"name": "x", "addresses": ["10.0.0.1"], "roles": ["server"], "colour": "red"}]}, "colour"),
        ({"assets": [{"name": "x", "addresses": ["10.0.0.1"], "roles": ["server"]},
                     {"name": "x", "addresses": ["10.0.0.2"], "roles": ["server"]}]}, "duplicate asset name"),
        ({"policies": {"backup_server": {"destination": {"EXFIL": "suppress"}}}}, "EXFIL"),
        ({"policies": {"backup_server": {"destination": {"DATA_EXFILTRATION": "ignore"}}}}, "ignore"),
        ({"policies": {"backup_server": {"inbound": {}}}}, "inbound"),
        ({"version": 2}, "version"),
    ])
    def test_invalid_inventories_are_rejected(self, bad, message):
        with pytest.raises(ValueError, match=message):
            AssetInventoryConfig(**bad)

    def test_shipped_file_is_valid_and_empty(self):
        assert load_assets(ROOT / "configs" / "assets.yaml").assets == []
        reset_assets()

    def test_documented_example_is_valid(self):
        """The commented example in configs/assets.yaml must stay loadable."""
        lines = (ROOT / "configs" / "assets.yaml").read_text(encoding="utf-8").splitlines()
        start = lines.index("# version: 1")
        end = next(i for i in range(start, len(lines)) if lines[i].startswith("# ----"))
        example = "\n".join(line[2:] if line.startswith("# ") else line.lstrip("#") for line in lines[start:end])
        cfg = AssetInventoryConfig(**yaml.safe_load(example))
        roles = {r for a in cfg.assets for r in a.roles}
        assert roles == {"dns_resolver", "backup_server", "vulnerability_scanner", "update_server",
                         "cdn_or_proxy", "monitoring", "server"}
        assert cfg.policies["backup_server"].destination[ThreatClass.DATA_EXFILTRATION] == "info"

    def test_missing_default_file_means_no_assets(self, clean_assets, monkeypatch, tmp_path):
        monkeypatch.setenv("UNISHIELD_CONFIG_DIR", str(tmp_path))
        assert get_assets().assets == []

    def test_missing_named_file_is_an_error(self, clean_assets, monkeypatch, tmp_path):
        monkeypatch.setenv("UNISHIELD_ASSETS_FILE", str(tmp_path / "nope.yaml"))
        with pytest.raises(FileNotFoundError):
            get_assets()

    def test_invalid_file_is_an_error(self, clean_assets, monkeypatch, tmp_path):
        path = tmp_path / "assets.yaml"
        path.write_text("assets:\n  - name: x\n    addresses: [10.0.0.1]\n    roles: [toaster]\n")
        monkeypatch.setenv("UNISHIELD_ASSETS_FILE", str(path))
        with pytest.raises(ValueError, match="Invalid asset inventory"):
            get_assets()

    def test_file_named_in_environment_is_loaded(self, clean_assets, monkeypatch, tmp_path):
        path = tmp_path / "site-assets.yaml"
        path.write_text(yaml.safe_dump({"assets": [{"name": "r", "addresses": ["10.0.9.53"],
                                                    "roles": ["dns_resolver"]}]}))
        monkeypatch.setenv("UNISHIELD_ASSETS_FILE", str(path))
        assert AssetInventory.from_config().roles("10.0.9.53") == {"dns_resolver"}


# ------------------------------------------------------------------- lookup

class TestLookup:
    def test_networks_hosts_and_ipv6(self):
        inv = inventory((["10.0.5.0/24"], ["server"]), (["10.0.5.7"], ["backup_server"]),
                        (["2001:db8:5::/64"], ["monitoring"]))
        assert inv.roles("10.0.5.7") == {"server", "backup_server"}
        assert inv.roles("10.0.5.8") == {"server"}
        assert inv.roles("2001:db8:5::20") == {"monitoring"}
        assert inv.roles("10.0.6.1") == set() and inv.roles(None) == set()

    def test_anonymised_addresses_match_single_host_entries_only(self):
        inv = inventory((["192.0.2.10"], ["vulnerability_scanner"]), (["192.0.2.0/28"], ["server"]), salt="s")
        hashed = hashlib.sha256(b"s:192.0.2.10").hexdigest()[:16]
        assert inv.roles(hashed) == {"vulnerability_scanner"}
        assert inv.roles("192.0.2.10") == {"vulnerability_scanner", "server"}

    def test_overrides_merge_into_built_in_policies(self):
        inv = inventory(policies={"vulnerability_scanner": {"source": {"PORT_SCAN": "suppress"}}})
        assert inv.action("vulnerability_scanner", "source", ThreatClass.PORT_SCAN) == "suppress"
        assert inv.action("vulnerability_scanner", "source", ThreatClass.HOST_SCAN) == "info"

    def test_most_lenient_matching_role_wins(self):
        inv = inventory((["10.0.0.1"], ["server"]), (["10.0.0.2"], ["server"]),
                        policies={"server": {"source": {"PORT_SCAN": "info"},
                                             "destination": {"PORT_SCAN": "suppress"}}})
        assert inv.decide(ThreatClass.PORT_SCAN, ["10.0.0.1"], "10.0.0.2")[0] == "suppress"
        assert inv.decide(ThreatClass.PORT_SCAN, ["10.0.0.1"], "10.0.0.9")[0] == "info"
        assert inv.decide(ThreatClass.PORT_SCAN, ["10.0.0.9"], None) == ("alert", [])

    def test_every_source_must_hold_the_role(self):
        inv = inventory(([RESOLVER], ["dns_resolver"]))
        assert inv.decide(ThreatClass.DNS_TUNNELLING, [RESOLVER], None)[0] == "info"
        assert inv.decide(ThreatClass.DNS_TUNNELLING, [RESOLVER, "10.0.1.77"], None)[0] == "alert"

    def test_truncated_client_lists_are_not_trusted(self):
        alert = Alert(window_start=T0, window_end=T0, threat_class=ThreatClass.DNS_TUNNELLING,
                      severity=Severity.HIGH, confidence=0.9, detector_name="dns_detector",
                      evidence={"clients": [RESOLVER], "client_count": 6})
        assert alert_sources(alert) == []


# ------------------------------------------------------------- role effects

class TestVulnerabilityScanner:
    def test_scans_become_info_and_are_counted(self):
        plain = by_class(run(build_scenario("port_scan", 1).flows, inventory())[0], "PORT_SCAN")
        result, pipeline = run(build_scenario("port_scan", 1).flows,
                               inventory(([SCANNERS], ["vulnerability_scanner"])))
        scans = by_class(result, "PORT_SCAN")
        assert len(scans) == len(plain) > 0
        assert all(a.severity == Severity.INFO for a in scans)
        assert {a.evidence["asset_policy"]["original_severity"] for a in scans} \
            == {a.severity.value for a in plain}
        assert scans[0].evidence["asset_policy"]["matches"][0]["role"] == "vulnerability_scanner"
        stats = result.summary()["asset_policy"]
        assert stats["downgraded_to_info"] == len(scans) and stats["suppressed"] == 0
        assert pipeline.get_metrics().alerts_downgraded_by_policy == len(scans)

    def test_scans_can_be_suppressed_and_stay_visible_in_stats(self):
        inv = inventory(([SCANNERS], ["vulnerability_scanner"]),
                        policies={"vulnerability_scanner": {"source": {"PORT_SCAN": "suppress"}}})
        result, pipeline = run(build_scenario("port_scan", 1).flows, inv)
        assert by_class(result, "PORT_SCAN") == []
        assert result.summary()["asset_policy"]["by_action"]["suppress"]["PORT_SCAN"]["vulnerability_scanner"] > 0
        assert pipeline.asset_policy.recent_suppressed[0]["threat_class"] == "PORT_SCAN"
        assert pipeline.get_metrics().alerts_suppressed_by_policy == pipeline.asset_policy.suppressed > 0

    def test_suppressed_scan_windows_do_not_turn_into_statistical_alerts(self):
        inv = inventory(([SCANNERS], ["vulnerability_scanner"]),
                        policies={"vulnerability_scanner": {"source": {"PORT_SCAN": "suppress"}}})
        result, _ = run(build_scenario("port_scan", 1).flows, inv)
        assert result.alerts == []

    def test_other_scanners_are_unaffected(self):
        result, _ = run(build_scenario("port_scan", 1).flows, inventory((["198.18.0.200"], ["vulnerability_scanner"])))
        scans = by_class(result, "PORT_SCAN")
        assert scans and all(a.severity != Severity.INFO and "asset_policy" not in a.evidence for a in scans)


class TestBackupServer:
    def test_uploads_to_a_backup_server_are_not_exfiltration(self):
        flows = build_scenario("exfil_episodes", 1).flows
        plain = run(flows, inventory())[0]
        result, pipeline = run(flows, inventory(([EXFIL_DEST], ["backup_server"])))
        assert len(by_class(plain, "DATA_EXFILTRATION")) == 3
        assert by_class(result, "DATA_EXFILTRATION") == []
        assert result.summary()["asset_policy"]["by_action"]["suppress"]["DATA_EXFILTRATION"]["backup_server"] == 3
        assert {s["destination_ip"] for s in pipeline.asset_policy.recent_suppressed} == {EXFIL_DEST}
        assert len(by_class(result, "STATISTICAL_ANOMALY")) <= len(by_class(plain, "STATISTICAL_ANOMALY"))

    def test_backup_uploads_stay_out_of_the_source_baseline(self):
        backup, other, src = "203.0.113.10", "203.0.113.20", "10.0.2.40"

        def upload(t, dst, size):
            return NormalisedFlow(timestamp=T0 + timedelta(seconds=t), source_ip=src, destination_ip=dst,
                                  source_port=50000, destination_port=443, protocol=ProtocolType.TCP,
                                  packet_count=100, byte_count=size + 1000, orig_bytes=size, resp_bytes=1000,
                                  duration=1.0, conn_state="SF", direction=FlowDirection.OUTBOUND)

        ext = ExfiltrationFeatureExtractor(assets=inventory(([backup], ["backup_server"])))
        features = ext.extract([upload(0, backup, 20_000_000), upload(1, other, 300_000)])
        cands = {c["destination_ip"]: c for c in features["exfil_candidates"]}
        assert features["expected_upload_bytes"] == 20_000_000
        assert cands[backup]["expected_destination"] and not cands[other]["expected_destination"]
        assert cands[other]["source_window_upload"] == 300_000
        assert list(ext._baselines[src]) == [300_000.0]

    def test_uploads_elsewhere_still_alert(self):
        result, _ = run(build_scenario("exfil_episodes", 1).flows, inventory((["203.0.113.10"], ["backup_server"])))
        assert len(by_class(result, "DATA_EXFILTRATION")) == 3


class TestDnsResolver:
    def background(self):
        return generate_normal_traffic(40, T0, seed=3)

    def test_generated_names_from_a_resolver_are_info(self):
        flows = self.background() + generate_dga_traffic(120, T0 + timedelta(seconds=5), infected_ip=RESOLVER, seed=3)
        dga = by_class(run(flows, inventory(([RESOLVER], ["dns_resolver"])))[0], "DGA_DETECTED")
        assert dga and all(a.severity == Severity.INFO for a in dga)
        assert dga[0].evidence["asset_policy"]["matches"][0] == {
            "asset": "a0", "role": "dns_resolver", "side": "source", "address": RESOLVER}

    def test_a_client_behind_the_resolver_is_still_reported(self):
        flows = self.background() + generate_dga_traffic(120, T0 + timedelta(seconds=5), seed=3)
        dga = by_class(run(flows, inventory(([RESOLVER], ["dns_resolver"])))[0], "DGA_DETECTED")
        assert dga and all(a.severity != Severity.INFO for a in dga)

    def test_tunnelling_seen_only_from_the_resolver_is_info(self):
        flows = self.background() + generate_dns_tunnel_traffic(150, T0 + timedelta(seconds=5),
                                                                 client_ip=RESOLVER, seed=3)
        tunnel = by_class(run(flows, inventory(([RESOLVER], ["dns_resolver"])))[0], "DNS_TUNNELLING")
        assert tunnel and all(a.severity == Severity.INFO for a in tunnel)

    def test_tunnelling_with_a_non_resolver_client_keeps_its_severity(self):
        start = T0 + timedelta(seconds=5)
        flows = self.background() + generate_dns_tunnel_traffic(75, start, client_ip=RESOLVER, seed=3) \
            + generate_dns_tunnel_traffic(75, start, client_ip="10.0.1.77", seed=4)
        tunnel = by_class(run(flows, inventory(([RESOLVER], ["dns_resolver"])))[0], "DNS_TUNNELLING")
        assert tunnel and all(a.severity != Severity.INFO for a in tunnel)
        assert {"10.0.1.77", RESOLVER} <= set(tunnel[0].evidence["clients"])


class TestBeaconRoles:
    @pytest.mark.parametrize("address, role", [
        (C2_SERVER, "update_server"), (C2_SERVER, "cdn_or_proxy"), (C2_SERVER, "monitoring"),
        (C2_SERVER, "backup_server"),
        ("10.0.1.50", "monitoring"),
    ])
    def test_regular_polling_of_or_by_these_roles_is_info(self, address, role):
        result, pipeline = run(build_scenario("beacon_30s", 1).flows, inventory(([address], [role])))
        beacons = by_class(result, "C2_BEACONING")
        assert beacons and all(a.severity == Severity.INFO for a in beacons)
        assert pipeline.asset_policy.counts[("info", "C2_BEACONING", role)] == len(beacons)

    def test_monitoring_sweeps_are_info(self):
        result, _ = run(build_scenario("host_sweep", 1).flows, inventory(([SCANNERS], ["monitoring"])))
        sweeps = by_class(result, "HOST_SCAN")
        assert sweeps and all(a.severity == Severity.INFO for a in sweeps)


class TestServerRole:
    def test_server_role_is_context_only(self):
        result, pipeline = run(build_scenario("beacon_30s", 1).flows, inventory(([C2_SERVER], ["server"])))
        beacons = by_class(result, "C2_BEACONING")
        assert beacons and all(a.severity != Severity.INFO for a in beacons)
        assert beacons[0].evidence["assets"]["destination"] == [
            {"address": C2_SERVER, "asset": "a0", "roles": ["server"]}]
        assert pipeline.asset_policy.stats()["suppressed"] == pipeline.asset_policy.stats()["downgraded_to_info"] == 0

    def test_explicit_alert_policy_turns_a_built_in_off(self):
        inv = inventory(([SCANNERS], ["vulnerability_scanner"]),
                        policies={"vulnerability_scanner": {"source": {"PORT_SCAN": "alert"}}})
        scans = by_class(run(build_scenario("port_scan", 1).flows, inv)[0], "PORT_SCAN")
        assert scans and all(a.severity != Severity.INFO for a in scans)


def test_policy_without_assets_changes_nothing():
    policy = AssetPolicy(inventory())
    alert = Alert(window_start=T0, window_end=T0, threat_class=ThreatClass.PORT_SCAN, severity=Severity.HIGH,
                  confidence=0.9, detector_name="scan_detector", source_ip="10.0.0.1")
    assert policy.apply([alert]) == [alert] and "assets" not in alert.evidence
    assert policy.stats() == {"assets": 0, "suppressed": 0, "downgraded_to_info": 0, "kept_for_intel_match": 0,
                              "by_action": {}}


def test_api_shows_inventory_and_policy_effects(clean_assets, api_client, monkeypatch, tmp_path):
    client, _ = api_client
    path = tmp_path / "assets.yaml"
    path.write_text(yaml.safe_dump({"assets": [{"name": "scanner", "addresses": [SCANNERS],
                                                "roles": ["vulnerability_scanner"]}]}))
    monkeypatch.setenv("UNISHIELD_ASSETS_FILE", str(path))
    reset_config()
    reset_assets()
    before = client.get("/system/assets").json()
    assert before["assets"][0]["name"] == "scanner" and before["policy_effects"] is None
    assert before["policies"]["backup_server"]["destination"] == {"DATA_EXFILTRATION": "suppress",
                                                                  "C2_BEACONING": "info"}
    assert client.post("/replay/demo", params={"scenario": "port_scan", "wait": True}).json()["status"] == "completed"
    after = client.get("/system/assets").json()
    assert after["policy_effects"]["downgraded_to_info"] > 0
    assert client.get("/metrics").json()["alerts_downgraded_by_policy"] == after["policy_effects"]["downgraded_to_info"]
    stored = client.get("/alerts", params={"threat_class": "PORT_SCAN"}).json()
    assert stored and {a["severity"] for a in stored} == {"INFO"}
    assert client.get("/system/architecture").json()["assets_source"] == str(path)


def test_asset_view_needs_a_viewer(client_as):
    assert client_as(None).get("/system/assets").status_code == 401
    assert client_as("viewer").get("/system/assets").status_code == 200


class TestThreatIntelWins:
    def intel(self, address):
        from unishield.intel.matcher import IntelEntry, IntelMatcher

        return IntelMatcher([IntelEntry("feed", "ip", address, "known exfiltration server")])

    def test_a_role_never_hides_an_intel_match(self):
        flows = build_scenario("exfil_episodes", 1).flows
        pipeline = Pipeline(assets=inventory(([EXFIL_DEST], ["backup_server"])), intel=self.intel(EXFIL_DEST))
        result = pipeline.run(SimulatedReader(flows))
        exfil = by_class(result, "DATA_EXFILTRATION")
        assert len(exfil) == 3
        assert all(a.evidence["asset_policy"] == {
            "action": "alert", "overridden": "suppress", "reason": "an imported threat-intel indicator matched",
            "matches": [{"asset": "a0", "role": "backup_server", "side": "destination", "address": EXFIL_DEST}]}
            for a in exfil)
        stats = result.summary()["asset_policy"]
        assert stats["kept_for_intel_match"] == 3 and stats["suppressed"] == 0

    def test_without_a_match_the_role_still_applies(self):
        flows = build_scenario("exfil_episodes", 1).flows
        pipeline = Pipeline(assets=inventory(([EXFIL_DEST], ["backup_server"])), intel=self.intel("192.0.2.77"))
        assert by_class(pipeline.run(SimulatedReader(flows)), "DATA_EXFILTRATION") == []
