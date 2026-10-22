"""Offline threat-intelligence import: parsing, validation, storage, expiry and lookups."""

from __future__ import annotations

import json
import runpy
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from unishield.intel.indicators import IndicatorError, ParseOptions, classify, parse, parse_expiry
from unishield.intel.matcher import IntelEntry, IntelMatcher, hash_ip
from unishield.intel.store import IntelStore

NOW = datetime(2026, 10, 22, 12, 0, tzinfo=timezone.utc)
SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "import_intel.py"


class TestClassify:
    @pytest.mark.parametrize("raw,expected", [
        ("198.51.100.7", ("ip", "198.51.100.7")),
        ("198.51.100[.]7", ("ip", "198.51.100.7")),
        ("2001:DB8::1", ("ip", "2001:db8::1")),
        ("203.0.113.0/24", ("cidr", "203.0.113.0/24")),
        ("203.0.113.9/24", ("cidr", "203.0.113.0/24")),
        ("203.0.113.9/32", ("ip", "203.0.113.9")),
        ("Evil-C2[.]Example.", ("domain", "evil-c2.example")),
        ("*.bad.example", ("domain", "bad.example")),
        ("E7D705A3286E19EA42F587B344EE6865", ("ja3", "e7d705a3286e19ea42f587b344ee6865")),
    ])
    def test_values_are_classified_and_normalised(self, raw, expected):
        assert classify(raw) == expected

    @pytest.mark.parametrize("raw,reason", [
        ("hxxp://evil.example/payload", "URLs are not supported"),
        ("10.0.0.0/4", "broader than /8"),
        ("localhost", "at least two labels"),
        ("co.uk", "public suffix"),
        ("", "empty"),
        ("not a value", "not a valid domain"),
    ])
    def test_unusable_values_are_rejected_with_a_reason(self, raw, reason):
        with pytest.raises(IndicatorError, match=reason):
            classify(raw)

    def test_kind_hint_restricts_the_kind(self):
        with pytest.raises(IndicatorError):
            classify("evil.example", "ip")
        with pytest.raises(IndicatorError):
            classify("198.51.100.7", "ja3")
        assert classify("198.51.100.7", "ip-dst") == ("ip", "198.51.100.7")

    def test_network_size_limit_is_configurable(self):
        assert classify("10.0.0.0/4", options=ParseOptions(min_prefix_v4=4)) == ("cidr", "0.0.0.0/4")

    def test_date_only_expiry_lasts_the_whole_day(self):
        assert parse_expiry("2026-12-31") == datetime(2027, 1, 1, tzinfo=timezone.utc)
        assert parse_expiry("2026-12-31T08:00:00Z") == datetime(2026, 12, 31, 8, tzinfo=timezone.utc)
        assert parse_expiry("") is None


class TestFormats:
    def test_plain_text_with_comments_labels_and_duplicates(self):
        text = "# blocklist\n198.51.100.7 known C2\nevil[.]example  # phishing\n\n198.51.100.7\nhttp://x.example/a\n"
        result = parse(text)
        assert result.format == "text"
        assert [(i.kind, i.value, i.label) for i in result.indicators] == [
            ("ip", "198.51.100.7", "known C2"), ("domain", "evil.example", "")]
        assert result.duplicates == 1 and result.rejected_total == 1
        assert result.rejected[0]["record"] == 6

    def test_csv_with_header_type_expiry_severity_and_techniques(self):
        text = ("indicator,type,description,expires,severity,techniques\n"
                "198.51.100.7,ip,Feodo C2,2026-12-31,critical,T1071;T1573\n"
                "203.0.113.0/24,cidr,bulletproof hosting,,,\n"
                "bad.example,domain,phishing kit,,,\n"
                "e7d705a3286e19ea42f587b344ee6865,ja3,Trickbot,,,\n"
                "bad.example,url,wrong type,,,\n")
        result = parse(text, filename="feed.csv")
        assert result.format == "csv" and result.counts() == {"ip": 1, "cidr": 1, "domain": 1, "ja3": 1}
        first = result.indicators[0]
        assert first.label == "Feodo C2" and first.severity == "CRITICAL"
        assert first.techniques == ("T1071", "T1573")
        assert first.expires_at == datetime(2027, 1, 1, tzinfo=timezone.utc)
        assert result.rejected[0]["reason"].startswith("unsupported indicator type")

    def test_feed_style_csv_columns(self):
        feodo = ("# Feodo Tracker style\nfirst_seen_utc,dst_ip,dst_port,c2_status,last_online,malware\n"
                 "2026-10-01 10:00:00,198.51.100.20,443,online,2026-10-20,QakBot\n")
        (ind,) = parse(feodo).indicators
        assert (ind.kind, ind.value, ind.label) == ("ip", "198.51.100.20", "QakBot")
        sslbl = "ja3_md5,Firstseen,Lastseen,Listingreason\n" \
                "e7d705a3286e19ea42f587b344ee6865,2026-01-01,2026-10-01,Tofsee\n"
        (ind,) = parse(sslbl, filename="ja3.csv").indicators
        assert (ind.kind, ind.label) == ("ja3", "Tofsee")

    def test_headerless_csv_uses_first_column(self):
        result = parse("198.51.100.7,C2 server\nevil.example,phishing\n", fmt="csv")
        assert [(i.value, i.label) for i in result.indicators] == [
            ("198.51.100.7", "C2 server"), ("evil.example", "phishing")]

    def test_stix_bundle_indicators(self):
        bundle = {"type": "bundle", "id": "bundle--8f0c8a9c-6f0b-4bd6-9a59-1b8a3f8f1c11", "objects": [
            {"type": "indicator", "spec_version": "2.1", "id": "indicator--1", "name": "Emotet C2",
             "pattern": "[ipv4-addr:value = '198.51.100.30' OR ipv4-addr:value = '198.51.100.31']",
             "pattern_type": "stix", "valid_from": "2026-10-01T00:00:00Z", "valid_until": "2026-11-01T00:00:00Z",
             "external_references": [{"source_name": "mitre-attack", "external_id": "T1071"}]},
            {"type": "indicator", "id": "indicator--2", "pattern_type": "stix",
             "pattern": "[ipv4-addr:value ISSUBSET '203.0.113.0/24']", "indicator_types": ["malicious-activity"]},
            {"type": "indicator", "id": "indicator--3", "pattern_type": "stix",
             "pattern": "[domain-name:value = 'c2.bad.example']"},
            {"type": "indicator", "id": "indicator--4", "pattern_type": "stix",
             "pattern": "[ipv4-addr:value = '198.51.100.40' AND network-traffic:dst_port = 443]"},
            {"type": "indicator", "id": "indicator--5", "pattern_type": "snort", "pattern": "alert tcp any"},
            {"type": "indicator", "id": "indicator--6", "pattern_type": "stix", "revoked": True,
             "pattern": "[ipv4-addr:value = '198.51.100.50']"},
            {"type": "malware", "id": "malware--1", "name": "ignored", "is_family": True},
        ]}
        result = parse(json.dumps(bundle))
        assert result.format == "stix"
        assert [(i.kind, i.value) for i in result.indicators] == [
            ("ip", "198.51.100.30"), ("ip", "198.51.100.31"), ("cidr", "203.0.113.0/24"),
            ("domain", "c2.bad.example")]
        first = result.indicators[0]
        assert first.label == "Emotet C2" and first.techniques == ("T1071",)
        assert first.expires_at == datetime(2026, 11, 1, tzinfo=timezone.utc)
        assert result.indicators[2].label == "malicious-activity"
        assert result.rejected_total == 3            # AND pattern, non-STIX pattern, revoked

    def test_size_limit_stops_the_import(self):
        with pytest.raises(IndicatorError, match="more than 2"):
            parse("198.51.100.1\n198.51.100.2\n198.51.100.3\n", options=ParseOptions(max_indicators=2))

    def test_invalid_stix_json_is_an_error(self):
        with pytest.raises(IndicatorError, match="not valid JSON"):
            parse("{not json", fmt="stix")


class TestMatcher:
    def entries(self):
        return [
            IntelEntry("feed-a", "ip", "198.51.100.7", "C2"),
            IntelEntry("feed-b", "cidr", "203.0.113.0/24", "hosting"),
            IntelEntry("feed-b", "cidr", "2001:db8:bad::/48", "v6 hosting"),
            IntelEntry("feed-a", "domain", "bad.example", "phishing"),
            IntelEntry("feed-a", "ja3", "e7d705a3286e19ea42f587b344ee6865", "Trickbot"),
            IntelEntry("feed-c", "ip", "198.51.100.8", "old", expires_at=NOW - timedelta(days=1)),
        ]

    def test_exact_network_and_domain_lookups(self):
        m = IntelMatcher(self.entries())
        assert [e.source for e in m.match_ip("198.51.100.7", NOW)] == ["feed-a"]
        assert [e.value for e in m.match_ip("203.0.113.200", NOW)] == ["203.0.113.0/24"]
        assert [e.value for e in m.match_ip("2001:db8:bad:1::5", NOW)] == ["2001:db8:bad::/48"]
        assert m.match_ip("203.0.114.1", NOW) == [] and m.match_ip("not-an-ip", NOW) == []
        assert [e.value for e in m.match_domain("x.y.BAD.example.", NOW)] == ["bad.example"]
        assert m.match_domain("notbad.example", NOW) == [] and m.match_domain("example", NOW) == []
        assert m.ja3_labels(NOW) == {"e7d705a3286e19ea42f587b344ee6865": "feed-a: Trickbot"}
        assert m.counts == {"ip": 2, "cidr": 2, "domain": 1, "ja3": 1}

    def test_expired_entries_never_match(self):
        m = IntelMatcher(self.entries())
        assert m.match_ip("198.51.100.8", NOW) == []
        assert m.match_ip("198.51.100.8", NOW - timedelta(days=2))

    def test_anonymised_flows_match_hashed_addresses_but_not_networks(self):
        m = IntelMatcher(self.entries(), anonymize_salt="pepper")
        assert m.match_ip(hash_ip("198.51.100.7", "pepper"), NOW)
        assert m.match_ip("198.51.100.7", NOW) == []
        assert m.inactive_cidrs == 2 and m.counts["cidr"] == 0

    def test_empty_matcher(self):
        m = IntelMatcher()
        assert m.empty and m.match_ip("198.51.100.7") == [] and m.match_domain("bad.example") == []


class TestStore:
    @pytest.fixture
    def store(self):
        return IntelStore.from_url("sqlite://")

    def test_import_replace_append_remove_and_status(self, store):
        summary = store.import_text("198.51.100.7\nbad.example\n", "feed-a", filename="a.txt")
        assert summary["accepted"] == 2 and summary["by_kind"]["domain"] == 1 and len(summary["sha256"]) == 64
        store.import_text("198.51.100.9\n", "feed-a")                     # replace
        assert {e.value for e in store.entries()} == {"198.51.100.9"}
        again = store.import_text("198.51.100.9\n203.0.113.0/24\n", "feed-a", mode="append")
        assert again["accepted"] == 1 and again["already_present"] == 1
        store.import_text("e7d705a3286e19ea42f587b344ee6865\n", "feed-b")
        status = store.status()
        assert status["active_total"] == 3
        assert [s["source"] for s in status["sources"]] == ["feed-a", "feed-b"]
        assert status["recent_imports"][0]["source"] == "feed-b"
        assert store.remove_source("feed-a") == 2
        assert [e.kind for e in store.entries()] == ["ja3"]

    def test_expiry_is_stored_and_purged(self, store):
        store.import_text("indicator,expires\n198.51.100.7,2020-01-01\n198.51.100.8,\n", "feed")
        assert [e.value for e in store.entries()] == ["198.51.100.8"]
        status = store.status()
        assert status["by_kind"]["ip"] == {"active": 1, "expired": 1}
        assert store.purge_expired() == 1
        assert store.status()["expired_total"] == 0
        m = store.matcher()
        assert m.match_ip("198.51.100.8") and not m.match_ip("198.51.100.7")

    def test_invalid_source_and_mode_are_refused(self, store):
        with pytest.raises(IndicatorError):
            store.import_text("198.51.100.7\n", "../etc")
        with pytest.raises(IndicatorError):
            store.import_text("198.51.100.7\n", "feed", mode="merge")


def test_cli_imports_files_into_the_configured_database(tmp_path, monkeypatch, capsys):
    db = tmp_path / "intel.db"
    feed = tmp_path / "c2-list.txt"
    feed.write_text("198.51.100.7\nbad[.]example\nhttp://x.example/\n", encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["import_intel.py", "--db", f"sqlite:///{db}", "--expires", "2099-01-01",
                                      str(feed)])
    with pytest.raises(SystemExit) as exit_info:
        runpy.run_path(str(SCRIPT), run_name="__main__")
    assert exit_info.value.code == 0
    out = capsys.readouterr().out
    assert "'c2-list'" in out and "2 stored" in out and "1 rejected" in out
    entries = IntelStore.from_url(f"sqlite:///{db}").entries()
    assert {e.value for e in entries} == {"198.51.100.7", "bad.example"}
    assert all(e.expires_at == datetime(2099, 1, 2, tzinfo=timezone.utc) for e in entries)
