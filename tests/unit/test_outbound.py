"""Outbound delivery to the analyst side: destination policy, syslog, email/webhook, service."""

from __future__ import annotations

import json
import re
import socket
import ssl
from datetime import datetime, timedelta, timezone
from email import message_from_bytes
from pathlib import Path

import pytest
from pydantic import ValidationError

from unishield.config import UnishieldConfig, load_config, reset_config
from unishield.evaluation.receivers import HttpReceiver, SmtpReceiver, TcpSyslogReceiver, UdpSyslogReceiver
from unishield.export import transport
from unishield.export.notify import Throttle, notification_view
from unishield.export.policy import DestinationPolicy, DestinationRefused
from unishield.export.service import OutputService
from unishield.export.syslog import SyslogForwarder, format_message, octet_frame
from unishield.schemas.alert import Alert, Severity, ThreatClass

HOME = ["10.20.0.0/16", "fd20::/48"]
T0 = datetime(2026, 10, 22, 10, 0, tzinfo=timezone.utc)
TLS_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "tls"
RFC5424 = re.compile(rb"^<(\d{1,3})>1 (\S+) (\S+) (\S+) (\S+) (\S+) (\[.*?[^\\]\]|-) (.*)$", re.S)


def alert(cls=ThreatClass.PORT_SCAN, severity=Severity.HIGH, src="198.51.100.66", dst="10.20.1.5", sec=0,
          evidence=None):
    end = T0 + timedelta(seconds=sec + 10)
    return Alert(window_start=end - timedelta(seconds=10), window_end=end, timestamp=end, source_ip=src,
                 destination_ip=dst, threat_class=cls, severity=severity, confidence=0.9,
                 detector_name="scan_detector", mitre_techniques=["T1046"],
                 evidence=evidence or {"summary": "vertical scan", "secret_detail": "10.20.1.99"})


def config(**outbound) -> UnishieldConfig:
    outbound.setdefault("allowed_destinations", ["127.0.0.1"])
    return UnishieldConfig(network={"home_networks": HOME}, outbound=outbound)


def tls_wrap():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(TLS_DIR / "test-server.crt", TLS_DIR / "test-server.key")
    return lambda sock: context.wrap_socket(sock, server_side=True)


def syslog_cfg(port, protocol="udp", **extra):
    dest = {"name": "siem", "host": "127.0.0.1", "port": port, "protocol": protocol, **extra}
    return config(syslog={"enabled": True, "destinations": [dest]})


def forwarder(cfg: UnishieldConfig) -> SyslogForwarder:
    return SyslogForwarder(cfg.outbound.syslog.destinations[0], cfg.outbound.syslog,
                           DestinationPolicy.from_config(cfg), timeout=3)


class TestPolicy:
    def policy(self, allowed=("192.0.2.0/24", "siem.analyst.example", "127.0.0.1")):
        return DestinationPolicy(allowed, HOME)

    def test_home_network_destinations_are_refused_first(self):
        with pytest.raises(DestinationRefused, match="inside the monitored network"):
            self.policy().check_host("10.20.4.4")
        with pytest.raises(DestinationRefused, match="inside the monitored network"):
            self.policy().check_host("::ffff:10.20.4.4")                  # IPv4-mapped form
        with pytest.raises(DestinationRefused, match="inside the monitored network"):
            self.policy().check_host("fd20::9")

    def test_only_allow_listed_addresses_and_listed_names(self):
        p = self.policy()
        p.check_host("192.0.2.10")
        p.check_host("SIEM.analyst.example.")
        with pytest.raises(DestinationRefused, match="not in outbound.allowed_destinations"):
            p.check_host("198.51.100.1")
        with pytest.raises(DestinationRefused, match="listed by name"):
            p.check_host("other.analyst.example")
        with pytest.raises(DestinationRefused, match="unicast"):
            DestinationPolicy(["192.0.2.0/24"], HOME).check_host("0.0.0.0")

    def test_names_resolving_into_the_monitored_network_are_refused(self):
        p = self.policy()
        p.check_address("siem.analyst.example", "198.18.5.5")
        assert p.permits_address("198.18.5.5")                           # remembered for the tripwire
        with pytest.raises(DestinationRefused, match="inside the monitored network"):
            p.check_address("siem.analyst.example", "10.20.0.7")
        assert not p.permits_address("10.20.0.7") and not p.permits_address("203.0.113.1")
        assert p.permits_name("siem.analyst.example") and not p.permits_name("example.org")

    def test_allow_list_must_not_overlap_the_monitored_network(self):
        with pytest.raises(ValueError, match="overlaps the monitored network"):
            DestinationPolicy(["10.0.0.0/8"], HOME)
        with pytest.raises(ValueError, match="not an address, network or host name"):
            DestinationPolicy(["bad host!"], HOME)
        with pytest.raises(DestinationRefused, match="home_networks"):
            DestinationPolicy(["192.0.2.1"], []).check_host("192.0.2.1")


class TestConfigLoad:
    def test_outputs_are_off_by_default(self):
        cfg = UnishieldConfig()
        assert not (cfg.outbound.syslog.enabled or cfg.outbound.email.enabled or cfg.outbound.webhook.enabled)
        assert not OutputService(cfg).active

    def test_home_network_destination_is_refused_at_load(self):
        with pytest.raises(ValidationError, match="inside the monitored network"):
            config(allowed_destinations=["192.0.2.0/24"],
                   syslog={"enabled": True, "destinations": [{"name": "siem", "host": "10.20.1.1"}]})

    def test_unlisted_destinations_are_refused_at_load(self):
        with pytest.raises(ValidationError, match="not in outbound.allowed_destinations"):
            config(syslog={"enabled": True, "destinations": [{"name": "siem", "host": "192.0.2.9"}]})
        with pytest.raises(ValidationError, match="listed by name"):
            config(webhook={"enabled": True, "destinations": [{"name": "soar", "url": "https://soar.example/h"}]})
        with pytest.raises(ValidationError, match="credentials"):
            config(webhook={"enabled": True, "destinations": [{"name": "soar", "url": "https://u:p@127.0.0.1/h"}]})

    def test_default_home_networks_cover_private_analyst_ranges(self):
        """With the default home networks (all private ranges) a private analyst host is refused."""
        with pytest.raises(ValidationError, match="overlaps the monitored network"):
            UnishieldConfig(outbound={"allowed_destinations": ["192.168.50.10"],
                                      "syslog": {"enabled": True,
                                                 "destinations": [{"name": "s", "host": "192.168.50.10"}]}})

    def test_yaml_with_a_monitored_destination_does_not_load(self, tmp_path):
        path = tmp_path / "config.yaml"
        path.write_text(
            "network:\n  home_networks: ['10.20.0.0/16']\n"
            "outbound:\n  allowed_destinations: ['10.20.0.0/24']\n"
            "  email: {enabled: true, smtp_host: 10.20.0.25, sender: a@b.example, recipients: [c@d.example]}\n",
            encoding="utf-8")
        reset_config()
        try:
            with pytest.raises(ValidationError, match="overlaps the monitored network"):
                load_config(path)
        finally:
            reset_config()


class TestSendTimeChecks:
    def test_listed_name_resolving_into_monitored_network_never_connects(self, monkeypatch):
        policy = DestinationPolicy(["siem.analyst.example"], HOME)
        monkeypatch.setattr(socket, "getaddrinfo",
                            lambda *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.20.3.3", 514))])

        def no_connection(*args, **kwargs):
            raise AssertionError("connection attempted")

        monkeypatch.setattr(socket, "create_connection", no_connection)
        with pytest.raises(DestinationRefused, match="inside the monitored network"):
            transport.deliver_stream(policy, "siem.analyst.example", 514, [b"x"])
        with pytest.raises(DestinationRefused, match="inside the monitored network"):
            transport.deliver_http_post(policy, "http://siem.analyst.example/hook", b"{}", {})

    def test_unlisted_names_are_not_even_resolved(self, monkeypatch):
        def no_lookup(*args, **kwargs):
            raise AssertionError("DNS lookup attempted")

        monkeypatch.setattr(socket, "getaddrinfo", no_lookup)
        with pytest.raises(DestinationRefused):
            transport.resolve(DestinationPolicy(["192.0.2.1"], HOME), "intranet.example", 514)

    def test_forwarder_records_a_refusal_and_drops(self, monkeypatch):
        cfg = config(allowed_destinations=["siem.analyst.example"],
                     syslog={"enabled": True, "destinations": [{"name": "siem", "host": "siem.analyst.example"}]})
        monkeypatch.setattr(socket, "getaddrinfo",
                            lambda *a, **k: [(socket.AF_INET, socket.SOCK_DGRAM, 17, "", ("10.20.9.9", 514))])
        fwd = forwarder(cfg)
        assert fwd.forward([alert()], []) == 0
        assert fwd.dropped == 1 and "monitored network" in fwd.last_error


class TestSyslogFormat:
    def test_rfc5424_header_structured_data_and_escaping(self):
        msg = format_message(severity=Severity.HIGH, facility=20, timestamp=T0, hostname="sensor 1",
                             app_name="unishield", procid=42, msgid="PORT_SCAN", sd_id="unishield@32473",
                             params={"alertId": "US-1", "note": 'a"b]c\\d', "empty": None}, msg="CEF:0|x")
        m = RFC5424.match(msg)
        assert m and int(m.group(1)) == 20 * 8 + 3                       # local4.err
        assert m.group(2) == b"2026-10-22T10:00:00.000Z" and m.group(3) == b"sensor1"
        assert m.group(7) == b'[unishield@32473 alertId="US-1" note="a\\"b\\]c\\\\d"]'
        assert m.group(8) == b"CEF:0|x"

    def test_non_ascii_message_gets_a_bom_and_truncation_keeps_utf8_valid(self):
        msg = format_message(severity=Severity.LOW, facility=16, timestamp=T0, hostname="h", app_name="a",
                             procid=1, msgid="M", sd_id="x@1", params={}, msg="é" * 100, max_bytes=80)
        assert len(msg) <= 80 and b"\xef\xbb\xbf" in msg
        msg.decode("utf-8")
        assert octet_frame(b"abc") == b"3 abc"

    def test_alert_message_cef_json_and_redaction(self):
        fwd = forwarder(syslog_cfg(514))
        text = fwd.alert_message(alert()).decode()
        assert text.startswith("<163>1 ") and " PORT_SCAN [unishield@32473 alertId=" in text
        assert 'src="198.51.100.66"' in text and "CEF:0|UniShield|UniShield|" in text
        redacted = forwarder(syslog_cfg(514, redact_ips=True, message_format="json")).alert_message(alert())
        body = json.loads(redacted.split(b"] ", 1)[1])
        assert b"198.51.100.66" not in redacted and b"10.20.1.99" not in redacted
        assert body["record_type"] == "alert" and body["source_ip"] == "redacted"


class TestSyslogDelivery:
    def test_udp(self):
        with UdpSyslogReceiver() as rx:
            fwd = forwarder(syslog_cfg(rx.port))
            assert fwd.forward([alert(), alert(sec=10)], []) == 2
            _wait(lambda: len(rx.messages) == 2)
        assert all(RFC5424.match(m) for m in rx.messages) and fwd.sent == 2

    def test_tcp_octet_counting_severity_floor_and_incidents(self):
        incident = {"incident_id": "INC-1", "severity": "CRITICAL", "alert_count": 2, "threat_classes": ["PORT_SCAN"],
                    "entity": "198.51.100.66", "source_ip": "198.51.100.66", "first_seen": T0.isoformat(),
                    "last_seen": T0.isoformat(), "alert_ids": ["US-1", "US-2"], "mitre_techniques": ["T1046"]}
        with TcpSyslogReceiver() as rx:
            fwd = forwarder(syslog_cfg(rx.port, "tcp", min_severity="MEDIUM"))
            fwd.forward([alert(), alert(severity=Severity.LOW)], [incident])
            _wait(lambda: len(rx.messages) == 2)
        assert b" PORT_SCAN " in rx.messages[0] and b" INCIDENT " in rx.messages[1]
        assert rx.connections == 1

    def test_tls_with_pinned_ca_and_retry_after_failure(self):
        with TcpSyslogReceiver(wrap=tls_wrap()) as rx:
            untrusted = forwarder(syslog_cfg(rx.port, "tls"))                 # system trust store only
            assert untrusted.forward([alert()], []) == 0
            assert "TLS handshake" in untrusted.last_error and untrusted.status()["pending_retry"] == 1
            trusted = forwarder(syslog_cfg(rx.port, "tls", tls={"ca_file": str(TLS_DIR / "test-server.crt")}))
            assert trusted.forward([alert()], []) == 1
            untrusted.tls = trusted.tls                                       # fix the trust, retry
            assert untrusted.forward([alert(sec=20)], []) == 2
            _wait(lambda: len(rx.messages) == 3)


class TestNotifications:
    def test_view_has_only_configured_fields_and_redacts(self):
        a = alert(evidence={"summary": "vertical scan", "intel_matches": [{"source": "feodo"}], "x": "10.20.1.99"})
        view = notification_view(a, ("alert_id", "severity", "source_ip", "summary", "intel_sources"), True)
        assert view == {"alert_id": a.alert_id, "severity": "HIGH", "source_ip": "redacted",
                        "summary": "vertical scan", "intel_sources": ["feodo"]}

    def test_throttle_first_alert_immediate_burst_digested_hourly_cap(self):
        now = [0.0]
        t = Throttle(min_interval_sec=60, max_per_hour=3, digest_max_alerts=2, clock=lambda: now[0])
        t.offer({"severity": "HIGH"})
        assert t.due() and t.take()[1] == 1
        for s in ("MEDIUM", "CRITICAL", "HIGH"):
            t.offer({"severity": s})
        assert not t.due()
        now[0] = 61
        views, total, counts, _ = t.take() if t.due() else (None, 0, {}, {})
        assert total == 3 and [v["severity"] for v in views] == ["HIGH", "CRITICAL"]   # most severe kept
        assert counts == {"MEDIUM": 1, "CRITICAL": 1, "HIGH": 1}
        now[0] = 130
        t.offer({"severity": "HIGH"})
        assert t.due() and t.take()
        now[0] = 200
        t.offer({"severity": "HIGH"})
        assert not t.due()                                                    # 3 messages this hour
        now[0] = 3601
        assert t.due()

    def test_email_through_relay_with_login_from_environment(self, monkeypatch):
        monkeypatch.setenv("UNISHIELD_SMTP_PASSWORD", "relay-pass")
        with SmtpReceiver() as rx:
            cfg = config(email={"enabled": True, "smtp_host": "127.0.0.1", "smtp_port": rx.port, "security": "none",
                                "username": "unishield", "sender": "unishield@analyst.example",
                                "recipients": ["soc@analyst.example"], "redact_ips": True})
            service = OutputService(cfg)
            service.process([alert(), alert(sec=10, severity=Severity.LOW)])
            _wait(lambda: len(rx.messages) == 1)
        msg = message_from_bytes(rx.messages[0]["data"])
        assert rx.logins == [("unishield", "relay-pass")] and rx.messages[0]["rcpt"] == ["soc@analyst.example"]
        assert msg["Subject"] == "[UniShield] HIGH PORT_SCAN"
        body = msg.get_payload(decode=True).decode("utf-8")
        assert "redacted" in body and "198.51.100.66" not in body and "10.20.1.99" not in body
        assert "never connects to" in body
        assert service.channels[0].status()["messages_sent"] == 1

    def test_smtps_with_pinned_ca(self):
        with SmtpReceiver(wrap=tls_wrap()) as rx:
            cfg = config(email={"enabled": True, "smtp_host": "127.0.0.1", "smtp_port": rx.port, "security": "ssl",
                                "sender": "u@analyst.example", "recipients": ["soc@analyst.example"],
                                "tls": {"ca_file": str(TLS_DIR / "test-server.crt")}})
            OutputService(cfg).process([alert()])
            _wait(lambda: len(rx.messages) == 1)

    def test_webhook_json_headers_from_env_failure_and_retry(self, monkeypatch):
        monkeypatch.setenv("UNISHIELD_WEBHOOK_TOKEN", "Bearer t0ken")
        now = [0.0]
        with HttpReceiver(status=500) as rx:
            url = f"http://127.0.0.1:{rx.port}/hooks/secret-path-token"
            cfg = config(webhook={"enabled": True, "destinations": [{
                "name": "soar", "url": url, "min_interval_sec": 10,
                "headers_from_env": {"Authorization": "UNISHIELD_WEBHOOK_TOKEN"}}]})
            service = OutputService(cfg, clock=lambda: now[0])
            service.process([alert()])
            channel = service.channels[0]
            assert channel.failures == 1 and "HTTP 500" in channel.last_error and channel.throttle.pending_total == 1
            rx.status = 204
            service.process([alert(sec=10)])                    # rate limited: the failure counted as an attempt
            assert channel.messages_sent == 0
            now[0] = 11
            service.process([])
            assert channel.messages_sent == 1 and channel.digests_sent == 1
        payload = json.loads(rx.requests[-1]["body"])
        assert payload["kind"] == "digest" and payload["total_alerts"] == 2
        assert rx.requests[-1]["headers"]["Authorization"] == "Bearer t0ken"
        assert "evidence" not in payload["alerts"][0]
        status = json.dumps(service.status())
        assert "t0ken" not in status and "secret-path-token" not in status


class TestService:
    def test_worker_fans_out_to_files_syslog_and_webhook(self, tmp_path):
        with UdpSyslogReceiver() as syslog_rx, HttpReceiver() as hook_rx:
            cfg = UnishieldConfig(
                network={"home_networks": HOME},
                export={"continuous": True, "directory": str(tmp_path / "exports")},
                outbound={"allowed_destinations": ["127.0.0.1"],
                          "syslog": {"enabled": True, "destinations": [
                              {"name": "siem", "host": "127.0.0.1", "port": syslog_rx.port}]},
                          "webhook": {"enabled": True, "destinations": [
                              {"name": "soar", "url": f"http://127.0.0.1:{hook_rx.port}/h"}]}})
            service = OutputService(cfg)
            service.start()
            try:
                for i in range(3):
                    service.submit(alert(sec=10 * i))
                assert service.drain(10)
                _wait(lambda: len(syslog_rx.messages) >= 4 and hook_rx.requests)
            finally:
                service.stop()
        assert len((tmp_path / "exports" / "alerts.jsonl").read_text(encoding="utf-8").splitlines()) == 3
        assert (tmp_path / "exports" / "unishield.stix.json").exists()
        assert any(b" INCIDENT " in m for m in syslog_rx.messages)              # 3 scans → one incident
        status = service.status()
        assert status["queue"]["processed"] == 3 and status["files"]["alerts_written"] == 3
        assert status["syslog"]["destinations"][0]["sent"] >= 4

    def test_full_queue_drops_instead_of_blocking(self, tmp_path):
        cfg = UnishieldConfig(export={"continuous": True, "directory": str(tmp_path)}, outbound={"queue_size": 10})
        service = OutputService(cfg)                                            # worker not started
        for i in range(15):
            service.submit(alert(sec=i))
        assert service.dropped == 5 and service.status()["queue"]["size"] == 10


def _wait(condition, timeout=5.0):
    import time

    deadline = time.monotonic() + timeout
    while not condition():
        if time.monotonic() > deadline:
            raise AssertionError("condition not met in time")
        time.sleep(0.02)
