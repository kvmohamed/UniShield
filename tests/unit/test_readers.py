"""Unit tests for the PCAP, Zeek and flow readers (audit D9, D13, D14, D15)."""

from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from unishield.data.sample_files import BASE_TIME, CLIENT, SCANNER, WEB_SERVER
from unishield.ingest.flow_reader import FlowReader
from unishield.ingest.pcap_reader import PcapReader
from unishield.ingest.zeek_reader import ZeekReader
from unishield.schemas.flow import FlowDirection, InputSource, ProtocolType


# --------------------------------------------------------------------- PCAP

class TestPcapReader:
    def test_one_record_per_ip_packet(self, sample_capture):
        reader = PcapReader(sample_capture.path)
        records = list(reader.read())
        assert len(records) == sample_capture.ip_packets == 26
        assert reader.skipped == sample_capture.non_ip_frames == 1
        assert reader.errors == 0
        assert all(r.packet_count == 1 and r.source_type == InputSource.PCAP for r in records)
        assert all(r.timestamp.tzinfo == timezone.utc for r in records)
        assert records[0].timestamp == BASE_TIME

    def test_pcapng_reads_the_same(self, sample_capture, sample_capture_ng):
        a = [(r.source_ip, r.destination_ip, r.byte_count) for r in PcapReader(sample_capture.path).read()]
        b = [(r.source_ip, r.destination_ip, r.byte_count) for r in PcapReader(sample_capture_ng.path).read()]
        assert a == b

    def test_tls_versions_come_from_the_handshake(self, sample_capture):
        tls = [(r.source_ip, r.tls_version, r.tls_cipher) for r in PcapReader(sample_capture.path).read()
               if r.tls_version]
        assert tls == [
            (CLIENT, "TLSv1.3", None),                                  # ClientHello offer
            (WEB_SERVER, "TLSv1.3", "TLS_AES_128_GCM_SHA256"),          # ServerHello selection
        ]

    def test_dns_question_and_response_code(self, sample_capture):
        dns = [(r.dns_query, r.dns_record_type, r.dns_rcode) for r in PcapReader(sample_capture.path).read()
               if r.dns_query]
        assert ("q7x9z2kd.example", "A", "NXDOMAIN") in dns
        assert ("www.example.com", "A", "NOERROR") in dns
        assert ("www.example.com", "A", None) in dns                   # query has no rcode

    def test_ipv6_and_icmp_records(self, sample_capture):
        records = list(PcapReader(sample_capture.path).read())
        assert any(r.source_ip == "fd00::10" and r.protocol == ProtocolType.UDP for r in records)
        icmp = [r for r in records if r.protocol == ProtocolType.ICMP]
        assert len(icmp) == 2 and all(r.source_port is None for r in icmp)

    def test_reader_is_packet_level(self, sample_capture):
        assert PcapReader(sample_capture.path).packet_level is True

    def test_missing_file_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            list(PcapReader(tmp_path / "missing.pcap").read())


# --------------------------------------------------------------------- Zeek

class TestZeekReader:
    def test_directory_joins_dns_and_ssl_on_uid(self, sample_zeek_dir):
        records = {r.flow_id: r for r in ZeekReader(sample_zeek_dir).read()}
        assert set(records) == {"CTLS0001", "CDNS0001", "CSCN0001", "CSCN0004"}
        tls = records["CTLS0001"]
        assert (tls.tls_version, tls.tls_cipher) == ("TLSv1.3", "TLS_AES_128_GCM_SHA256")
        assert (tls.orig_bytes, tls.resp_bytes, tls.orig_packets, tls.resp_packets) == (820, 1560, 6, 4)
        assert tls.byte_count == 2380 and tls.packet_count == 10
        assert tls.tcp_flags == "ACK,FIN,SYN"          # uppercase history letters only
        assert tls.conn_state == "SF"
        dns = records["CDNS0001"]
        assert (dns.dns_query, dns.dns_record_type, dns.dns_rcode) == ("q7x9z2kd.example", "A", "NXDOMAIN")
        assert dns.tcp_flags is None
        assert records["CSCN0004"].duration is None      # not fabricated
        assert all(r.source_type == InputSource.ZEEK_JSON for r in records.values())

    def test_tsv_format(self, sample_zeek_tsv):
        reader = ZeekReader(sample_zeek_tsv)
        records = list(reader.read())
        assert reader.errors == 0
        assert [r.flow_id for r in records] == ["CTLS0001", "CDNS0001", "CSCN0001", "CSCN0004"]
        assert all(r.source_type == InputSource.ZEEK_TSV for r in records)
        scan = records[2]
        assert (scan.source_ip, scan.destination_port, scan.conn_state) == (SCANNER, 21, "REJ")
        assert scan.duration is None and records[0].duration == pytest.approx(0.24)
        assert records[0].timestamp == BASE_TIME

    def test_single_dns_log_has_only_its_fields(self, sample_zeek_dir):
        (record,) = list(ZeekReader(sample_zeek_dir / "dns.log").read())
        assert record.dns_rcode == "NXDOMAIN"
        assert record.orig_bytes is None and record.resp_packets is None
        assert record.packet_count == 1 and record.byte_count == 0

    def test_record_without_ip_is_an_error_not_zero_address(self, tmp_path):
        path = tmp_path / "conn.log"
        path.write_text(json.dumps({"ts": 1.0, "uid": "C1", "id.resp_h": "10.0.0.1", "proto": "tcp"}) + "\n"
                        + "{not json\n", encoding="utf-8")
        reader = ZeekReader(path)
        assert list(reader.read()) == []
        assert reader.errors == 2

    def test_port_zero_is_kept(self, tmp_path):
        path = tmp_path / "conn.log"
        path.write_text(json.dumps({"ts": 1.0, "id.orig_h": "10.0.0.1", "id.orig_p": 0,
                                    "id.resp_h": "10.0.0.2", "id.resp_p": 0, "proto": "udp"}), encoding="utf-8")
        (record,) = list(ZeekReader(path).read())
        assert (record.source_port, record.destination_port) == (0, 0)

    @pytest.mark.parametrize("local_orig,local_resp,expected", [
        (True, False, FlowDirection.OUTBOUND),
        (False, True, FlowDirection.INBOUND),
        (True, True, FlowDirection.INTERNAL),
    ])
    def test_local_orig_resp_give_direction(self, tmp_path, local_orig, local_resp, expected):
        path = tmp_path / "conn.log"
        path.write_text(json.dumps({"ts": 1.0, "id.orig_h": "10.0.0.1", "id.resp_h": "8.8.8.8",
                                    "local_orig": local_orig, "local_resp": local_resp}), encoding="utf-8")
        assert next(ZeekReader(path).read()).direction == expected

    def test_json_array_format(self, tmp_path):
        path = tmp_path / "conn.json"
        path.write_text(json.dumps([{"ts": 1.0, "id.orig_h": "10.0.0.1", "id.resp_h": "10.0.0.2"},
                                    {"ts": 2.0, "id.orig_h": "10.0.0.1", "id.resp_h": "10.0.0.3"}]),
                        encoding="utf-8")
        assert len(list(ZeekReader(path).read())) == 2

    def test_directory_without_conn_log_is_invalid(self, tmp_path):
        assert ZeekReader(tmp_path).validate_source() is False


# --------------------------------------------------------------------- Flow

class TestFlowReader:
    @pytest.mark.parametrize("fixture", ["sample_flow_csv", "sample_flow_jsonl"])
    def test_fields_are_kept(self, request, fixture):
        reader = FlowReader(request.getfixturevalue(fixture))
        web, scan, dns = list(reader.read())
        assert reader.errors == 0
        assert web.direction == FlowDirection.OUTBOUND and scan.direction == FlowDirection.INBOUND
        assert (web.orig_bytes, web.resp_bytes, web.byte_count, web.packet_count) == (820, 1560, 2380, 10)
        assert web.label == "BENIGN" and scan.label == "PortScan"
        assert scan.protocol == ProtocolType.TCP                    # numeric "6"
        assert (dns.byte_count, dns.packet_count, dns.orig_bytes) == (68, 2, None)
        assert (dns.dns_query, dns.dns_rcode) == ("q7x9z2kd.example", "NXDOMAIN")
        assert dns.direction == FlowDirection.UNKNOWN

    def test_cicids2017_profile_detected(self, sample_cicids_csv):
        reader = FlowReader(sample_cicids_csv)
        records = list(reader.read())
        assert reader.profile is not None and reader.profile.name == "cicids2017"
        assert len(records) == 2 and reader.errors == 1           # row with an invalid IP
        benign, ddos = records
        assert benign.timestamp == datetime(2017, 7, 7, 3, 30, tzinfo=timezone.utc)
        assert benign.duration == pytest.approx(5.0)               # 5,000,000 µs
        assert (benign.orig_packets, benign.resp_packets, benign.packet_count) == (10, 8, 18)
        assert (benign.orig_bytes, benign.resp_bytes, benign.byte_count) == (1200, 6400, 7600)
        assert benign.flow_id.startswith("192.168.10.5-")
        assert (benign.label, ddos.label) == ("BENIGN", "DDoS")
        assert ddos.timestamp == datetime(2017, 7, 7, 3, 31, 15, tzinfo=timezone.utc)

    def test_explicit_profile_none_disables_detection(self, sample_cicids_csv):
        reader = FlowReader(sample_cicids_csv, profile="none")
        records = list(reader.read())
        assert reader.profile is None
        assert records[0].duration == pytest.approx(5_000_000)    # treated as seconds

    def test_unknown_profile_rejected(self, sample_flow_csv):
        with pytest.raises(ValueError, match="Unknown dataset profile"):
            FlowReader(sample_flow_csv, profile="nope")

    def test_missing_ip_is_an_error_not_zero_address(self, tmp_path):
        path = tmp_path / "f.csv"
        path.write_text("timestamp,src_ip,dst_ip\n2026-01-01T00:00:00Z,10.0.0.1,\n", encoding="utf-8")
        reader = FlowReader(path)
        assert list(reader.read()) == [] and reader.errors == 1

    def test_negative_duration_becomes_none(self, tmp_path):
        path = tmp_path / "f.csv"
        path.write_text("timestamp,src_ip,dst_ip,duration\n2026-01-01T00:00:00Z,10.0.0.1,10.0.0.2,-1\n",
                        encoding="utf-8")
        assert next(FlowReader(path).read()).duration is None

    def test_extension_independent_json_detection(self, tmp_path, sample_flow_jsonl):
        path = tmp_path / "flows.data"
        path.write_text(sample_flow_jsonl.read_text(encoding="utf-8"), encoding="utf-8")
        assert len(list(FlowReader(path).read())) == 3
