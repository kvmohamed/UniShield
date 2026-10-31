"""Live, receive-only inputs: flow-export decoding, the UDP collector, Zeek follow mode, clock ticks and the API."""

from __future__ import annotations

import json
import socket
import struct
import time
from datetime import datetime, timedelta, timezone

import pytest

from unishield.data.flow_export_samples import encode_ipfix, encode_v5, ipfix_template
from unishield.ingest.base import BaseReader, ClockTick
from unishield.ingest.collector import FlowExportCollector
from unishield.ingest.netflow import (
    DST_PORT, DST_V4, FIRST_SWITCHED, LAST_SWITCHED, OCTETS, PACKETS, PROTOCOL, SRC_PORT, SRC_V4, TCP_FLAGS,
    FlowExportDecoder, FlowExportError,
)
from unishield.ingest.zeek_follow import ZeekFollowReader
from unishield.processing.pipeline import Pipeline
from unishield.schemas.flow import InputSource, NormalisedFlow, ProtocolType

T0 = datetime(2026, 3, 1, 9, 0, tzinfo=timezone.utc)


def _flow(i: int = 0, **kw) -> NormalisedFlow:
    base = dict(timestamp=T0 + timedelta(seconds=i / 10), source_ip="10.0.0.5", destination_ip=f"10.0.1.{i % 250 + 1}",
                source_port=40000 + i, destination_port=22, protocol=ProtocolType.TCP, duration=0.5, byte_count=120,
                packet_count=2, tcp_flags="ACK,SYN", source_type=InputSource.FLOW_EXPORT)
    base.update(kw)
    return NormalisedFlow(**base)


# --- decoder -------------------------------------------------------------------------------------------------------

def test_v5_round_trip():
    flows = [_flow(i) for i in range(30)]
    decoded = FlowExportDecoder().decode(encode_v5(flows, T0 + timedelta(minutes=1)), "192.0.2.1")
    assert len(decoded) == 30
    for sent, got in zip(flows, decoded):
        assert (got.source_ip, got.destination_ip, got.source_port, got.destination_port) == \
            (sent.source_ip, sent.destination_ip, sent.source_port, sent.destination_port)
        assert got.timestamp == sent.timestamp and got.duration == pytest.approx(0.5)
        assert got.byte_count == 120 and got.packet_count == 2 and got.tcp_flags == "ACK,SYN"
        assert got.source_type == InputSource.FLOW_EXPORT and got.orig_bytes is None    # unidirectional


def _v9(sets: bytes, uptime: int, secs: int, source_id: int = 7) -> bytes:
    return struct.pack("!HHIIII", 9, 1, uptime, secs, 0, source_id) + sets


def test_v9_template_then_data_and_data_before_template():
    fields = [(SRC_V4, 4), (DST_V4, 4), (SRC_PORT, 2), (DST_PORT, 2), (PROTOCOL, 1), (TCP_FLAGS, 1), (PACKETS, 4),
              (OCTETS, 4), (FIRST_SWITCHED, 4), (LAST_SWITCHED, 4)]
    tpl = struct.pack("!HH", 300, len(fields)) + b"".join(struct.pack("!HH", ie, n) for ie, n in fields)
    template_set = struct.pack("!HH", 0, 4 + len(tpl)) + tpl
    export = int(T0.timestamp()) + 60
    uptime = 100_000                                                  # export happened at 100 s of uptime
    record = struct.pack("!4s4sHHBBIIII", bytes([10, 0, 0, 9]), bytes([10, 0, 1, 1]), 51000, 443, 17, 0, 3, 900,
                         40_000, 41_000)
    data_set = struct.pack("!HH", 300, 4 + len(record) + 2) + record + b"\x00\x00"     # padded

    decoder = FlowExportDecoder()
    assert decoder.decode(_v9(data_set, uptime, export), "192.0.2.1") == []
    assert decoder.counts["records_without_template"] == 1
    [flow] = decoder.decode(_v9(template_set + data_set, uptime, export), "192.0.2.1")
    assert flow.protocol == ProtocolType.UDP and flow.destination_port == 443 and flow.byte_count == 900
    assert flow.timestamp == datetime.fromtimestamp(export, tz=timezone.utc) - timedelta(seconds=60)
    assert flow.duration == pytest.approx(1.0) and flow.tcp_flags is None
    # templates are per exporter: another exporter's data is not decoded with them
    assert decoder.decode(_v9(data_set, uptime, export), "192.0.2.2") == []


def test_ipfix_biflow_round_trip_and_template_reuse():
    flows = [_flow(i, orig_packets=3, resp_packets=2, orig_bytes=300, resp_bytes=1500, packet_count=5,
                   byte_count=1800) for i in range(5)]
    decoder = FlowExportDecoder()
    decoded = decoder.decode(encode_ipfix(flows, T0 + timedelta(minutes=1), biflow=True), "192.0.2.1")
    assert [(f.orig_bytes, f.resp_bytes, f.orig_packets, f.resp_packets) for f in decoded] == [(300, 1500, 3, 2)] * 5
    assert all(f.byte_count == 1800 and f.packet_count == 5 for f in decoded)
    later = decoder.decode(encode_ipfix(flows[:2], T0, biflow=True, include_template=False), "192.0.2.1")
    assert len(later) == 2 and decoder.templates == 1
    assert len(ipfix_template(biflow=True)) == len(ipfix_template()) + 2


def test_ipfix_variable_length_field_is_skipped():
    # template: source, destination, a variable-length field (interfaceName, IE 82), octets
    tpl = struct.pack("!HH", 400, 4) + struct.pack("!HHHHHHHH", SRC_V4, 4, DST_V4, 4, 82, 0xFFFF, OCTETS, 4)
    record = bytes([10, 0, 0, 1, 10, 0, 0, 2]) + bytes([3]) + b"eth" + struct.pack("!I", 77)
    sets = struct.pack("!HH", 2, 4 + len(tpl)) + tpl + struct.pack("!HH", 400, 4 + len(record)) + record
    message = struct.pack("!HHIII", 10, 16 + len(sets), int(T0.timestamp()), 0, 1) + sets
    [flow] = FlowExportDecoder().decode(message, "192.0.2.1")
    assert flow.byte_count == 77 and flow.protocol == ProtocolType.OTHER and flow.source_port is None


def test_sequence_gaps_reordering_and_restarts_are_counted():
    decoder = FlowExportDecoder()
    batch = [_flow(i) for i in range(10)]
    for seq in (500_000, 500_010, 500_040, 500_030, 500_050):        # 20 records lost; one datagram late
        decoder.decode(encode_v5(batch, T0, sequence=seq), "192.0.2.1")
    assert decoder.counts["lost_records"] == 20 and decoder.counts["reordered_datagrams"] == 1
    decoder.decode(encode_v5(batch, T0, sequence=0), "192.0.2.1")      # far behind: exporter restarted
    decoder.decode(encode_v5(batch, T0, sequence=10), "192.0.2.1")
    assert decoder.counts["sequence_resets"] == 1 and decoder.counts["lost_records"] == 20
    decoder.decode(encode_v5(batch, T0, sequence=0), "192.0.2.2")      # another exporter has its own sequence
    assert decoder.counts["lost_records"] == 20

    ipfix = FlowExportDecoder()
    ipfix.decode(encode_ipfix(batch, T0, sequence=0), "192.0.2.1")
    ipfix.decode(encode_ipfix(batch[:5], T0, sequence=10, include_template=False), "192.0.2.1")
    ipfix.decode(encode_ipfix(batch, T0, sequence=25, include_template=False), "192.0.2.1")
    assert ipfix.counts["lost_records"] == 10


@pytest.mark.parametrize("data", [b"\x00", struct.pack("!H", 7) + b"\x00" * 30,
                                  struct.pack("!HH", 5, 3) + b"\x00" * 40])
def test_malformed_datagrams_raise(data):
    with pytest.raises(FlowExportError):
        FlowExportDecoder().decode(data, "192.0.2.1")


# --- collector -----------------------------------------------------------------------------------------------------

def _drain(collector: FlowExportCollector, until_tick: bool = True, limit: float = 5.0) -> list:
    """Read from the collector until the first clock tick after data (or the time limit)."""
    out: list = []
    deadline = time.monotonic() + limit
    for item in collector.read():
        out.append(item)
        data_tick = isinstance(item, ClockTick) and item.event_time is not None
        if (until_tick and data_tick) or time.monotonic() > deadline:
            collector.stop()
            break
    return out


def test_collector_receives_on_loopback_and_ticks():
    collector = FlowExportCollector("127.0.0.1", 0, tick_interval=0.2)
    host, port = collector.open()
    flows = [_flow(i) for i in range(20)]
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
        sender.sendto(encode_v5(flows, T0 + timedelta(minutes=1)), (host, port))
        sender.sendto(b"\x00\x09garbage", (host, port))
    items = _drain(collector)
    records = [i for i in items if isinstance(i, NormalisedFlow)]
    ticks = [i for i in items if isinstance(i, ClockTick)]
    assert len(records) == 20 and ticks and ticks[-1].event_time >= flows[-1].timestamp
    stats = collector.stats()
    assert stats["datagrams"] == 2 and stats["records"] == 20 and stats["malformed"] == 1
    assert collector.bound_address is None                            # the socket is closed after reading


def test_collector_drops_exporters_outside_the_allow_list():
    collector = FlowExportCollector("127.0.0.1", 0, tick_interval=0.2, allowed_exporters=["192.0.2.0/24"])
    host, port = collector.open()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
        sender.sendto(encode_v5([_flow()], T0), (host, port))
    items = _drain(collector, until_tick=False, limit=0.8)
    assert items and all(isinstance(i, ClockTick) and i.event_time is None for i in items)    # idle heartbeats
    assert not any(isinstance(i, NormalisedFlow) for i in items)
    assert collector.stats()["rejected_exporters"] == 1 and collector.stats()["allowed_exporters"] == ["192.0.2.0/24"]


def test_collector_never_sends_or_connects():
    calls: list[str] = []

    class Recorder:
        def __init__(self, *args):
            self.queue = [encode_v5([_flow()], T0)]

        def __getattr__(self, name):
            calls.append(name)
            raise AssertionError(f"collector called socket.{name}")

        def setsockopt(self, *args):
            calls.append("setsockopt")

        def bind(self, address):
            calls.append("bind")

        def settimeout(self, value):
            calls.append("settimeout")

        def getsockname(self):
            return ("127.0.0.1", 2055)

        def recvfrom(self, size):
            calls.append("recvfrom")
            if self.queue:
                return self.queue.pop(), ("192.0.2.1", 9995)
            raise socket.timeout()

        def close(self):
            calls.append("close")

    collector = FlowExportCollector("127.0.0.1", 2055, tick_interval=0.05, socket_factory=Recorder)
    items = _drain(collector)
    assert sum(isinstance(i, NormalisedFlow) for i in items) == 1
    assert set(calls) == {"setsockopt", "bind", "settimeout", "recvfrom", "close"}


# --- pipeline clock ticks --------------------------------------------------------------------------------------------

class _ListReader(BaseReader):
    packet_level = False

    def __init__(self, items, probe):
        super().__init__(None)
        self.items, self.probe = items, probe

    def validate_source(self) -> bool:
        return True

    def read(self):
        for item in self.items:
            yield item
            if isinstance(item, ClockTick):
                self.probe()


def test_clock_tick_closes_idle_windows_before_the_stream_ends():
    alerts: list = []
    seen_at_tick: list[int] = []
    sweep = [_flow(i, tcp_flags="SYN", packet_count=1, byte_count=60, duration=0.0) for i in range(60)]
    reader = _ListReader([*sweep, ClockTick(T0 + timedelta(minutes=5))], lambda: seen_at_tick.append(len(alerts)))
    Pipeline(alert_callback=alerts.append, allowed_lateness_sec=0).run(reader)
    assert alerts and seen_at_tick == [len(alerts)]                  # raised by the tick, not by end of stream


# --- Zeek follow -----------------------------------------------------------------------------------------------------

TSV_HEADER = ("#separator \\x09\n#set_separator\t,\n#empty_field\t(empty)\n#unset_field\t-\n#path\tconn\n"
              "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tduration\torig_bytes\t"
              "resp_bytes\tconn_state\torig_pkts\tresp_pkts\n"
              "#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tinterval\tcount\tcount\tstring\tcount\tcount\n")


def _tsv_line(uid: str, ts: float, resp_port: int = 443) -> str:
    return f"{ts:.6f}\t{uid}\t10.0.0.5\t50000\t10.0.1.1\t{resp_port}\ttcp\t0.5\t100\t200\tSF\t3\t3\n"


def _poll(reader: ZeekFollowReader, gen, want: int) -> list[NormalisedFlow]:
    out: list[NormalisedFlow] = []
    for item in gen:
        if isinstance(item, NormalisedFlow):
            out.append(item)
        if len(out) >= want or isinstance(item, ClockTick):
            break
    return out


def test_zeek_follow_reads_appended_tsv_lines_and_survives_rotation(tmp_path):
    conn = tmp_path / "conn.log"
    conn.write_text(TSV_HEADER + _tsv_line("Cold", T0.timestamp()), encoding="utf-8")
    reader = ZeekFollowReader(tmp_path, poll_interval=0.01)          # follows from the end: "Cold" is skipped
    gen = reader.read()
    assert _poll(reader, gen, 1) == []
    with open(conn, "a", encoding="utf-8") as f:
        f.write(_tsv_line("C1", T0.timestamp() + 1))
    [first] = _poll(reader, gen, 1)
    assert first.destination_port == 443 and first.orig_bytes == 100   # header parsed while skipping to the end

    with open(conn, "a", encoding="utf-8") as f:                      # written after the last poll ...
        f.write(_tsv_line("C2", T0.timestamp() + 2, 22))
    conn.rename(tmp_path / "conn.09-00.log")                         # ... then Zeek rotates
    conn.write_text(TSV_HEADER + _tsv_line("C3", T0.timestamp() + 3, 53), encoding="utf-8")
    got = _poll(reader, gen, 2)
    assert [f.destination_port for f in got] == [22, 53]
    reader.stop()
    stats = reader.stats()
    assert stats["rotations"] == 1 and stats["rotations_without_remainder"] == 0 and stats["errors"] == 0


def test_zeek_follow_joins_dns_and_ssl_by_uid(tmp_path):
    (tmp_path / "conn.log").write_text("", encoding="utf-8")
    (tmp_path / "dns.log").write_text("", encoding="utf-8")
    reader = ZeekFollowReader(tmp_path, poll_interval=0.01)
    gen = reader.read()
    assert _poll(reader, gen, 1) == []
    with open(tmp_path / "dns.log", "a", encoding="utf-8") as f:
        f.write(json.dumps({"ts": T0.timestamp(), "uid": "D1", "query": "example.org", "qtype_name": "A"}) + "\n")
    with open(tmp_path / "conn.log", "a", encoding="utf-8") as f:
        f.write(json.dumps({"ts": T0.timestamp(), "uid": "D1", "id.orig_h": "10.0.0.5", "id.orig_p": 53000,
                            "id.resp_h": "10.0.0.53", "id.resp_p": 53, "proto": "udp", "duration": 0.01,
                            "orig_bytes": 40, "resp_bytes": 80, "orig_pkts": 1, "resp_pkts": 1}) + "\n")
        f.write("{not json\n")
    [flow] = _poll(reader, gen, 1)
    assert flow.dns_query == "example.org" and flow.protocol == ProtocolType.UDP
    _poll(reader, gen, 1)
    reader.stop()
    assert reader.stats()["errors"] == 1 and reader.stats()["enrichment_cached"] == 1


def test_zeek_follow_reads_a_log_created_after_following_began_from_its_start(tmp_path):
    reader = ZeekFollowReader(tmp_path, poll_interval=0.01)
    gen = reader.read()
    assert _poll(reader, gen, 1) == []                                # no conn.log yet
    (tmp_path / "conn.log").write_text(TSV_HEADER + _tsv_line("C0", T0.timestamp()), encoding="utf-8")
    assert len(_poll(reader, gen, 1)) == 1
    reader.stop()


def test_zeek_follow_from_start_reads_existing_lines(tmp_path):
    (tmp_path / "conn.log").write_text(TSV_HEADER + _tsv_line("C0", T0.timestamp()), encoding="utf-8")
    reader = ZeekFollowReader(tmp_path, from_start=True, poll_interval=0.01)
    assert len(_poll(reader, reader.read(), 1)) == 1


# --- API -----------------------------------------------------------------------------------------------------------

def _free_udp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_idle(client, limit: float = 10.0) -> None:
    deadline = time.monotonic() + limit
    while client.get("/live/status").json().get("running") and time.monotonic() < deadline:
        time.sleep(0.05)


def test_live_netflow_api_start_status_conflict_and_stop(api_client, client_as, monkeypatch):
    from unishield.config import reset_config

    client, _ = api_client
    port = _free_udp_port()
    monkeypatch.setenv("UNISHIELD_NETFLOW_PORT", str(port))
    reset_config()
    assert client.get("/live/status").json() == {"live": False}
    assert client_as("analyst").post("/live/netflow/start").status_code == 403
    assert client_as(None).get("/live/status").status_code == 401

    started = client.post("/live/netflow/start")
    assert started.status_code == 200, started.text
    assert started.json()["listening"] == f"127.0.0.1:{port}"
    assert client.post("/live/netflow/start").status_code == 409           # one run at a time
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
        sender.sendto(encode_v5([_flow(i) for i in range(5)], T0), ("127.0.0.1", port))
    deadline = time.monotonic() + 5
    while client.get("/live/status").json()["records"] < 5 and time.monotonic() < deadline:
        time.sleep(0.05)
    status = client_as("viewer").get("/live/status").json()
    assert status["live"] and status["running"] and status["records"] == 5 and status["kind"] == "FlowExportCollector"
    assert client.post("/replay/stop").json()["status"] == "stopping"
    _wait_idle(client)
    assert client.get("/live/status").json()["running"] is False
    actions = [e["action"] for e in client.get("/audit").json()]
    assert "live.start" in actions


def test_live_zeek_api_checks_the_directory(api_client, tmp_path):
    client, data_dir = api_client
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    assert client.post("/live/zeek/start", params={"directory": str(outside)}).status_code in (400, 403)
    (data_dir / "conn.log").write_text("", encoding="utf-8")
    assert client.post("/live/zeek/start", params={"directory": str(data_dir / "conn.log")}).status_code == 400
    zeek = data_dir / "zeek"
    zeek.mkdir()
    (zeek / "conn.log").write_text(TSV_HEADER, encoding="utf-8")
    # from the start: the follower's first poll may come after the line below is written
    started = client.post("/live/zeek/start", params={"directory": str(zeek), "from_start": True})
    assert started.status_code == 200, started.text
    with open(zeek / "conn.log", "a", encoding="utf-8") as f:
        f.write(_tsv_line("C1", T0.timestamp()))
    deadline = time.monotonic() + 5
    while client.get("/live/status").json().get("records", 0) < 1 and time.monotonic() < deadline:
        time.sleep(0.05)
    assert client.get("/live/status").json()["records"] == 1
    client.post("/replay/stop")
    _wait_idle(client)
