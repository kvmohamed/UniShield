"""Unit tests for the packet → bidirectional flow sessionizer."""

from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone

from unishield.processing.sessionizer import Sessionizer
from unishield.schemas.flow import NormalisedFlow, ProtocolType

T0 = datetime(2026, 1, 1, tzinfo=timezone.utc)
CLIENT, SERVER, OTHER = "10.0.0.1", "10.0.0.2", "10.0.0.3"


def pkt(t, src, sport, dst, dport, flags=None, proto=ProtocolType.TCP, size=60, **kw):
    return NormalisedFlow(
        timestamp=T0 + timedelta(seconds=t), source_ip=src, destination_ip=dst,
        source_port=sport, destination_port=dport, protocol=proto,
        packet_count=1, byte_count=size, duration=0.0, tcp_flags=flags, **kw,
    )


def handshake_and_close(t0=0.0, sport=50000):
    c, s = (CLIENT, sport, SERVER, 80), (SERVER, 80, CLIENT, sport)
    return [
        pkt(t0 + 0.00, *c, "SYN", size=60),
        pkt(t0 + 0.01, *s, "SYN,ACK", size=60),
        pkt(t0 + 0.02, *c, "ACK", size=52),
        pkt(t0 + 0.03, *c, "PSH,ACK", size=500),
        pkt(t0 + 0.04, *s, "PSH,ACK", size=1500),
        pkt(t0 + 0.05, *c, "FIN,ACK", size=52),
        pkt(t0 + 0.06, *s, "FIN,ACK", size=52),
        pkt(t0 + 0.07, *c, "ACK", size=52),      # trailing ACK, absorbed by closing grace
    ]


def run(packets, **kw):
    s = Sessionizer(**kw)
    return list(s.process(packets)), s


def test_handshake_and_close_is_one_sf_flow():
    flows, s = run(handshake_and_close())
    assert len(flows) == 1
    f = flows[0]
    assert (f.source_ip, f.source_port, f.destination_ip, f.destination_port) == (CLIENT, 50000, SERVER, 80)
    assert (f.orig_packets, f.resp_packets) == (5, 3)
    assert (f.orig_bytes, f.resp_bytes) == (716, 1612)
    assert f.packet_count == 8 and f.byte_count == 2328
    assert f.conn_state == "SF"
    assert f.tcp_flags == "ACK,FIN,PSH,SYN"      # originator's flags only
    assert abs(f.duration - 0.07) < 1e-9
    assert f.flow_id is not None
    assert s.stats()["flows_out"] == 1 and s.active_flows == 0


def test_unanswered_syn_is_s0_after_idle_timeout():
    s = Sessionizer(idle_timeout_sec=5, active_timeout_sec=10)
    assert s.add(pkt(0, CLIENT, 40000, SERVER, 22, "SYN")) == []
    s.add(pkt(6, OTHER, 1234, SERVER, 443, "SYN"))          # time passes; first flow goes idle
    assert s.active_flows == 1
    released = s.add(pkt(20, OTHER, 1235, SERVER, 443, "SYN"))
    assert [(f.destination_port, f.conn_state, f.tcp_flags) for f in released] == [(22, "S0", "SYN")]


def test_rejected_syn_is_rej():
    flows, _ = run([pkt(0, CLIENT, 40000, SERVER, 23, "SYN"),
                    pkt(0.001, SERVER, 23, CLIENT, 40000, "RST,ACK")])
    assert [f.conn_state for f in flows] == ["REJ"]
    assert flows[0].tcp_flags == "SYN"


def test_reset_after_establishment_is_rst():
    flows, _ = run([pkt(0, CLIENT, 40000, SERVER, 22, "SYN"),
                    pkt(0.001, SERVER, 22, CLIENT, 40000, "SYN,ACK"),
                    pkt(0.002, CLIENT, 40000, SERVER, 22, "RST")])
    assert [f.conn_state for f in flows] == ["RST"]


def test_established_but_not_closed_is_s1():
    flows, _ = run(handshake_and_close()[:5])
    assert flows[0].conn_state == "S1"


def test_syn_ack_seen_first_sets_originator_to_receiver():
    flows, _ = run([pkt(0, SERVER, 80, CLIENT, 50000, "SYN,ACK"),
                    pkt(0.01, CLIENT, 50000, SERVER, 80, "ACK")])
    f = flows[0]
    assert (f.source_ip, f.destination_port) == (CLIENT, 80)
    assert f.conn_state == "OTH"


def test_reply_from_service_port_seen_first_is_flipped():
    flows, _ = run([pkt(0, SERVER, 53, CLIENT, 40000, proto=ProtocolType.UDP)])
    f = flows[0]
    assert (f.source_ip, f.source_port, f.destination_port) == (CLIENT, 40000, 53)
    assert (f.orig_packets, f.resp_packets) == (0, 1)


def test_udp_two_way_is_sf_and_one_way_is_s0():
    two_way, _ = run([pkt(0, CLIENT, 40000, SERVER, 53, proto=ProtocolType.UDP),
                      pkt(0.01, SERVER, 53, CLIENT, 40000, proto=ProtocolType.UDP)])
    one_way, _ = run([pkt(0, CLIENT, 40000, SERVER, 123, proto=ProtocolType.UDP)])
    assert two_way[0].conn_state == "SF" and two_way[0].tcp_flags is None
    assert one_way[0].conn_state == "S0"


def test_dns_rcode_from_response_and_tls_selected_over_offered():
    flows, _ = run([
        pkt(0, CLIENT, 40000, SERVER, 53, proto=ProtocolType.UDP, dns_query="x.example", dns_record_type="A"),
        pkt(0.01, SERVER, 53, CLIENT, 40000, proto=ProtocolType.UDP, dns_query="x.example",
            dns_record_type="A", dns_rcode="NXDOMAIN"),
        pkt(1, CLIENT, 50001, SERVER, 443, "SYN"),
        pkt(1.01, SERVER, 443, CLIENT, 50001, "SYN,ACK"),
        pkt(1.02, CLIENT, 50001, SERVER, 443, "PSH,ACK", tls_version="TLSv1.3"),
        pkt(1.03, SERVER, 443, CLIENT, 50001, "PSH,ACK", tls_version="TLSv1.2",
            tls_cipher="TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"),
    ])
    dns, tls = flows
    assert (dns.dns_query, dns.dns_rcode, dns.dns_query_length) == ("x.example", "NXDOMAIN", 9)
    assert tls.tls_version == "TLSv1.2"          # server's selection wins over client's offer
    assert tls.tls_cipher == "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"


def test_long_flow_is_split_into_segments_at_active_timeout():
    packets = [pkt(0, CLIENT, 50000, SERVER, 80, "SYN")]
    for t in range(1, 25):
        src = (CLIENT, 50000, SERVER, 80) if t % 2 else (SERVER, 80, CLIENT, 50000)
        packets.append(pkt(t, *src, "ACK", size=100))
    flows, s = run(packets, idle_timeout_sec=5, active_timeout_sec=10)
    assert [f.timestamp - T0 for f in flows] == [timedelta(0), timedelta(seconds=10), timedelta(seconds=20)]
    assert [f.duration for f in flows] == [9.0, 9.0, 4.0]
    assert len({f.flow_id for f in flows}) == 1
    assert sum(f.packet_count for f in flows) == 25
    assert sum(f.byte_count for f in flows) == 60 + 24 * 100
    assert s.stats()["segments_split"] == 2


def test_max_active_flows_ends_least_recent_flow_early():
    flows, s = run([pkt(0.0, CLIENT, 1, SERVER, 80, "SYN"),
                    pkt(0.1, CLIENT, 2, SERVER, 80, "SYN"),
                    pkt(0.2, CLIENT, 3, SERVER, 80, "SYN")], max_active_flows=2)
    assert s.stats()["evicted_early"] == 1
    assert [f.source_port for f in flows] == [1, 2, 3]


def test_output_is_in_start_time_order():
    rng = random.Random(7)
    packets = []
    for t10 in range(0, 400):                     # a 40 s flow with a packet every 0.1 s
        packets.append(pkt(t10 / 10, CLIENT, 50000, SERVER, 443, "ACK"))
    for i in range(300):                          # short flows sprinkled throughout
        start = rng.uniform(0, 40)
        packets.append(pkt(start, OTHER, 10000 + i, SERVER, 80, "SYN"))
        if rng.random() < 0.5:
            packets.append(pkt(start + 0.01, SERVER, 80, OTHER, 10000 + i, "SYN,ACK"))
    packets.sort(key=lambda p: p.timestamp)
    flows, s = run(packets)
    assert all(a.timestamp <= b.timestamp for a, b in zip(flows, flows[1:]))
    assert s.stats()["out_of_order_flows"] == 0
    assert sum(f.packet_count for f in flows) == len(packets)


def test_from_config():
    from unishield.config import UnishieldConfig
    config = UnishieldConfig(sessionizer={"idle_timeout_sec": 2, "active_timeout_sec": 4,
                                          "max_active_flows": 10})
    s = Sessionizer.from_config(config)
    assert s.idle_timeout == timedelta(seconds=2)
    assert s.active_timeout == timedelta(seconds=4)
    assert s.max_active_flows == 10
