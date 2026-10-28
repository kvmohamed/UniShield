"""CTU-13 binetflow (Argus) reading: profile detection, state translation, byte split, labels."""

from __future__ import annotations

import pytest

from unishield.ingest.detect import detect_format, open_reader
from unishield.ingest.flow_reader import FlowReader, argus_conn_state
from unishield.models.dataset import normalise_label
from unishield.schemas.flow import ProtocolType

HEADER = "StartTime,Dur,Proto,SrcAddr,Sport,Dir,DstAddr,Dport,State,sTos,dTos,TotPkts,TotBytes,SrcBytes,Label\n"
ROWS = [
    "2011/08/10 09:46:53.047277,3.124,tcp,147.32.84.165,1027,   ->,74.125.232.195,80,FSPA_FSPA,0,0,12,4520,860,flow=From-Botnet-V42-TCP-HTTP-Google-Net-Established-6\n",
    "2011/08/10 09:46:53.100000,0.000,tcp,147.32.84.165,1028,   ->,10.0.0.9,445,S_,0,,1,62,62,flow=From-Botnet-V42-TCP-Attempt\n",
    "2011/08/10 09:46:54.000000,0.001,tcp,147.32.84.165,1029,   ->,10.0.0.9,139,S_RA,0,0,2,122,62,flow=From-Botnet-V42-TCP-Attempt\n",
    "2011/08/10 09:46:55.500000,0.250,udp,147.32.80.9,53,  <->,147.32.84.229,1234,CON,0,0,2,300,90,flow=Background-UDP-Established\n",
    "2011/08/10 09:46:56.000000,0.000,icmp,147.32.84.165,0x0008,   ->,1.2.3.4,0x0000,ECO,0,,1,70,70,flow=To-Normal-V42-ICMP\n",
    "garbage,line,without,enough,fields\n",
]


@pytest.fixture
def binetflow(tmp_path):
    path = tmp_path / "capture20110810.binetflow"
    path.write_text(HEADER + "".join(ROWS), encoding="utf-8")
    return path


@pytest.mark.parametrize("state,proto,expected", [
    ("S_", "tcp", ("S0", "SYN")),
    ("S_RA", "tcp", ("REJ", "SYN")),
    ("FSPA_FSPA", "tcp", ("SF", "ACK,FIN,PSH,SYN")),
    ("SPA_SPA", "tcp", ("S1", "ACK,PSH,SYN")),
    ("SRPA_SPA", "tcp", ("RST", "ACK,PSH,RST,SYN")),
    ("PA_PA", "tcp", ("OTH", "ACK,PSH")),
    ("INT", "udp", ("S0", None)),
    ("CON", "udp", ("SF", None)),
    ("ECO", "icmp", ("OTH", None)),
    ("", "tcp", (None, None)),
])
def test_argus_state_translation(state, proto, expected):
    assert argus_conn_state(state, proto) == expected


def test_binetflow_is_read_with_the_ctu13_profile(binetflow):
    assert detect_format(binetflow) == "flow_csv"
    reader, fmt = open_reader(binetflow)
    flows = list(reader.read())
    assert fmt == "flow_csv" and reader.profile.name == "ctu13"
    assert len(flows) == 5 and reader.errors == 1                  # garbage line counted, not fabricated

    web, syn, rej, dns, icmp = flows
    assert web.timestamp.microsecond == 47277 and web.duration == pytest.approx(3.124)
    assert (web.source_ip, web.source_port, web.destination_ip, web.destination_port) == \
        ("147.32.84.165", 1027, "74.125.232.195", 80)
    assert web.protocol == ProtocolType.TCP and web.packet_count == 12
    assert (web.byte_count, web.orig_bytes, web.resp_bytes) == (4520, 860, 3660)
    assert web.conn_state == "SF" and web.tcp_flags == "ACK,FIN,PSH,SYN"
    assert (syn.conn_state, rej.conn_state) == ("S0", "REJ")
    assert dns.conn_state == "SF" and dns.protocol == ProtocolType.UDP
    assert icmp.source_port is None and icmp.protocol == ProtocolType.ICMP   # hex ICMP type/code ignored
    assert normalise_label(web.label) == "BOTNET" and normalise_label(dns.label) == "BENIGN"
    assert normalise_label(icmp.label) == "BENIGN"


def test_argus_direction_column_is_not_taken_as_network_direction(binetflow):
    flows = list(FlowReader(binetflow).read())
    assert all(f.direction.value == "unknown" for f in flows)


def test_prepare_files_uses_the_given_home_networks(binetflow, tmp_path):
    import json

    from unishield.models.dataset import load_windows
    from unishield.models.workflow import prepare_files

    out = tmp_path / "windows_ctu.csv"
    manifest = prepare_files(out, [binetflow], home_networks=["147.32.0.0/16"])
    assert manifest["source"]["home_networks"] == ["147.32.0.0/16"]
    assert manifest["source"]["inputs"][0]["records_read"] == 5
    records, _ = load_windows(out)
    assert any(r.label == "BOTNET" for r in records)
    assert json.loads(out.with_suffix(".manifest.json").read_text())["sha256"] == manifest["sha256"]
