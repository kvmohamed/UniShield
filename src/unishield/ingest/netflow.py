"""
UniShield — NetFlow v5 / v9 and IPFIX Decoding

Turns flow-export datagrams into NormalisedFlow records. Pure byte parsing:
this module has no network access (the receive-only collector in
``ingest/collector.py`` hands it datagrams).

    NetFlow v5  fixed 48-byte records (unidirectional)
    NetFlow v9  template-based (RFC 3954); templates per exporter and source id
    IPFIX       template-based (RFC 7011), variable-length fields, enterprise
                fields; bidirectional flows with the RFC 5103 reverse
                counters (enterprise 29305) give per-direction packets/bytes

Times: v5 and the v9/IPFIX "switched" fields are milliseconds of exporter
uptime and are converted with the header's export time and uptime; IPFIX
absolute start/end fields are used when present. Unidirectional exports
carry no reply counters, so per-direction fields stay empty.

Malformed datagrams raise ``FlowExportError``; data records for an unknown
template are counted and skipped (they decode once the template arrives).
Template storage is bounded.

Loss: exporters number their output (v5 and IPFIX count flow records, v9
counts datagrams). Gaps in the sequence per exporter and domain are counted
as ``lost_records`` / ``lost_datagrams``: UDP is unacknowledged, and a full
receive buffer or a lossy path drops datagrams silently otherwise. Small
backward steps are counted as reordering; large ones as an exporter restart.
"""

from __future__ import annotations

import ipaddress
import struct
from collections import Counter, OrderedDict
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from unishield.schemas.flow import FlowDirection, InputSource, NormalisedFlow, ProtocolType

REVERSE_PEN = 29305                    # RFC 5103 reverse information elements
_PROTOCOLS = {6: ProtocolType.TCP, 17: ProtocolType.UDP, 1: ProtocolType.ICMP, 58: ProtocolType.ICMP}
_TCP_FLAG_NAMES = ((0x01, "FIN"), (0x02, "SYN"), (0x04, "RST"), (0x08, "PSH"), (0x10, "ACK"), (0x20, "URG"),
                   (0x40, "ECE"), (0x80, "CWR"))

# Information element ids (NetFlow v9 field types share these numbers)
OCTETS, PACKETS, PROTOCOL, TCP_FLAGS = 1, 2, 4, 6
SRC_PORT, SRC_V4, DST_PORT, DST_V4 = 7, 8, 11, 12
LAST_SWITCHED, FIRST_SWITCHED, SRC_V6, DST_V6 = 21, 22, 27, 28
START_SEC, END_SEC, START_MS, END_MS, START_US, END_US = 150, 151, 152, 153, 154, 155
SYS_INIT_MS = 160

_V5_HEADER = struct.Struct("!HHIIIIBBH")              # 24 bytes
_V5_RECORD = struct.Struct("!4s4s4sHHIIIIHHxBBBHHBBxx")  # 48 bytes
_V9_HEADER = struct.Struct("!HHIIII")                 # 20 bytes
_IPFIX_HEADER = struct.Struct("!HHIII")               # 16 bytes
_SEQ_MOD = 2 ** 32
_MAX_GAP = 1_000_000                  # a larger forward jump is an exporter restart, not loss
_MAX_REORDER = 10_000                 # a smaller backward step is a late datagram


class FlowExportError(ValueError):
    """The datagram is not a well-formed NetFlow v5/v9 or IPFIX message."""


def tcp_flags_text(value: int) -> Optional[str]:
    names = sorted(name for bit, name in _TCP_FLAG_NAMES if value & bit)
    return ",".join(names) or None


class FlowExportDecoder:
    """Stateful decoder (templates are remembered per exporter and domain)."""

    def __init__(self, max_templates: int = 10_000):
        self.max_templates = max_templates
        self._templates: OrderedDict[tuple, list[tuple[int, int, int]]] = OrderedDict()
        self._next_sequence: OrderedDict[tuple, int] = OrderedDict()
        self.counts: Counter = Counter()

    @property
    def templates(self) -> int:
        return len(self._templates)

    def decode(self, data: bytes, exporter: str) -> list[NormalisedFlow]:
        if len(data) < 4:
            raise FlowExportError("datagram too short")
        version = struct.unpack_from("!H", data)[0]
        if version == 5:
            flows = self._v5(data, exporter)
        elif version == 9:
            flows = self._v9(data, exporter)
        elif version == 10:
            flows = self._ipfix(data, exporter)
        else:
            raise FlowExportError(f"unsupported flow-export version {version}")
        self.counts[f"v{version}_datagrams"] += 1
        self.counts["records"] += len(flows)
        return flows

    def _sequence(self, key: tuple, sequence: int, advance: Optional[int], unit: str) -> None:
        """Count units the exporter numbered but that never arrived; ``advance`` None: next value unknown."""
        expected = self._next_sequence.get(key)
        if expected is not None:
            gap = (sequence - expected) % _SEQ_MOD
            if 0 < gap <= _MAX_GAP:
                self.counts[f"lost_{unit}"] += gap
            elif gap > _SEQ_MOD - _MAX_REORDER:                  # behind the expected value: a late datagram
                self.counts["reordered_datagrams"] += 1
                return
            elif gap:
                self.counts["sequence_resets"] += 1
        if advance is None:
            self._next_sequence.pop(key, None)
            return
        self._next_sequence[key] = (sequence + advance) % _SEQ_MOD
        self._next_sequence.move_to_end(key)
        while len(self._next_sequence) > self.max_templates:
            self._next_sequence.popitem(last=False)

    # --- NetFlow v5 -------------------------------------------------------------

    def _v5(self, data: bytes, exporter: str) -> list[NormalisedFlow]:
        if len(data) < _V5_HEADER.size:
            raise FlowExportError("v5 header truncated")
        _, count, uptime, secs, nsecs, sequence, engine_type, engine_id, _ = _V5_HEADER.unpack_from(data)
        if not 1 <= count <= 30 or len(data) < _V5_HEADER.size + count * _V5_RECORD.size:
            raise FlowExportError(f"v5 record count {count} does not match the datagram length")
        export = secs + nsecs / 1e9
        flows = []
        for i in range(count):
            (src, dst, _, _, _, pkts, octets, first, last, sport, dport, flags, proto, _, _, _, _, _
             ) = _V5_RECORD.unpack_from(data, _V5_HEADER.size + i * _V5_RECORD.size)
            values = {SRC_V4: src, DST_V4: dst, PACKETS: pkts, OCTETS: octets, FIRST_SWITCHED: first,
                      LAST_SWITCHED: last, SRC_PORT: sport, DST_PORT: dport, TCP_FLAGS: flags, PROTOCOL: proto}
            flow = self._to_flow(values, {}, export, uptime)
            if flow is not None:
                flows.append(flow)
        self._sequence((5, exporter, engine_type, engine_id), sequence, count, "records")
        return flows

    # --- NetFlow v9 -------------------------------------------------------------

    def _v9(self, data: bytes, exporter: str) -> list[NormalisedFlow]:
        if len(data) < _V9_HEADER.size:
            raise FlowExportError("v9 header truncated")
        _, _, uptime, secs, sequence, source_id = _V9_HEADER.unpack_from(data)
        flows: list[NormalisedFlow] = []
        for set_id, body in self._sets(data, _V9_HEADER.size, len(data)):
            if set_id == 0:
                self._v9_templates(body, (9, exporter, source_id))
            elif set_id >= 256:
                flows += self._data_set(body, (9, exporter, source_id, set_id), float(secs), uptime)
            # set 1 (options templates) carries no flows
        self._sequence((9, exporter, source_id), sequence, 1, "datagrams")
        return flows

    def _v9_templates(self, body: bytes, domain: tuple) -> None:
        off = 0
        while off + 4 <= len(body):
            template_id, field_count = struct.unpack_from("!HH", body, off)
            off += 4
            if template_id < 256 or off + 4 * field_count > len(body):
                raise FlowExportError("v9 template malformed")
            fields = []
            for _ in range(field_count):
                ie, length = struct.unpack_from("!HH", body, off)
                fields.append((ie, 0, length))
                off += 4
            self._remember((*domain, template_id), fields)

    # --- IPFIX --------------------------------------------------------------------

    def _ipfix(self, data: bytes, exporter: str) -> list[NormalisedFlow]:
        if len(data) < _IPFIX_HEADER.size:
            raise FlowExportError("IPFIX header truncated")
        _, length, export_time, sequence, domain = _IPFIX_HEADER.unpack_from(data)
        if length > len(data) or length < _IPFIX_HEADER.size:
            raise FlowExportError("IPFIX message length does not match the datagram")
        flows: list[NormalisedFlow] = []
        undecoded = self.counts["records_without_template"]
        without_addresses = self.counts["records_without_addresses"]
        for set_id, body in self._sets(data, _IPFIX_HEADER.size, length):
            if set_id == 2:
                self._ipfix_templates(body, (10, exporter, domain))
            elif set_id >= 256:
                flows += self._data_set(body, (10, exporter, domain, set_id), float(export_time), None)
            # set 3 (options templates) carries no flows
        # the sequence counts data records sent; a set without a known template hides how many it held
        records = len(flows) + self.counts["records_without_addresses"] - without_addresses
        advance = records if self.counts["records_without_template"] == undecoded else None
        self._sequence((10, exporter, domain), sequence, advance, "records")
        return flows

    def _ipfix_templates(self, body: bytes, domain: tuple) -> None:
        off = 0
        while off + 4 <= len(body):
            template_id, field_count = struct.unpack_from("!HH", body, off)
            off += 4
            if template_id < 256:
                raise FlowExportError("IPFIX template id below 256")
            if field_count == 0:                               # template withdrawal
                self._templates.pop((*domain, template_id), None)
                continue
            fields = []
            for _ in range(field_count):
                if off + 4 > len(body):
                    raise FlowExportError("IPFIX template truncated")
                ie, length = struct.unpack_from("!HH", body, off)
                off += 4
                pen = 0
                if ie & 0x8000:
                    if off + 4 > len(body):
                        raise FlowExportError("IPFIX enterprise field truncated")
                    pen = struct.unpack_from("!I", body, off)[0]
                    off += 4
                    ie &= 0x7FFF
                fields.append((ie, pen, length))
            self._remember((*domain, template_id), fields)

    # --- shared -------------------------------------------------------------------

    @staticmethod
    def _sets(data: bytes, start: int, end: int):
        off = start
        while off + 4 <= end:
            set_id, set_len = struct.unpack_from("!HH", data, off)
            if set_len < 4 or off + set_len > end:
                raise FlowExportError("flow set length out of range")
            yield set_id, data[off + 4: off + set_len]
            off += set_len

    def _remember(self, key: tuple, fields: list[tuple[int, int, int]]) -> None:
        self._templates[key] = fields
        self._templates.move_to_end(key)
        self.counts["templates_received"] += 1
        while len(self._templates) > self.max_templates:
            self._templates.popitem(last=False)

    def _data_set(self, body: bytes, key: tuple, export: float, uptime: Optional[int]) -> list[NormalisedFlow]:
        fields = self._templates.get(key)
        if fields is None:
            self.counts["records_without_template"] += 1
            return []
        # shortest possible record: fixed fields plus one length octet per variable field
        min_len = sum(1 if length == 0xFFFF else length for _, _, length in fields)
        flows: list[NormalisedFlow] = []
        off = 0
        while off < len(body):
            if len(body) - off < max(min_len, 1):
                break                                          # padding at the end of the set
            values: dict[int, Any] = {}
            reverse: dict[int, Any] = {}
            try:
                for ie, pen, length in fields:
                    if length == 0xFFFF:
                        length = body[off]
                        off += 1
                        if length == 255:
                            length = struct.unpack_from("!H", body, off)[0]
                            off += 2
                    if off + length > len(body):
                        raise FlowExportError("data record truncated")
                    raw = body[off: off + length]
                    off += length
                    if pen == REVERSE_PEN:
                        reverse[ie] = raw
                    elif pen == 0:
                        values[ie] = raw
            except (IndexError, struct.error) as exc:
                raise FlowExportError("data record truncated") from exc
            flow = self._to_flow(values, reverse, export, uptime)
            if flow is not None:
                flows.append(flow)
            else:
                self.counts["records_without_addresses"] += 1
        return flows

    @staticmethod
    def _int(raw: Any) -> Optional[int]:
        if raw is None:
            return None
        return raw if isinstance(raw, int) else int.from_bytes(raw, "big")

    @staticmethod
    def _ip(raw: Any) -> Optional[str]:
        if raw is None:
            return None
        if isinstance(raw, (bytes, bytearray)) and len(raw) in (4, 16):
            return str(ipaddress.ip_address(bytes(raw)))
        return None

    def _to_flow(self, values: dict[int, Any], reverse: dict[int, Any], export: float,
                 uptime: Optional[int]) -> Optional[NormalisedFlow]:
        src = self._ip(values.get(SRC_V4)) or self._ip(values.get(SRC_V6))
        dst = self._ip(values.get(DST_V4)) or self._ip(values.get(DST_V6))
        if src is None or dst is None:
            return None
        start, end = self._times(values, export, uptime)
        proto_num = self._int(values.get(PROTOCOL))
        protocol = _PROTOCOLS.get(proto_num, ProtocolType.OTHER) if proto_num is not None else ProtocolType.OTHER
        ports = protocol in (ProtocolType.TCP, ProtocolType.UDP)
        pkts, octets = self._int(values.get(PACKETS)) or 0, self._int(values.get(OCTETS)) or 0
        rev_pkts, rev_octets = self._int(reverse.get(PACKETS)), self._int(reverse.get(OCTETS))
        biflow = rev_pkts is not None or rev_octets is not None
        flags = self._int(values.get(TCP_FLAGS))
        return NormalisedFlow(
            timestamp=start,
            source_ip=src,
            destination_ip=dst,
            source_port=self._int(values.get(SRC_PORT)) if ports else None,
            destination_port=self._int(values.get(DST_PORT)) if ports else None,
            protocol=protocol,
            packet_count=max(pkts + (rev_pkts or 0), 1),
            byte_count=octets + (rev_octets or 0),
            orig_packets=pkts if biflow else None,
            resp_packets=(rev_pkts or 0) if biflow else None,
            orig_bytes=octets if biflow else None,
            resp_bytes=(rev_octets or 0) if biflow else None,
            duration=max(0.0, (end - start).total_seconds()),
            tcp_flags=tcp_flags_text(flags) if protocol == ProtocolType.TCP and flags else None,
            direction=FlowDirection.UNKNOWN,
            source_type=InputSource.FLOW_EXPORT,
        )

    def _times(self, values: dict[int, Any], export: float, uptime: Optional[int]) -> tuple[datetime, datetime]:
        exported = datetime.fromtimestamp(export, tz=timezone.utc)
        for start_ie, end_ie, scale in ((START_MS, END_MS, 1e-3), (START_US, END_US, 1e-6), (START_SEC, END_SEC, 1.0)):
            start = self._int(values.get(start_ie))
            if start is not None:
                begin = datetime.fromtimestamp(start * scale, tz=timezone.utc)
                end = self._int(values.get(end_ie))
                return begin, (datetime.fromtimestamp(end * scale, tz=timezone.utc) if end is not None else begin)
        first, last = self._int(values.get(FIRST_SWITCHED)), self._int(values.get(LAST_SWITCHED))
        init = self._int(values.get(SYS_INIT_MS))
        if first is not None and init is not None:              # IPFIX sysUpTime relative to system init
            begin = datetime.fromtimestamp((init + first) / 1000, tz=timezone.utc)
            return begin, begin + timedelta(milliseconds=max(0, (last or first) - first))
        if first is not None and uptime is not None:             # NetFlow: ms of uptime at export time
            begin = exported - timedelta(milliseconds=max(0, uptime - first))
            return begin, begin + timedelta(milliseconds=max(0, (last if last is not None else first) - first))
        return exported, exported
