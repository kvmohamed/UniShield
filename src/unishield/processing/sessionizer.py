"""
UniShield — Flow Sessionizer

Aggregates packet-level records (PCAP input) into bidirectional flow
records, similar to a NetFlow/IPFIX exporter or Zeek's conn.log:

    - Packets are grouped by protocol + the two (IP, port) endpoints.
    - The originator is the first sender, except when the first packet seen
      is a SYN-ACK, or comes from a well-known port (< 1024) to a high port,
      in which case the receiver is treated as the originator.
    - Per-direction packet/byte counts and a Zeek-style connection state
      (S0, REJ, S1, SF, RST, OTH) are kept.
    - ``tcp_flags`` holds the flags sent by the originator, so a SYN-only
      flow is an unanswered or rejected connection attempt.

A flow ends when it has been idle for ``idle_timeout_sec``, shortly after a
FIN from both sides or an RST (``closing_grace_sec`` absorbs trailing ACKs),
or early when ``max_active_flows`` is exceeded (least recently active flow
first). Long flows are emitted in segments of ``active_timeout_sec``; the
segments share a ``flow_id`` and their counts are deltas.

Ordering guarantee: every segment is emitted no later than
``start + active_timeout + idle_timeout + sweep_interval`` (traffic time),
so finished segments are held in a heap and released in start-time order
once traffic time has passed that bound. Output therefore lags input by
that amount; ``flush()`` releases everything at end of input.

Time is traffic (event) time from packet timestamps, never the wall clock.

SECURITY CONSTRAINTS:
    - Pure in-memory aggregation of records already read. No network I/O.
"""

from __future__ import annotations

import heapq
import itertools
import logging
from collections import OrderedDict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Iterable, Iterator, Optional

from unishield.schemas.flow import InputSource, NormalisedFlow, ProtocolType

logger = logging.getLogger("unishield.processing.sessionizer")

_Endpoint = tuple[str, Optional[int]]


@dataclass
class _FlowState:
    flow_id: str
    protocol: ProtocolType
    orig: _Endpoint
    resp: _Endpoint
    source_type: InputSource
    first_ts: datetime
    last_ts: datetime
    seg_start: datetime
    seg_last: datetime
    # current segment counters
    orig_pkts: int = 0
    resp_pkts: int = 0
    orig_bytes: int = 0
    resp_bytes: int = 0
    orig_flags: set[str] = field(default_factory=set)
    # whole-connection state
    total_resp_pkts: int = 0
    orig_syn: bool = False
    resp_synack: bool = False
    orig_fin: bool = False
    resp_fin: bool = False
    orig_rst: bool = False
    resp_rst: bool = False
    closing_since: Optional[datetime] = None
    dns_query: Optional[str] = None
    dns_record_type: Optional[str] = None
    dns_rcode: Optional[str] = None
    tls_offered: Optional[str] = None
    tls_selected: Optional[str] = None
    tls_cipher: Optional[str] = None


def _port_key(endpoint: _Endpoint) -> tuple[str, int]:
    return endpoint[0], -1 if endpoint[1] is None else endpoint[1]


def _flow_key(protocol: ProtocolType, a: _Endpoint, b: _Endpoint) -> tuple:
    """Same key for both directions of a connection."""
    lo, hi = sorted((a, b), key=_port_key)
    return (protocol, lo, hi)


def _flag_set(flags: Optional[str]) -> set[str]:
    return {f.strip().upper() for f in flags.split(",") if f.strip()} if flags else set()


class Sessionizer:
    """Streaming packet → bidirectional flow aggregator."""

    def __init__(
        self,
        idle_timeout_sec: float = 5.0,
        active_timeout_sec: float = 10.0,
        closing_grace_sec: float = 1.0,
        max_active_flows: int = 100_000,
        sweep_interval_sec: float = 1.0,
    ):
        self.idle_timeout = timedelta(seconds=idle_timeout_sec)
        self.active_timeout = timedelta(seconds=active_timeout_sec)
        self.closing_grace = timedelta(seconds=closing_grace_sec)
        self.sweep_interval = timedelta(seconds=sweep_interval_sec)
        self.max_active_flows = max_active_flows
        # Segments are emitted at most this long after they start.
        self.release_lag = self.active_timeout + max(self.idle_timeout, self.closing_grace) \
            + self.sweep_interval

        self._flows: OrderedDict[tuple, _FlowState] = OrderedDict()  # least recently active first
        self._closing: set[tuple] = set()
        self._heap: list[tuple[datetime, int, NormalisedFlow]] = []
        self._seq = itertools.count()
        self._ids = itertools.count(1)
        self._now: Optional[datetime] = None
        self._next_sweep: Optional[datetime] = None
        self._last_released: Optional[datetime] = None

        self.packets_in = 0
        self.flows_out = 0
        self.segments_split = 0
        self.evicted = 0
        self.out_of_order = 0

    @classmethod
    def from_config(cls, config=None) -> "Sessionizer":
        if config is None:
            from unishield.config import get_config
            config = get_config()
        s = config.sessionizer
        return cls(
            idle_timeout_sec=s.idle_timeout_sec,
            active_timeout_sec=s.active_timeout_sec,
            closing_grace_sec=s.closing_grace_sec,
            max_active_flows=s.max_active_flows,
        )

    # ------------------------------------------------------------------ API

    def process(self, packets: Iterable[NormalisedFlow]) -> Iterator[NormalisedFlow]:
        """Sessionize a packet stream; yields flows in start-time order, then flushes."""
        for packet in packets:
            yield from self.add(packet)
        yield from self.flush()

    def add(self, packet: NormalisedFlow) -> list[NormalisedFlow]:
        """Add one packet record; return flows whose release time has passed."""
        self.packets_in += 1
        ts = packet.timestamp
        if self._now is None or ts > self._now:
            self._now = ts
        if self._next_sweep is None:
            self._next_sweep = ts + self.sweep_interval
        if self._now >= self._next_sweep:
            self._sweep(self._now)
            self._next_sweep = self._now + self.sweep_interval

        self._update(packet)
        return self._release(self._now - self.release_lag)

    def flush(self) -> list[NormalisedFlow]:
        """End all active flows and release everything (end of input)."""
        for key in list(self._flows):
            self._finish(key)
        return self._release(None)

    @property
    def active_flows(self) -> int:
        return len(self._flows)

    def stats(self) -> dict:
        return {
            "packets_in": self.packets_in,
            "flows_out": self.flows_out,
            "active_flows": len(self._flows),
            "pending_release": len(self._heap),
            "segments_split": self.segments_split,
            "evicted_early": self.evicted,
            "out_of_order_flows": self.out_of_order,
        }

    # ------------------------------------------------------------ internals

    def _update(self, p: NormalisedFlow) -> None:
        src: _Endpoint = (p.source_ip, p.source_port)
        dst: _Endpoint = (p.destination_ip, p.destination_port)
        key = _flow_key(p.protocol, src, dst)
        flags = _flag_set(p.tcp_flags)
        ts = p.timestamp

        state = self._flows.get(key)
        if state is not None and ts - state.seg_start >= self.active_timeout:
            self._emit_segment(state)
            self.segments_split += 1
            state.seg_start = ts
        if state is None:
            if len(self._flows) >= self.max_active_flows:
                oldest = next(iter(self._flows))
                self._finish(oldest)
                self.evicted += 1
            orig, resp = self._orientation(p, src, dst, flags)
            state = _FlowState(
                flow_id=f"S{next(self._ids):08d}",
                protocol=p.protocol,
                orig=orig,
                resp=resp,
                source_type=p.source_type,
                first_ts=ts,
                last_ts=ts,
                seg_start=ts,
                seg_last=ts,
            )
            self._flows[key] = state
        else:
            self._flows.move_to_end(key)

        from_orig = src == state.orig
        if from_orig:
            state.orig_pkts += p.packet_count
            state.orig_bytes += p.byte_count
            state.orig_flags |= flags
        else:
            state.resp_pkts += p.packet_count
            state.resp_bytes += p.byte_count
            state.total_resp_pkts += p.packet_count
        if ts > state.last_ts:
            state.last_ts = ts
        if ts > state.seg_last:
            state.seg_last = ts

        if p.protocol == ProtocolType.TCP and flags:
            if from_orig:
                state.orig_syn |= "SYN" in flags and "ACK" not in flags
                state.orig_fin |= "FIN" in flags
                state.orig_rst |= "RST" in flags
            else:
                state.resp_synack |= "SYN" in flags and "ACK" in flags
                state.resp_fin |= "FIN" in flags
                state.resp_rst |= "RST" in flags
            ended = state.orig_rst or state.resp_rst or (state.orig_fin and state.resp_fin)
            if ended and state.closing_since is None:
                state.closing_since = ts
                self._closing.add(key)

        if p.dns_query and state.dns_query is None:
            state.dns_query, state.dns_record_type = p.dns_query, p.dns_record_type
        if p.dns_rcode and not from_orig:
            state.dns_rcode = p.dns_rcode
        if p.tls_version:
            if from_orig:
                state.tls_offered = state.tls_offered or p.tls_version
            else:
                state.tls_selected = p.tls_version
        if p.tls_cipher and not from_orig:
            state.tls_cipher = p.tls_cipher

    @staticmethod
    def _orientation(p: NormalisedFlow, src: _Endpoint, dst: _Endpoint, flags: set[str]):
        """Decide (originator, responder) from the first packet seen."""
        if p.protocol == ProtocolType.TCP and "SYN" in flags:
            return (dst, src) if "ACK" in flags else (src, dst)
        if (
            p.source_port is not None and p.destination_port is not None
            and p.source_port < 1024 <= p.destination_port
        ):
            return dst, src   # reply from a service port: the receiver started it
        return src, dst

    def _sweep(self, now: datetime) -> None:
        """End flows that are idle, or closed and past the grace period."""
        for key in [k for k in self._closing if now - self._flows[k].last_ts >= self.closing_grace]:
            self._finish(key)
        while self._flows:
            key, state = next(iter(self._flows.items()))
            if now - state.last_ts < self.idle_timeout:
                break
            self._finish(key)

    def _finish(self, key: tuple) -> None:
        state = self._flows.pop(key)
        self._closing.discard(key)
        self._emit_segment(state)

    def _emit_segment(self, s: _FlowState) -> None:
        tcp_flags = None
        if s.protocol == ProtocolType.TCP and s.orig_flags:
            tcp_flags = ",".join(sorted(s.orig_flags))
        record = NormalisedFlow(
            flow_id=s.flow_id,
            timestamp=s.seg_start,
            source_ip=s.orig[0],
            destination_ip=s.resp[0],
            source_port=s.orig[1],
            destination_port=s.resp[1],
            protocol=s.protocol,
            packet_count=s.orig_pkts + s.resp_pkts,
            byte_count=s.orig_bytes + s.resp_bytes,
            orig_packets=s.orig_pkts,
            resp_packets=s.resp_pkts,
            orig_bytes=s.orig_bytes,
            resp_bytes=s.resp_bytes,
            duration=max((s.seg_last - s.seg_start).total_seconds(), 0.0),
            tcp_flags=tcp_flags,
            conn_state=self._conn_state(s),
            dns_query=s.dns_query,
            dns_query_length=len(s.dns_query) if s.dns_query else None,
            dns_record_type=s.dns_record_type,
            dns_rcode=s.dns_rcode,
            tls_version=s.tls_selected or s.tls_offered,
            tls_cipher=s.tls_cipher,
            source_type=s.source_type,
        )
        heapq.heappush(self._heap, (record.timestamp, next(self._seq), record))
        s.orig_pkts = s.resp_pkts = s.orig_bytes = s.resp_bytes = 0
        s.orig_flags = set()
        s.seg_last = s.seg_start

    @staticmethod
    def _conn_state(s: _FlowState) -> str:
        if s.protocol != ProtocolType.TCP:
            return "SF" if s.total_resp_pkts else "S0"
        if s.orig_syn and not s.resp_synack:
            if s.resp_rst:
                return "REJ"          # attempt rejected
            return "S0" if s.total_resp_pkts == 0 else "OTH"
        if s.orig_rst or s.resp_rst:
            return "RST"
        if s.orig_syn and s.resp_synack:
            return "SF" if (s.orig_fin and s.resp_fin) else "S1"
        return "OTH"                  # handshake not observed

    def _release(self, until: Optional[datetime]) -> list[NormalisedFlow]:
        out: list[NormalisedFlow] = []
        while self._heap and (until is None or self._heap[0][0] <= until):
            ts, _, record = heapq.heappop(self._heap)
            if self._last_released is not None and ts < self._last_released:
                self.out_of_order += 1
            else:
                self._last_released = ts
            out.append(record)
        self.flows_out += len(out)
        return out
