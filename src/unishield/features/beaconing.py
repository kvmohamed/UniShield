"""
UniShield — Beaconing Feature Extractor

C2 beacons check in every few seconds to every few hours, so a single
10-second window can never show the pattern. This extractor keeps a bounded
rolling history across windows:

    - per (source, destination, destination port): start times and uploaded
      bytes of up to ``max_per_pair`` recent connections within ``history_sec``
    - per destination: which sources contacted it within ``history_sec``
      (destination rarity — a C2 server is contacted by few internal hosts,
      a popular service by many)

Each window adds only records not seen before (windows overlap) and then
profiles every pair it touched: interval mean/std/CV, periodicity (share of
intervals within 20% of the median), size regularity and destination rarity.
Inbound connections (an outside host contacting an internal one) are not
tracked; beacons originate inside the monitored network.

SECURITY CONSTRAINTS:
    - Read-only computation over local flow records.
    - No network communication.
"""

from __future__ import annotations

import math
from collections import OrderedDict, deque
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
from typing import Any, Optional

from unishield.config import get_thresholds
from unishield.features.base import BaseFeatureExtractor, WindowContext
from unishield.schemas.flow import FlowDirection, NormalisedFlow
from unishield.schemas.timeutil import from_epoch_us, to_epoch_us

_MAX_CANDIDATES = 10
_SEEN_LIMIT = 200_000


@dataclass
class BeaconCandidate:
    source_ip: str
    destination_ip: str
    destination_port: Optional[int]
    connection_count: int
    interval_mean_sec: float
    interval_std_sec: float
    interval_cv: float
    periodicity: float
    size_regularity: float
    span_sec: float
    destination_sources: int
    uses_tls: bool


def _cv(values: list[float]) -> float:
    if len(values) < 2:
        return 0.0
    mean = sum(values) / len(values)
    if mean == 0:
        return 0.0
    std = math.sqrt(sum((v - mean) ** 2 for v in values) / len(values))
    return std / mean


class BeaconingFeatureExtractor(BaseFeatureExtractor):
    """Extract C2 beaconing features from a rolling per-pair connection history."""

    def __init__(
        self,
        min_connections: int | None = None,
        history_sec: float | None = None,
        max_pairs: int = 50_000,
        max_per_pair: int = 64,
    ):
        t = get_thresholds().get("beaconing", {})
        self.min_connections = min_connections or t.get("min_connections", 10)
        self.history = timedelta(seconds=history_sec or t.get("history_sec", 7200))
        self.max_pairs = max_pairs
        self.max_per_pair = max_per_pair
        # (src, dst, dport) -> deque[(timestamp, orig_bytes, tls)]; least recently used first
        self._pairs: OrderedDict[tuple, deque] = OrderedDict()
        # dst -> {src: last seen}
        self._dst_sources: OrderedDict[str, dict[str, datetime]] = OrderedDict()
        self._seen: OrderedDict[str, None] = OrderedDict()

    @property
    def name(self) -> str:
        return "beaconing"

    @property
    def feature_names(self) -> list[str]:
        return [
            "candidate_beacon_pairs",
            "top_beacon_interval_mean",
            "top_beacon_interval_std",
            "top_beacon_interval_cv",
            "top_beacon_periodicity_score",
            "top_beacon_size_regularity",
            "top_beacon_connection_count",
            "top_beacon_src_ip",
            "top_beacon_dst_ip",
            "avg_beacon_cv",
            "min_beacon_cv",
            "beacon_candidates",
            "tracked_pairs",
        ]

    def reset(self) -> None:
        self._pairs.clear()
        self._dst_sources.clear()
        self._seen.clear()

    def state_dict(self) -> dict[str, Any]:
        """Pair histories and destination sources (least recently used first), JSON-serialisable."""
        return {
            "pairs": [[src, dst, dport, [[to_epoch_us(t), up, tls] for t, up, tls in history]]
                      for (src, dst, dport), history in self._pairs.items()],
            "destination_sources": [[dst, [[src, to_epoch_us(t)] for src, t in sources.items()]]
                                    for dst, sources in self._dst_sources.items()],
        }

    def load_state_dict(self, state: dict[str, Any]) -> None:
        """Restore ``state_dict()`` output; the pair limits of this instance apply."""
        self.reset()
        for src, dst, dport, entries in state["pairs"][-self.max_pairs:]:
            history = deque(((from_epoch_us(t), int(up), bool(tls)) for t, up, tls in entries),
                            maxlen=self.max_per_pair)
            self._pairs[(src, dst, dport)] = history
        for dst, sources in state["destination_sources"][-self.max_pairs:]:
            self._dst_sources[dst] = {src: from_epoch_us(t) for src, t in sources}

    def extract(self, flows: list[NormalisedFlow], window: WindowContext | None = None) -> dict[str, Any]:
        touched: set[tuple] = set()
        for f in sorted(flows, key=lambda x: x.timestamp):
            if f.event_id in self._seen or f.direction == FlowDirection.INBOUND:
                continue
            self._remember(f.event_id)
            key = (f.source_ip, f.destination_ip, f.destination_port)
            self._add(key, f)
            touched.add(key)

        now = max((f.timestamp for f in flows), default=None)
        candidates = []
        for key in touched:
            if key not in self._pairs:        # evicted by the pair limit within this window
                continue
            candidate = self._profile(key, now)
            if candidate is not None:
                candidates.append(candidate)
        candidates.sort(key=lambda c: (c.interval_cv, -c.connection_count))
        candidates = candidates[:_MAX_CANDIDATES]

        features: dict[str, Any] = {name: 0 for name in self.feature_names}
        features.update(top_beacon_src_ip=None, top_beacon_dst_ip=None, beacon_candidates=[],
                        tracked_pairs=len(self._pairs))
        if not candidates:
            return features
        top = candidates[0]
        features.update(
            candidate_beacon_pairs=len(candidates),
            top_beacon_interval_mean=round(top.interval_mean_sec, 4),
            top_beacon_interval_std=round(top.interval_std_sec, 4),
            top_beacon_interval_cv=round(top.interval_cv, 4),
            top_beacon_periodicity_score=round(top.periodicity, 4),
            top_beacon_size_regularity=round(top.size_regularity, 4),
            top_beacon_connection_count=top.connection_count,
            top_beacon_src_ip=top.source_ip,
            top_beacon_dst_ip=top.destination_ip,
            avg_beacon_cv=round(sum(c.interval_cv for c in candidates) / len(candidates), 4),
            min_beacon_cv=round(top.interval_cv, 4),
            beacon_candidates=[asdict(c) for c in candidates],
        )
        return features

    # ------------------------------------------------------------ internals

    def _remember(self, event_id: str) -> None:
        self._seen[event_id] = None
        if len(self._seen) > _SEEN_LIMIT:
            self._seen.popitem(last=False)

    def _add(self, key: tuple, f: NormalisedFlow) -> None:
        history = self._pairs.get(key)
        if history is None:
            if len(self._pairs) >= self.max_pairs:
                self._pairs.popitem(last=False)
            history = self._pairs[key] = deque(maxlen=self.max_per_pair)
        else:
            self._pairs.move_to_end(key)
        upload = f.orig_bytes if f.orig_bytes is not None else f.byte_count
        history.append((f.timestamp, upload, bool(f.tls_version) or f.destination_port in (443, 8443)))

        sources = self._dst_sources.get(f.destination_ip)
        if sources is None:
            if len(self._dst_sources) >= self.max_pairs:
                self._dst_sources.popitem(last=False)
            sources = self._dst_sources[f.destination_ip] = {}
        else:
            self._dst_sources.move_to_end(f.destination_ip)
        sources[f.source_ip] = f.timestamp

    def _profile(self, key: tuple, now: Optional[datetime]) -> Optional[BeaconCandidate]:
        history = self._pairs[key]
        if now is not None:
            while history and now - history[0][0] > self.history:
                history.popleft()
        if len(history) < self.min_connections:
            return None
        times = sorted(h[0] for h in history)
        intervals = [(b - a).total_seconds() for a, b in zip(times, times[1:])]
        intervals = [i for i in intervals if i > 0]
        if len(intervals) < self.min_connections - 1:
            return None
        mean = sum(intervals) / len(intervals)
        std = math.sqrt(sum((i - mean) ** 2 for i in intervals) / len(intervals))
        median = sorted(intervals)[len(intervals) // 2]
        periodicity = sum(1 for i in intervals if abs(i - median) <= 0.2 * median) / len(intervals)

        src, dst, dport = key
        sources = self._dst_sources.get(dst, {})
        if now is not None:
            for s in [s for s, seen in sources.items() if now - seen > self.history]:
                del sources[s]
        return BeaconCandidate(
            source_ip=src,
            destination_ip=dst,
            destination_port=dport,
            connection_count=len(times),
            interval_mean_sec=mean,
            interval_std_sec=std,
            interval_cv=std / mean if mean > 0 else 0.0,
            periodicity=periodicity,
            size_regularity=max(0.0, 1.0 - _cv([float(h[1]) for h in history])),
            span_sec=(times[-1] - times[0]).total_seconds(),
            destination_sources=len(sources),
            uses_tls=any(h[2] for h in history),
        )
