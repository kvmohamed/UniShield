"""
UniShield — Exfiltration Feature Extractor

Profiles what internal hosts upload. For every internal source → external
destination pair in the window it measures the bytes the internal host sent
on connections it initiated (``orig_bytes`` of outbound flows), what it
downloaded on them, ports, session length and TLS use.

State kept across windows (bounded):
    - per source: its upload total in recent windows where it uploaded
      (``baseline_windows`` values) → median, MAD and a robust z-score for
      the current window
    - per destination: which internal sources uploaded to it within
      ``history_sec`` (destination rarity)

Replies from internal servers to inbound requests are not uploads: serving
content is not exfiltration evidence. Flows without a direction fall back to
a port heuristic (higher source port → likely an outbound client).

Uploads to destinations whose asset role makes them expected (by default a
``backup_server``, see ``unishield.assets``) are still profiled as
candidates, marked ``expected_destination``, but are left out of the
source's window total and baseline: a nightly backup neither inflates the
source's history nor makes its other uploads look anomalous.

SECURITY CONSTRAINTS:
    - Read-only computation over local flow records.
    - No network communication or payload inspection.
"""

from __future__ import annotations

from collections import OrderedDict, defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Optional

from unishield.assets import AssetInventory
from unishield.config import get_thresholds
from unishield.features.base import BaseFeatureExtractor, WindowContext
from unishield.schemas.alert import ThreatClass
from unishield.schemas.flow import FlowDirection, NormalisedFlow
from unishield.schemas.timeutil import from_epoch_us, to_epoch_us

WELL_KNOWN_PORTS = frozenset({21, 22, 25, 53, 80, 110, 123, 143, 443, 587, 993, 995, 8080, 8443})
_MIN_CANDIDATE_UPLOAD = 100_000          # bytes; smaller pairs are not profiled
_MAX_CANDIDATES = 10
_MAD_FLOOR_BYTES = 50_000


@dataclass
class _Pair:
    upload: int = 0
    download: int = 0
    flows: int = 0
    ports: set = field(default_factory=set)
    max_duration: float = 0.0
    long_session_upload: int = 0
    tls: bool = False


def _upload_download(f: NormalisedFlow) -> Optional[tuple[int, int]]:
    """(uploaded, downloaded) bytes if the flow is an internal host's outbound connection."""
    split = f.orig_bytes is not None and f.resp_bytes is not None
    outbound = f.direction == FlowDirection.OUTBOUND or (
        f.direction == FlowDirection.UNKNOWN and f.source_port and f.destination_port
        and f.source_port > f.destination_port
    )
    if not outbound:
        return None
    return (f.orig_bytes, f.resp_bytes) if split else (f.byte_count, 0)


def robust_z(value: float, history: list[float]) -> tuple[float, float, float]:
    """(z, median, MAD) of ``value`` against ``history`` using the median absolute deviation."""
    ordered = sorted(history)
    median = ordered[len(ordered) // 2]
    mad = sorted(abs(v - median) for v in history)[len(history) // 2]
    scale = 1.4826 * max(mad, _MAD_FLOOR_BYTES, 0.05 * median)
    return (value - median) / scale, median, mad


class ExfiltrationFeatureExtractor(BaseFeatureExtractor):
    """Extract per-pair upload features with per-source baselines."""

    def __init__(self, baseline_windows: int = 60, history_sec: float | None = None,
                 long_session_sec: float | None = None, max_tracked: int = 50_000,
                 assets: AssetInventory | None = None):
        t = get_thresholds().get("exfiltration", {})
        self.assets = assets if assets is not None else AssetInventory.from_config()
        self.baseline_windows = baseline_windows
        self.history = timedelta(seconds=history_sec or t.get("history_sec", 7200))
        self.long_session_sec = long_session_sec or t.get("long_session_duration_sec", 3600)
        self.max_tracked = max_tracked
        self._baselines: OrderedDict[str, deque] = OrderedDict()
        self._uploaders: OrderedDict[str, dict[str, datetime]] = OrderedDict()

    @property
    def name(self) -> str:
        return "exfiltration"

    @property
    def feature_names(self) -> list[str]:
        return [
            "total_outbound_bytes",
            "total_inbound_bytes",
            "outbound_inbound_ratio",
            "max_session_bytes",
            "max_session_duration_sec",
            "long_sessions_count",
            "high_volume_destinations",
            "top_dest_ip",
            "top_dest_bytes",
            "avg_bytes_per_dest",
            "dest_port_rarity",
            "unusual_port_flows",
            "expected_upload_bytes",
            "exfil_candidates",
        ]

    def reset(self) -> None:
        self._baselines.clear()
        self._uploaders.clear()

    def state_dict(self) -> dict[str, Any]:
        """Per-source upload baselines and per-destination uploaders, JSON-serialisable."""
        return {
            "baselines": [[src, list(history)] for src, history in self._baselines.items()],
            "uploaders": [[dst, [[src, to_epoch_us(t)] for src, t in sources.items()]]
                          for dst, sources in self._uploaders.items()],
        }

    def load_state_dict(self, state: dict[str, Any]) -> None:
        """Restore ``state_dict()`` output; this instance's baseline length and limits apply."""
        self.reset()
        for src, values in state["baselines"][-self.max_tracked:]:
            self._baselines[src] = deque((float(v) for v in values), maxlen=self.baseline_windows)
        for dst, sources in state["uploaders"][-self.max_tracked:]:
            self._uploaders[dst] = {src: from_epoch_us(t) for src, t in sources}

    def extract(self, flows: list[NormalisedFlow], window: WindowContext | None = None) -> dict[str, Any]:
        empty: dict[str, Any] = {name: 0 for name in self.feature_names}
        empty.update(top_dest_ip=None, exfil_candidates=[])
        if not flows:
            return empty

        outbound = inbound = 0
        pairs: dict[tuple[str, str], _Pair] = defaultdict(_Pair)
        source_upload: dict[str, int] = defaultdict(int)
        dest_upload: dict[str, int] = defaultdict(int)
        expected: dict[str, bool] = {}
        expected_upload = 0
        unusual_port_flows = 0
        for f in flows:
            split = f.orig_bytes is not None and f.resp_bytes is not None
            ud = _upload_download(f)
            if ud is None:
                if f.direction == FlowDirection.INBOUND:
                    inbound += f.orig_bytes if split else f.byte_count
                continue
            up, down = ud
            outbound += up
            inbound += down
            p = pairs[(f.source_ip, f.destination_ip)]
            p.upload += up
            p.download += down
            p.flows += 1
            if f.destination_port is not None:
                p.ports.add(f.destination_port)
                if f.destination_port not in WELL_KNOWN_PORTS and f.destination_port > 1024:
                    unusual_port_flows += 1
            duration = f.duration or 0.0
            p.max_duration = max(p.max_duration, duration)
            if duration >= self.long_session_sec:
                p.long_session_upload += up
            p.tls = p.tls or bool(f.tls_version) or f.destination_port in (443, 8443)
            dest_upload[f.destination_ip] += up
            if f.destination_ip not in expected:
                expected[f.destination_ip] = self.assets.expected_destination(
                    f.destination_ip, ThreatClass.DATA_EXFILTRATION)
            if expected[f.destination_ip]:
                expected_upload += up              # kept out of the source total and baseline
            else:
                source_upload[f.source_ip] += up

        now = max(f.timestamp for f in flows)
        candidates = [self._candidate(src, dst, p, source_upload[src], now, expected.get(dst, False))
                      for (src, dst), p in pairs.items() if p.upload >= _MIN_CANDIDATE_UPLOAD]
        candidates.sort(key=lambda c: c["upload_bytes"], reverse=True)

        # Update state only after profiling, so the baseline excludes the current window.
        for src, up in source_upload.items():
            if up > 0:
                self._baseline(src).append(float(up))
        for (src, dst), p in pairs.items():
            if p.upload > 0:
                self._uploader_set(dst)[src] = now

        top_dest = max(dest_upload.items(), key=lambda kv: kv[1], default=(None, 0))
        outbound_flows = sum(p.flows for p in pairs.values())
        return {
            "total_outbound_bytes": outbound,
            "total_inbound_bytes": inbound,
            "outbound_inbound_ratio": round(outbound / max(inbound, 1), 4),
            "max_session_bytes": max((f.byte_count for f in flows), default=0),
            "max_session_duration_sec": round(max((f.duration or 0.0 for f in flows), default=0.0), 2),
            "long_sessions_count": sum(1 for f in flows if (f.duration or 0) >= self.long_session_sec),
            "high_volume_destinations": sum(1 for b in dest_upload.values() if b > 10_000_000),
            "top_dest_ip": top_dest[0],
            "top_dest_bytes": top_dest[1],
            "avg_bytes_per_dest": round(sum(dest_upload.values()) / max(len(dest_upload), 1), 2),
            "dest_port_rarity": round(unusual_port_flows / max(outbound_flows, 1), 4),
            "unusual_port_flows": unusual_port_flows,
            "expected_upload_bytes": expected_upload,
            "exfil_candidates": candidates[:_MAX_CANDIDATES],
        }

    # ------------------------------------------------------------ internals

    def _baseline(self, src: str) -> deque:
        history = self._baselines.get(src)
        if history is None:
            if len(self._baselines) >= self.max_tracked:
                self._baselines.popitem(last=False)
            history = self._baselines[src] = deque(maxlen=self.baseline_windows)
        else:
            self._baselines.move_to_end(src)
        return history

    def _uploader_set(self, dst: str) -> dict[str, datetime]:
        uploaders = self._uploaders.get(dst)
        if uploaders is None:
            if len(self._uploaders) >= self.max_tracked:
                self._uploaders.popitem(last=False)
            uploaders = self._uploaders[dst] = {}
        else:
            self._uploaders.move_to_end(dst)
        return uploaders

    def _candidate(self, src: str, dst: str, p: _Pair, source_total: int, now: datetime,
                   expected_destination: bool) -> dict[str, Any]:
        history = list(self._baselines.get(src, ()))
        z = median = mad = None
        if history:
            z, median, mad = robust_z(float(source_total), history)
        uploaders = self._uploaders.get(dst, {})
        recent = {s for s, seen in uploaders.items() if now - seen <= self.history} | {src}
        return {
            "source_ip": src,
            "destination_ip": dst,
            "upload_bytes": p.upload,
            "download_bytes": p.download,
            "upload_download_ratio": round(p.upload / max(p.download, 1), 2),
            "flows": p.flows,
            "destination_ports": sorted(x for x in p.ports)[:5],
            "unusual_port": any(x not in WELL_KNOWN_PORTS and x > 1024 for x in p.ports),
            "max_duration_sec": round(p.max_duration, 1),
            "long_session_upload_bytes": p.long_session_upload,
            "uses_tls": p.tls,
            "source_window_upload": source_total,
            "baseline_windows": len(history),
            "baseline_median_bytes": round(median, 1) if median is not None else None,
            "baseline_mad_bytes": round(mad, 1) if mad is not None else None,
            "robust_z": round(z, 2) if z is not None else None,
            "destination_sources": len(recent),
            "expected_destination": expected_destination,
        }
