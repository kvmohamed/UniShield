"""
UniShield — Service-Abuse Feature Extractor (brute force, spam)

Two behaviours that one 10-second window is too short to judge, so recent
history is kept across windows (bounded):

Brute force — one source opening many short, small connections to the same
login service on one host (SSH, FTP, Telnet, RDP, SMB, LDAP, mail login,
databases, VNC). For every (source, destination, port) on an
authentication port it keeps the start times of qualifying connections
(duration <= ``max_session_sec``, bytes <= ``max_session_bytes``) within
``horizon_sec`` and reports the pairs with the most attempts. A port scan
touches many ports; a login attempt repeats one.

Spam — an internal host opening SMTP connections (``smtp_ports``, port 25)
to many different external mail servers. A normal client sends through one
relay; only mail servers deliver directly to many. For every source it keeps
the external SMTP destinations seen within ``spam_horizon_sec`` and reports
the sources with the most. Flows from the outside in, and internal ones, are
ignored.

SECURITY CONSTRAINTS:
    - Read-only computation over local flow records; no payload inspection,
      nothing is decrypted (whether a login succeeded is not known).
"""

from __future__ import annotations

from collections import OrderedDict, deque
from datetime import datetime, timedelta
from typing import Any, Optional

from unishield.config import get_thresholds
from unishield.features.base import BaseFeatureExtractor, WindowContext
from unishield.features.scan import is_failed
from unishield.schemas.flow import FlowDirection, NormalisedFlow, ProtocolType
from unishield.schemas.timeutil import from_epoch_us, to_epoch_us

DEFAULT_AUTH_PORTS = (21, 22, 23, 110, 143, 389, 445, 993, 995, 1433, 3306, 3389, 5432, 5900)
_MAX_CANDIDATES = 10


class ServiceAbuseFeatureExtractor(BaseFeatureExtractor):
    """Rolling per-pair login-attempt and per-source SMTP-fan-out profiles."""

    def __init__(self, thresholds: dict[str, Any] | None = None, max_pairs: int = 50_000,
                 max_per_pair: int = 2_000, max_sources: int = 20_000):
        t = thresholds if thresholds is not None else get_thresholds()
        bf, spam = t.get("brute_force", {}), t.get("spam", {})
        self.auth_ports = frozenset(bf.get("auth_ports", DEFAULT_AUTH_PORTS))
        self.horizon = timedelta(seconds=bf.get("horizon_sec", 60))
        self.max_session_sec = float(bf.get("max_session_sec", 30))
        self.max_session_bytes = int(bf.get("max_session_bytes", 20_000))
        self.smtp_ports = frozenset(spam.get("smtp_ports", (25,)))
        self.spam_horizon = timedelta(seconds=spam.get("horizon_sec", 300))
        self.max_pairs, self.max_per_pair, self.max_sources = max_pairs, max_per_pair, max_sources
        self._attempts: OrderedDict[tuple[str, str, int], deque] = OrderedDict()   # -> (time, failed)
        self._smtp: OrderedDict[str, dict[str, datetime]] = OrderedDict()          # src -> dst -> last seen
        self._smtp_failed: dict[str, deque] = {}                                   # src -> (time, failed)

    @property
    def name(self) -> str:
        return "service_abuse_features"

    @property
    def feature_names(self) -> list[str]:
        return ["bruteforce_candidates", "spam_candidates", "auth_attempt_pairs", "smtp_sources"]

    def reset(self) -> None:
        self._attempts.clear()
        self._smtp.clear()
        self._smtp_failed.clear()

    # --- classification ------------------------------------------------------

    def _login_attempt(self, f: NormalisedFlow) -> bool:
        """A short, small TCP connection to a login service, in either direction."""
        return (f.protocol == ProtocolType.TCP and f.destination_port in self.auth_ports
                and (f.duration or 0.0) <= self.max_session_sec and f.byte_count <= self.max_session_bytes)

    def _smtp_delivery(self, f: NormalisedFlow) -> bool:
        return (f.protocol == ProtocolType.TCP and f.destination_port in self.smtp_ports
                and f.direction in (FlowDirection.OUTBOUND, FlowDirection.UNKNOWN))

    # --- extraction ------------------------------------------------------------

    def extract(self, flows: list[NormalisedFlow], window: WindowContext | None = None) -> dict[str, Any]:
        latest: Optional[datetime] = None
        touched_pairs, touched_sources = set(), set()
        for f in flows:
            latest = f.timestamp if latest is None or f.timestamp > latest else latest
            if f.destination_port is None:
                continue
            if self._login_attempt(f):
                key = (f.source_ip, f.destination_ip, f.destination_port)
                history = self._attempts.get(key)
                if history is None:
                    history = self._attempts[key] = deque(maxlen=self.max_per_pair)
                history.append((f.timestamp, is_failed(f)))
                self._attempts.move_to_end(key)
                touched_pairs.add(key)
            elif self._smtp_delivery(f):
                dests = self._smtp.setdefault(f.source_ip, {})
                dests[f.destination_ip] = max(f.timestamp, dests.get(f.destination_ip, f.timestamp))
                self._smtp.move_to_end(f.source_ip)
                self._smtp_failed.setdefault(f.source_ip, deque(maxlen=self.max_per_pair)).append(
                    (f.timestamp, is_failed(f)))
                touched_sources.add(f.source_ip)
        now = window.end if window is not None else latest
        if now is not None:
            self._expire(now)
        while len(self._attempts) > self.max_pairs:
            self._attempts.popitem(last=False)
        while len(self._smtp) > self.max_sources:
            src, _ = self._smtp.popitem(last=False)
            self._smtp_failed.pop(src, None)

        brute = []
        for key in touched_pairs:
            history = self._attempts.get(key)
            if not history:
                continue
            times = [t for t, _ in history]
            span = (max(times) - min(times)).total_seconds()
            brute.append({
                "source_ip": key[0], "destination_ip": key[1], "destination_port": key[2],
                "attempts": len(history), "failed": sum(1 for _, failed in history if failed),
                "span_sec": round(span, 1),
                "rate_per_min": round(60.0 * len(history) / max(span, 1.0), 1),
            })
        brute.sort(key=lambda c: -c["attempts"])

        spam = []
        for src in touched_sources:
            dests = self._smtp.get(src) or {}
            attempts = self._smtp_failed.get(src) or ()
            spam.append({
                "source_ip": src, "smtp_destinations": len(dests), "smtp_connections": len(attempts),
                "failed": sum(1 for _, failed in attempts if failed),
                "examples": sorted(dests)[:5],
            })
        spam.sort(key=lambda c: -c["smtp_destinations"])
        return {
            "bruteforce_candidates": brute[:_MAX_CANDIDATES],
            "spam_candidates": spam[:_MAX_CANDIDATES],
            "auth_attempt_pairs": len(self._attempts),
            "smtp_sources": len(self._smtp),
        }

    def _expire(self, now: datetime) -> None:
        cutoff = now - self.horizon
        for key in list(self._attempts):
            history = self._attempts[key]
            while history and history[0][0] < cutoff:
                history.popleft()
            if not history:
                del self._attempts[key]
        spam_cutoff = now - self.spam_horizon
        for src in list(self._smtp):
            dests = {d: t for d, t in self._smtp[src].items() if t >= spam_cutoff}
            attempts = self._smtp_failed.get(src)
            while attempts and attempts[0][0] < spam_cutoff:
                attempts.popleft()
            if dests:
                self._smtp[src] = dests
            else:
                del self._smtp[src]
                self._smtp_failed.pop(src, None)

    # --- restart-safe state -----------------------------------------------------

    def state_dict(self) -> dict[str, Any]:
        return {
            "attempts": [[s, d, p, [[to_epoch_us(t), bool(x)] for t, x in h]]
                         for (s, d, p), h in self._attempts.items()],
            "smtp": [[s, [[d, to_epoch_us(t)] for d, t in dests.items()],
                      [[to_epoch_us(t), bool(x)] for t, x in self._smtp_failed.get(s, ())]]
                     for s, dests in self._smtp.items()],
        }

    def load_state_dict(self, state: dict[str, Any]) -> None:
        self.reset()
        for s, d, p, history in state["attempts"][-self.max_pairs:]:
            self._attempts[(s, d, int(p))] = deque(((from_epoch_us(t), bool(x)) for t, x in history),
                                                   maxlen=self.max_per_pair)
        for s, dests, attempts in state["smtp"][-self.max_sources:]:
            self._smtp[s] = {d: from_epoch_us(t) for d, t in dests}
            self._smtp_failed[s] = deque(((from_epoch_us(t), bool(x)) for t, x in attempts), maxlen=self.max_per_pair)
