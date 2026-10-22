"""
UniShield — Encrypted-Session Feature Extractor (optional advanced module)

Profiles TLS sessions from handshake metadata only: the negotiated or
offered protocol version, the client's JA3 fingerprint, the destination
port and the session's duration and byte rate. Payloads are never
inspected and nothing is decrypted.

For every client → server → port triple with TLS metadata in the window it
reports:
    - outdated protocol versions seen (``outdated_versions``)
    - JA3 fingerprints and whether any is on the operator's blocklist
      (``ja3_blocklist`` plus JA3 indicators imported as threat intelligence)
    - whether the port is a usual TLS port
    - the longest session and its average byte rate

SECURITY CONSTRAINTS:
    - Read-only computation over local flow records.
    - No decryption, no payload inspection, no network communication.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any, Iterable

from unishield.config import get_thresholds
from unishield.features.base import BaseFeatureExtractor, WindowContext
from unishield.schemas.flow import NormalisedFlow

#: Ports where TLS is expected (HTTPS, mail, LDAP, DNS-over-TLS, SIP, XMPP, ...).
TLS_PORTS = frozenset({443, 465, 563, 636, 853, 989, 990, 992, 993, 994, 995, 5061, 5223, 8443})
_MAX_CANDIDATES = 20


def _normalise_hashes(values: Iterable[str] | dict | None) -> dict[str, str]:
    """Blocklist as {lower-case hash: label}; accepts a list of hashes or a mapping."""
    if not values:
        return {}
    if isinstance(values, dict):
        return {str(k).lower(): str(v) for k, v in values.items()}
    return {str(v).lower(): "blocklisted" for v in values}


class EncryptedSessionFeatureExtractor(BaseFeatureExtractor):
    """Extract per-session TLS metadata features (no decryption)."""

    def __init__(self, thresholds: dict[str, Any] | None = None, extra_ja3: dict[str, str] | None = None):
        """``extra_ja3``: {fingerprint: label} from imported threat intelligence, added to ``ja3_blocklist``."""
        t = thresholds if thresholds is not None else get_thresholds().get("encrypted", {})
        self.outdated_versions = frozenset(t.get("outdated_tls_versions", ["SSLv3", "TLSv1.0", "TLSv1.1"]))
        self.ja3_blocklist = {**_normalise_hashes(extra_ja3), **_normalise_hashes(t.get("ja3_blocklist"))}
        self.tls_ports = frozenset(t.get("tls_ports", TLS_PORTS))

    @property
    def name(self) -> str:
        return "encrypted_session_features"

    @property
    def feature_names(self) -> list[str]:
        return ["tls_flow_count", "tls_outdated_count", "tls_unusual_port_count",
                "tls_distinct_ja3", "tls_candidates"]

    def extract(self, flows: list[NormalisedFlow], window: WindowContext | None = None) -> dict[str, Any]:
        groups: dict[tuple[str, str, int | None], list[NormalisedFlow]] = defaultdict(list)
        for f in flows:
            if f.tls_version or f.ja3:
                groups[(f.source_ip, f.destination_ip, f.destination_port)].append(f)

        candidates = []
        outdated_total = unusual_total = 0
        all_ja3: set[str] = set()
        for (src, dst, port), group in groups.items():
            versions = sorted({f.tls_version for f in group if f.tls_version})
            outdated = [v for v in versions if v in self.outdated_versions]
            ja3s = sorted({f.ja3.lower() for f in group if f.ja3})
            all_ja3.update(ja3s)
            blocked = {h: self.ja3_blocklist[h] for h in ja3s if h in self.ja3_blocklist}
            unusual_port = port is not None and port not in self.tls_ports
            longest = max(group, key=lambda f: f.duration or 0.0)
            duration = longest.duration or 0.0
            rate = (longest.byte_count / duration) if duration > 0 else None
            outdated_total += sum(1 for f in group if f.tls_version in self.outdated_versions)
            unusual_total += len(group) if unusual_port else 0
            candidates.append({
                "source_ip": src,
                "destination_ip": dst,
                "destination_port": port,
                "flows": len(group),
                "tls_versions": versions,
                "outdated_versions": outdated,
                "ja3": ja3s,
                "blocklisted_ja3": blocked,
                "unusual_port": unusual_port,
                "max_duration_sec": round(duration, 3),
                "max_session_bytes_per_sec": round(rate, 2) if rate is not None else None,
            })

        def interest(c):
            return (bool(c["blocklisted_ja3"]), bool(c["outdated_versions"]), c["unusual_port"],
                    c["max_duration_sec"])

        candidates.sort(key=interest, reverse=True)
        return {
            "tls_flow_count": sum(len(g) for g in groups.values()),
            "tls_outdated_count": outdated_total,
            "tls_unusual_port_count": unusual_total,
            "tls_distinct_ja3": len(all_ja3),
            "tls_candidates": candidates[:_MAX_CANDIDATES],
        }
