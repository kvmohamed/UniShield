"""
UniShield — Read-Only Normalisation Layer

Applied to every record after ingest (and after sessionization for
packet-level input), before windowing:

    1. Infer direction from the configured home networks, unless the
       source already supplied one.
    2. Fill derived fields (DNS query length) and normalise naming
       (TLS version strings from different sources).
    3. Optionally replace IP addresses with salted hashes. This runs
       last so direction inference still sees real addresses. Hashing
       keeps per-address consistency but prevents subnet reasoning,
       which affects correlation and evaluation.

SECURITY CONSTRAINTS:
    - Pure computation on records already read. No lookups, no network I/O.
"""

from __future__ import annotations

import ipaddress
import logging
import re
from typing import Iterable, Iterator, Optional

from unishield.ingest.base import ClockTick
from unishield.schemas.flow import FlowDirection, NormalisedFlow

logger = logging.getLogger("unishield.processing.normalization")

_TLS_NAMES = {
    "SSLV2": "SSLv2",
    "SSLV3": "SSLv3",
    "TLSV10": "TLSv1.0",
    "TLSV11": "TLSv1.1",
    "TLSV12": "TLSv1.2",
    "TLSV13": "TLSv1.3",
}


def normalize_tls_version(value: Optional[str]) -> Optional[str]:
    """
    Map TLS version spellings to one form: Zeek's 'TLSv12', 'TLS 1.2',
    'tlsv1.2' and 'TLSv1.2' all become 'TLSv1.2'. Unknown values are
    returned unchanged (stripped); empty values become None.
    """
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    key = re.sub(r"[\s._-]", "", text).upper()
    if key in ("TLSV1", "TLS1"):
        key = "TLSV10"
    key = key.replace("TLS1", "TLSV1") if key.startswith("TLS1") else key
    return _TLS_NAMES.get(key, text)


class Normalizer:
    """Direction inference, field normalisation and optional anonymisation."""

    _CACHE_LIMIT = 65_536

    def __init__(
        self,
        home_networks: Iterable[str] | None = None,
        anonymize: bool = False,
        salt: str = "",
    ):
        self._networks = [ipaddress.ip_network(n, strict=False) for n in (home_networks or [])]
        self._anonymize = anonymize
        self._salt = salt
        self._home_cache: dict[str, Optional[bool]] = {}
        self.records_in = 0
        self.directions_inferred = 0

        if anonymize and salt in ("", "change-this-salt", "change-this-salt-in-production"):
            logger.warning("IP anonymisation is on with a default or empty salt; set ip_hash_salt")

    @classmethod
    def from_config(cls, config=None) -> "Normalizer":
        """Build from the application config (network + security sections)."""
        if config is None:
            from unishield.config import get_config
            config = get_config()
        return cls(
            home_networks=config.network.home_networks,
            anonymize=config.security.anonymize_ips,
            salt=config.security.ip_hash_salt,
        )

    def is_home(self, ip: str) -> Optional[bool]:
        """True/False for real addresses; None when it cannot be decided (hashed IP)."""
        cached = self._home_cache.get(ip, ...)
        if cached is not ...:
            return cached
        try:
            addr = ipaddress.ip_address(ip)
            result: Optional[bool] = any(addr in net for net in self._networks)
        except ValueError:
            result = None
        if len(self._home_cache) >= self._CACHE_LIMIT:
            self._home_cache.clear()
        self._home_cache[ip] = result
        return result

    def infer_direction(self, source_ip: str, destination_ip: str) -> FlowDirection:
        """Direction relative to the home networks; UNKNOWN if neither end is home."""
        src_home = self.is_home(source_ip)
        dst_home = self.is_home(destination_ip)
        if src_home is None or dst_home is None:
            return FlowDirection.UNKNOWN
        if src_home and dst_home:
            return FlowDirection.INTERNAL
        if src_home:
            return FlowDirection.OUTBOUND
        if dst_home:
            return FlowDirection.INBOUND
        return FlowDirection.UNKNOWN

    def normalize(self, flow: NormalisedFlow) -> NormalisedFlow:
        """Return a normalised copy (or the same object if nothing changes)."""
        self.records_in += 1
        updates: dict = {}

        if flow.direction == FlowDirection.UNKNOWN and self._networks:
            direction = self.infer_direction(flow.source_ip, flow.destination_ip)
            if direction != FlowDirection.UNKNOWN:
                updates["direction"] = direction
                self.directions_inferred += 1

        if flow.dns_query and flow.dns_query_length is None:
            updates["dns_query_length"] = len(flow.dns_query)

        if flow.tls_version:
            tls = normalize_tls_version(flow.tls_version)
            if tls != flow.tls_version:
                updates["tls_version"] = tls

        if updates:
            flow = flow.model_copy(update=updates)
        if self._anonymize:
            flow = flow.to_anonymised(self._salt)
        return flow

    def normalize_stream(self, flows: Iterable[NormalisedFlow]) -> Iterator[NormalisedFlow]:
        """Normalise records lazily, preserving order; live readers' clock ticks pass through."""
        for flow in flows:
            yield flow if isinstance(flow, ClockTick) else self.normalize(flow)

    def stats(self) -> dict:
        return {
            "records_in": self.records_in,
            "directions_inferred": self.directions_inferred,
            "anonymize": self._anonymize,
            "home_networks": [str(n) for n in self._networks],
        }
