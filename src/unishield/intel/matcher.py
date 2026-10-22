"""
UniShield — Threat-intelligence matcher

An in-memory snapshot of the active indicators, built from the intel store
when a run starts or after an import. Lookups:

    match_ip(ip)       exact addresses and containing networks
    match_domain(name) the name and its parent domains
    ja3_labels()       JA3 fingerprints for the encrypted-session blocklist

With ``security.anonymize_ips`` on, flows carry salted address hashes, so
exact addresses are hashed with the same salt; networks cannot be matched
against hashes and are reported as inactive.

SECURITY CONSTRAINTS:
    - Pure computation over indicators already imported. No lookups, no network I/O.
"""

from __future__ import annotations

import hashlib
import ipaddress
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Iterable, Optional

from unishield.schemas.timeutil import utc_now

_CACHE_LIMIT = 65_536


@dataclass(frozen=True)
class IntelEntry:
    """An active indicator with its provenance."""
    source: str
    kind: str
    value: str
    label: str = ""
    expires_at: Optional[datetime] = None
    severity: Optional[str] = None
    techniques: tuple[str, ...] = ()

    def active(self, now: datetime) -> bool:
        return self.expires_at is None or self.expires_at > now

    def to_evidence(self, field: str, observed: str) -> dict[str, Any]:
        return {
            "field": field,
            "observed": observed,
            "kind": self.kind,
            "indicator": self.value,
            "source": self.source,
            "label": self.label,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
        }


def hash_ip(ip: str, salt: str) -> str:
    """Same salted hash as NormalisedFlow.to_anonymised."""
    return hashlib.sha256(f"{salt}:{ip}".encode()).hexdigest()[:16]


class IntelMatcher:
    """Lookups over a fixed set of indicators (thread-safe for concurrent reads)."""

    def __init__(self, entries: Iterable[IntelEntry] = (), anonymize_salt: Optional[str] = None):
        self._anonymized = anonymize_salt is not None
        self._ips: dict[str, list[IntelEntry]] = defaultdict(list)
        self._nets: dict[tuple[int, int], dict[int, list[IntelEntry]]] = defaultdict(lambda: defaultdict(list))
        self._domains: dict[str, list[IntelEntry]] = defaultdict(list)
        self._ja3: dict[str, list[IntelEntry]] = defaultdict(list)
        self.counts = {"ip": 0, "cidr": 0, "domain": 0, "ja3": 0}
        self.inactive_cidrs = 0
        for e in entries:
            if e.kind == "ip":
                self._ips[hash_ip(e.value, anonymize_salt) if self._anonymized else e.value].append(e)
            elif e.kind == "cidr":
                if self._anonymized:
                    self.inactive_cidrs += 1
                    continue
                net = ipaddress.ip_network(e.value)
                self._nets[(net.version, net.prefixlen)][int(net.network_address)].append(e)
            elif e.kind == "domain":
                self._domains[e.value].append(e)
            elif e.kind == "ja3":
                self._ja3[e.value].append(e)
            else:
                continue
            self.counts[e.kind] += 1
        self._ip_cache: dict[str, tuple[IntelEntry, ...]] = {}
        self._domain_cache: dict[str, tuple[IntelEntry, ...]] = {}

    @property
    def empty(self) -> bool:
        return not any(self.counts.values())

    @property
    def size(self) -> int:
        return sum(self.counts.values())

    @property
    def anonymized(self) -> bool:
        return self._anonymized

    @staticmethod
    def _active(entries: tuple[IntelEntry, ...], now: Optional[datetime]) -> list[IntelEntry]:
        now = now or utc_now()
        return [e for e in entries if e.active(now)]

    def match_ip(self, ip: Optional[str], now: Optional[datetime] = None) -> list[IntelEntry]:
        if not ip or (not self._ips and not self._nets):
            return []
        found = self._ip_cache.get(ip)
        if found is None:
            hits = list(self._ips.get(ip, ()))
            if self._nets:
                try:
                    addr = ipaddress.ip_address(ip)
                except ValueError:
                    addr = None
                if addr is not None:
                    value = int(addr)
                    for (version, prefix), nets in self._nets.items():
                        if version == addr.version:
                            shift = addr.max_prefixlen - prefix
                            hits.extend(nets.get((value >> shift) << shift, ()))
            found = tuple(hits)
            if len(self._ip_cache) >= _CACHE_LIMIT:
                self._ip_cache.clear()
            self._ip_cache[ip] = found
        return self._active(found, now) if found else []

    def match_domain(self, name: Optional[str], now: Optional[datetime] = None) -> list[IntelEntry]:
        if not name or not self._domains:
            return []
        key = name.lower().rstrip(".")
        found = self._domain_cache.get(key)
        if found is None:
            labels = key.split(".")
            hits: list[IntelEntry] = []
            for i in range(0, max(len(labels) - 1, 0)):
                hits.extend(self._domains.get(".".join(labels[i:]), ()))
            found = tuple(hits)
            if len(self._domain_cache) >= _CACHE_LIMIT:
                self._domain_cache.clear()
            self._domain_cache[key] = found
        return self._active(found, now) if found else []

    def match_ja3(self, value: Optional[str], now: Optional[datetime] = None) -> list[IntelEntry]:
        if not value:
            return []
        return self._active(tuple(self._ja3.get(value.lower(), ())), now)

    def ja3_labels(self, now: Optional[datetime] = None) -> dict[str, str]:
        """{fingerprint: "source: label"} of the active JA3 indicators."""
        now = now or utc_now()
        out = {}
        for value, entries in self._ja3.items():
            active = [e for e in entries if e.active(now)]
            if active:
                out[value] = "; ".join(f"{e.source}: {e.label}" if e.label else e.source for e in active)
        return out

