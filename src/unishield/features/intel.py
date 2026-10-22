"""
UniShield — Threat-Intelligence Feature Extractor

Looks up every flow's addresses and DNS query name in the imported
indicators (IntelMatcher) and groups the hits of a window:

    destination match  per (listed destination, monitored source): a host
                       contacting a listed address
    source match       per listed source: a listed address contacting the
                       monitored network (its peers are listed)
    DNS query match    per (listed domain, client): a host resolving a
                       listed domain or one of its subdomains

Each group carries the matched indicators with their source, label and
expiry (plus any severity and ATT&CK techniques listed with them), flow
and byte counts, peers, destination ports and direction.

SECURITY CONSTRAINTS:
    - Read-only computation over local flow records and imported lists.
    - No lookups and no network communication.
"""

from __future__ import annotations

from collections import Counter
from typing import Any

from unishield.features.base import BaseFeatureExtractor, WindowContext
from unishield.intel.matcher import IntelEntry, IntelMatcher
from unishield.schemas.flow import NormalisedFlow
from unishield.schemas.timeutil import utc_now

_MAX_GROUPS = 50
_MAX_LISTED = 20


class IntelFeatureExtractor(BaseFeatureExtractor):
    """Group flows that involve an imported indicator."""

    def __init__(self, matcher: IntelMatcher | None = None):
        self.matcher = matcher if matcher is not None else IntelMatcher()

    @property
    def name(self) -> str:
        return "intel_features"

    @property
    def feature_names(self) -> list[str]:
        return ["intel_match_count", "intel_matches"]

    def extract(self, flows: list[NormalisedFlow], window: WindowContext | None = None) -> dict[str, Any]:
        if self.matcher.empty or not flows:
            return {"intel_match_count": 0, "intel_matches": []}
        now = utc_now()
        memo: dict[str, list[IntelEntry]] = {}

        def ip_hits(ip: str) -> list[IntelEntry]:
            if ip not in memo:
                memo[ip] = self.matcher.match_ip(ip, now)
            return memo[ip]

        groups: dict[tuple[str, str, str], dict[str, Any]] = {}
        for f in flows:
            hits = ip_hits(f.destination_ip)
            if hits:
                self._add(groups, ("destination_ip", f.destination_ip, f.source_ip), hits, f, f.source_ip)
            hits = ip_hits(f.source_ip)
            if hits:
                self._add(groups, ("source_ip", f.source_ip, ""), hits, f, f.destination_ip)
            if f.dns_query:
                hits = self.matcher.match_domain(f.dns_query, now)
                if hits:
                    self._add(groups, ("dns_query", hits[0].value, f.source_ip), hits, f, f.source_ip,
                              query=f.dns_query)

        matches = [self._summary(key, g) for key, g in groups.items()]
        matches.sort(key=lambda m: (m["flows"], m["bytes"]), reverse=True)
        return {"intel_match_count": len(matches), "intel_matches": matches[:_MAX_GROUPS]}

    @staticmethod
    def _add(groups, key, hits: list[IntelEntry], flow: NormalisedFlow, peer: str, query: str | None = None) -> None:
        g = groups.get(key)
        if g is None:
            g = groups[key] = {"entries": {}, "flows": 0, "bytes": 0, "peers": Counter(), "ports": Counter(),
                               "directions": Counter(), "queries": Counter()}
        for e in hits:
            g["entries"].setdefault((e.source, e.kind, e.value), e)
        g["flows"] += 1
        g["bytes"] += flow.byte_count
        g["peers"][peer] += 1
        if flow.destination_port is not None:
            g["ports"][flow.destination_port] += 1
        g["directions"][flow.direction.value] += 1
        if query:
            g["queries"][query.lower().rstrip(".")] += 1

    @staticmethod
    def _summary(key: tuple[str, str, str], g: dict[str, Any]) -> dict[str, Any]:
        field, observed, _ = key
        entries: list[IntelEntry] = list(g["entries"].values())
        return {
            "field": field,
            "observed": observed,
            "intel_matches": [e.to_evidence(field, observed) for e in entries[:_MAX_LISTED]],
            "sources": sorted({e.source for e in entries}),
            "severities": sorted({e.severity for e in entries if e.severity}),
            "techniques": sorted({t for e in entries for t in e.techniques}),
            "flows": g["flows"],
            "bytes": g["bytes"],
            "peers": [p for p, _ in g["peers"].most_common(_MAX_LISTED)],
            "peer_count": len(g["peers"]),
            "destination_ports": sorted(p for p, _ in g["ports"].most_common(_MAX_LISTED)),
            "direction": g["directions"].most_common(1)[0][0],
            "query_names": [q for q, _ in g["queries"].most_common(_MAX_LISTED)],
        }
