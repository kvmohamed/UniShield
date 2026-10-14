"""
UniShield — DNS Feature Extractor

Extracts DNS-specific features for DGA and DNS tunnelling detection.
Works on DNS query metadata only — no payload decryption.

Features computed:
    - Query length statistics
    - Character entropy of domain names
    - Subdomain depth and uniqueness
    - NXDOMAIN ratio
    - TXT record frequency
    - N-gram anomaly indicators

SECURITY CONSTRAINTS:
    - Read-only: operates on DNS metadata fields only.
    - No DNS resolution or lookups performed.
"""

from __future__ import annotations

import math
from collections import Counter, defaultdict
from typing import Any

from unishield.features.base import BaseFeatureExtractor, WindowContext
from unishield.schemas.flow import NormalisedFlow


def _char_entropy(s: str) -> float:
    """Shannon entropy of character distribution in a string."""
    if not s:
        return 0.0
    counter = Counter(s.lower())
    total = len(s)
    return -sum(
        (c / total) * math.log2(c / total)
        for c in counter.values()
        if c > 0
    )


def _subdomain_depth(domain: str) -> int:
    """Count the number of labels (dots + 1) in a domain."""
    return domain.count(".") + 1 if domain else 0


def _consonant_ratio(s: str) -> float:
    """Ratio of consonants to total alpha characters."""
    alpha_chars = [c for c in s.lower() if c.isalpha()]
    if not alpha_chars:
        return 0.0
    vowels = set("aeiou")
    consonants = sum(1 for c in alpha_chars if c not in vowels)
    return consonants / len(alpha_chars)


class DNSFeatureExtractor(BaseFeatureExtractor):
    """Extract DNS query pattern features."""

    @property
    def name(self) -> str:
        return "dns"

    @property
    def feature_names(self) -> list[str]:
        return [
            "dns_query_count",
            "unique_domains",
            "avg_query_length",
            "max_query_length",
            "avg_domain_entropy",
            "max_domain_entropy",
            "avg_subdomain_depth",
            "max_subdomain_depth",
            "nxdomain_ratio",
            "txt_record_ratio",
            "unique_subdomain_ratio",
            "avg_consonant_ratio",
            "high_entropy_domains",
            "long_query_domains",
        ]

    def extract(self, flows: list[NormalisedFlow], window: WindowContext | None = None) -> dict[str, Any]:
        # Filter to DNS flows only
        dns_flows = [f for f in flows if f.dns_query]

        if not dns_flows:
            return {name: 0 for name in self.feature_names}

        queries = [f.dns_query for f in dns_flows if f.dns_query]
        query_lengths = [len(q) for q in queries]
        entropies = [_char_entropy(q) for q in queries]
        depths = [_subdomain_depth(q) for q in queries]
        consonant_ratios = [_consonant_ratio(q) for q in queries]

        # Unique domains vs total queries
        unique_domains = set(queries)

        # NXDOMAIN ratio (heuristic: DNS queries without a corresponding response)
        # In metadata-only mode, we approximate using record type
        nxdomain_count = sum(
            1 for f in dns_flows
            if f.dns_record_type and f.dns_record_type.upper() == "NXDOMAIN"
        )

        # TXT record ratio (often used in tunnelling)
        txt_count = sum(
            1 for f in dns_flows
            if f.dns_record_type and f.dns_record_type.upper() == "TXT"
        )

        # Subdomain uniqueness (unique subdomains / total queries)
        subdomains = set()
        for q in queries:
            parts = q.split(".")
            if len(parts) >= 3:
                subdomains.add(".".join(parts[:-2]))

        # High-entropy domains (potential DGA)
        high_entropy = sum(1 for e in entropies if e > 3.5)

        # Long query domains (potential tunnelling)
        long_queries = sum(1 for l in query_lengths if l > 50)

        return {
            "dns_query_count": len(dns_flows),
            "unique_domains": len(unique_domains),
            "avg_query_length": round(sum(query_lengths) / len(query_lengths), 2),
            "max_query_length": max(query_lengths),
            "avg_domain_entropy": round(sum(entropies) / len(entropies), 4),
            "max_domain_entropy": round(max(entropies), 4),
            "avg_subdomain_depth": round(sum(depths) / len(depths), 2),
            "max_subdomain_depth": max(depths),
            "nxdomain_ratio": round(nxdomain_count / len(dns_flows), 4),
            "txt_record_ratio": round(txt_count / len(dns_flows), 4),
            "unique_subdomain_ratio": round(
                len(subdomains) / max(len(dns_flows), 1), 4
            ),
            "avg_consonant_ratio": round(
                sum(consonant_ratios) / len(consonant_ratios), 4
            ),
            "high_entropy_domains": high_entropy,
            "long_query_domains": long_queries,
        }
