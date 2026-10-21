"""
UniShield — Model Feature Vector

Turns the feature dictionary of one window (all extractors) into the fixed,
numeric vector the supervised and unsupervised window models use.

Scalar window features are taken as they are; the per-entity candidate lists
of the beaconing, exfiltration, DNS and TLS extractors are summarised by
their strongest entry. Every value is log-scaled with ``log1p`` (negative
values clipped to 0) so that rates spanning orders of magnitude stay
comparable. Feature groups name the extractor each feature comes from, for
ablation studies.
"""

from __future__ import annotations

import math
from typing import Any, Callable

FEATURE_GROUPS: dict[str, list[str]] = {
    "volume": [
        "total_packets", "total_bytes", "total_flows", "packets_per_second", "bytes_per_second",
        "flows_per_second", "unique_source_ips", "unique_dest_ips", "unique_dest_ports",
        "source_ip_entropy", "dest_ip_entropy", "dest_port_entropy", "tcp_ratio", "udp_ratio",
        "icmp_ratio", "syn_count", "syn_ack_ratio", "max_packet_count_per_flow",
        "max_byte_count_per_flow", "avg_packet_count_per_flow", "avg_byte_count_per_flow",
        "dest_concentration", "peak_flows_per_second", "vol_target_pps_peak", "vol_target_bps_peak",
        "vol_target_unique_sources", "vol_target_source_entropy", "syn_target_attempts",
        "syn_target_rate_peak", "syn_target_syn_only_ratio", "syn_target_unique_sources",
        "udp_target_pps_peak", "udp_target_udp_ratio", "udp_target_unique_sources",
    ],
    "scan": [
        "unique_dest_ports_per_source", "unique_dest_hosts_per_source", "connection_rate",
        "failed_connection_ratio", "fanout_score", "max_vertical_ports", "max_horizontal_hosts",
        "burst_connections", "scanner_source_ips",
    ],
    "beaconing": [
        "candidate_beacon_pairs", "top_beacon_connection_count", "top_beacon_periodicity_score",
        "top_beacon_size_regularity", "beacon_regularity",
    ],
    "exfiltration": [
        "total_outbound_bytes", "outbound_inbound_ratio", "max_session_bytes",
        "max_session_duration_sec", "long_sessions_count", "high_volume_destinations",
        "unusual_port_flows", "max_pair_upload", "max_pair_upload_ratio", "max_upload_robust_z",
    ],
    "dns": [
        "dns_query_count", "unique_domains", "avg_query_length", "max_query_length",
        "avg_domain_entropy", "max_domain_entropy", "nxdomain_ratio", "txt_record_ratio",
        "unique_subdomain_ratio", "high_entropy_domains", "long_query_domains",
        "max_generated_domains", "max_tunnel_subdomain_length",
    ],
    "tls": [
        "tls_flow_count", "tls_outdated_count", "tls_unusual_port_count", "tls_distinct_ja3",
    ],
}

MODEL_FEATURE_KEYS: list[str] = [k for keys in FEATURE_GROUPS.values() for k in keys]


def _max_of(items: list[dict], key: str) -> float:
    values = [c.get(key) for c in items or []]
    return max((float(v) for v in values if v is not None), default=0.0)


# Derived features computed from candidate lists
_DERIVED: dict[str, Callable[[dict[str, Any]], float]] = {
    # 1 - cv of the most periodic pair: higher is more regular (0 if none)
    "beacon_regularity": lambda f: max(
        (1.0 - min(1.0, float(c.get("interval_cv") or 1.0)) for c in f.get("beacon_candidates") or []),
        default=0.0,
    ),
    "max_pair_upload": lambda f: _max_of(f.get("exfil_candidates"), "upload_bytes"),
    "max_pair_upload_ratio": lambda f: _max_of(f.get("exfil_candidates"), "upload_download_ratio"),
    "max_upload_robust_z": lambda f: _max_of(f.get("exfil_candidates"), "robust_z"),
    "max_generated_domains": lambda f: _max_of(f.get("dga_candidates"), "generated_looking_domains"),
    "max_tunnel_subdomain_length": lambda f: _max_of(f.get("tunnel_candidates"), "avg_subdomain_length"),
}


def raw_value(features: dict[str, Any], key: str) -> float:
    """Numeric value of one model feature (0 when missing or non-numeric)."""
    try:
        value = _DERIVED[key](features) if key in _DERIVED else features.get(key)
        value = float(value or 0.0)
    except (TypeError, ValueError):
        return 0.0
    return value if math.isfinite(value) else 0.0


def model_vector(features: dict[str, Any], keys: list[str] = MODEL_FEATURE_KEYS) -> list[float]:
    """log1p-scaled vector of ``keys`` for one window's feature dictionary."""
    return [math.log1p(max(raw_value(features, k), 0.0)) for k in keys]


def keys_without(groups: list[str]) -> list[str]:
    """Feature keys with whole groups removed (ablation)."""
    unknown = set(groups) - set(FEATURE_GROUPS)
    if unknown:
        raise ValueError(f"Unknown feature groups: {sorted(unknown)}")
    return [k for g, keys in FEATURE_GROUPS.items() if g not in groups for k in keys]
