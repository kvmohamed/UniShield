"""Unit tests for the seeded, labelled synthetic generator (audit D10)."""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone

import pytest

from unishield.data.sample_generator import (
    LABEL_BENIGN,
    LABEL_DDOS_SYN,
    LABEL_DDOS_UDP,
    SCENARIO_NAMES,
    build_scenario,
    generate_ddos_traffic,
    generate_mixed_scenario,
)
from unishield.features.volume import VolumeFeatureExtractor

T0 = datetime(2026, 1, 1, tzinfo=timezone.utc)


def _fingerprint(flows):
    return [f.model_dump(exclude={"event_id"}) for f in flows]


@pytest.mark.parametrize("name", SCENARIO_NAMES)
def test_scenarios_are_reproducible_from_the_seed(name):
    assert _fingerprint(build_scenario(name, 7).flows) == _fingerprint(build_scenario(name, 7).flows)
    assert _fingerprint(build_scenario(name, 7).flows) != _fingerprint(build_scenario(name, 8).flows)


@pytest.mark.parametrize("name", SCENARIO_NAMES)
def test_every_flow_is_labelled_and_sorted(name):
    flows = build_scenario(name, 1).flows
    assert all(f.label for f in flows)
    assert all(a.timestamp <= b.timestamp for a, b in zip(flows, flows[1:]))


def test_benign_scenario_has_only_benign_labels():
    assert {f.label for f in build_scenario("benign_hard", 1).flows} == {LABEL_BENIGN}


def test_mixed_scenario_is_reproducible():
    a = generate_mixed_scenario(100, 600, 50, 10, 10, start_time=T0, seed=3)
    b = generate_mixed_scenario(100, 600, 50, 10, 10, start_time=T0, seed=3)
    assert _fingerprint(a) == _fingerprint(b)


def test_ddos_generator_exceeds_default_thresholds():
    """Audit D10: the shipped DDoS generator peaked at ~290 pps, far below any threshold."""
    flows = generate_ddos_traffic(6000, T0, seed=1)
    labels = Counter(f.label for f in flows)
    assert labels[LABEL_DDOS_SYN] == 4800 and labels[LABEL_DDOS_UDP] == 1200
    f = VolumeFeatureExtractor().extract(flows)
    assert f["syn_target_rate_peak"] > 1000        # syn_rate_threshold
    assert f["udp_target_pps_peak"] > 8000          # udp_flood_pps
    assert f["vol_target_pps_peak"] > 10000         # packets_per_second


def test_unknown_scenario_rejected():
    with pytest.raises(ValueError, match="Unknown scenario"):
        build_scenario("nope", 1)
