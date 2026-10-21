"""
Phase 5 exit tests: beaconing and exfiltration through the full pipeline.

- 30 s and 60 s beacons with 5% jitter raise C2_BEACONING for the beacon pair.
- Three exfiltration episodes 12 minutes apart raise exactly three alerts.
- No beaconing or exfiltration alert on the benign, DDoS or scan scenarios.
"""

from __future__ import annotations

import pytest

from unishield.data.sample_generator import C2_SERVER, EXFIL_DEST, SimulatedReader, build_scenario
from unishield.processing.pipeline import Pipeline

pytestmark = pytest.mark.integration
SEEDS = [1, 2, 3]


def alerts_of(name, seed, threat):
    result = Pipeline().run(SimulatedReader(build_scenario(name, seed).flows))
    return [a for a in result.alerts if a.threat_class.value == threat]


@pytest.mark.parametrize("seed", SEEDS)
@pytest.mark.parametrize("name", ["beacon_30s", "beacon_60s"])
def test_beacons_are_detected(name, seed):
    beacons = alerts_of(name, seed, "C2_BEACONING")
    assert beacons and {(a.source_ip, a.destination_ip) for a in beacons} == {("10.0.1.50", C2_SERVER)}


@pytest.mark.parametrize("seed", SEEDS)
def test_three_exfiltration_episodes_give_three_alerts(seed):
    exfil = alerts_of("exfil_episodes", seed, "DATA_EXFILTRATION")
    assert len(exfil) == 3
    assert {a.destination_ip for a in exfil} == {EXFIL_DEST}
    gaps = [(b.window_end - a.window_end).total_seconds() for a, b in zip(exfil, exfil[1:])]
    assert all(g > 600 for g in gaps)


@pytest.mark.parametrize("name", ["benign_hard", "ddos_syn", "ddos_udp", "port_scan", "host_sweep"])
def test_no_beaconing_or_exfiltration_on_other_scenarios(name):
    result = Pipeline().run(SimulatedReader(build_scenario(name, 1).flows))
    assert not {a.threat_class.value for a in result.alerts} & {"C2_BEACONING", "DATA_EXFILTRATION"}
