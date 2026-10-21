"""
UniShield — MITRE ATT&CK mapping

Single source of truth for the ATT&CK techniques attached to each threat
class. Mappings describe the adversary behaviour the alert is evidence of,
from the defender's (victim network's) point of view.
"""

from __future__ import annotations

from unishield.schemas.alert import ThreatClass

MITRE_TECHNIQUES: dict[ThreatClass, tuple[str, ...]] = {
    # T1498 Network Denial of Service / .001 Direct Network Flood
    ThreatClass.DDOS_VOLUMETRIC: ("T1498", "T1498.001"),
    ThreatClass.DDOS_PROTOCOL: ("T1498",),
    # T1499.001 OS Exhaustion Flood covers TCP state exhaustion such as SYN floods
    ThreatClass.SYN_FLOOD: ("T1498.001", "T1499.001"),
    ThreatClass.UDP_FLOOD: ("T1498", "T1498.001"),
    # T1046 Network Service Discovery; T1595.001 Active Scanning: Scanning IP Blocks
    ThreatClass.PORT_SCAN: ("T1046",),
    ThreatClass.HOST_SCAN: ("T1046", "T1595.001"),
    ThreatClass.RECONNAISSANCE: ("T1046",),
    # T1071 Application Layer Protocol (C2 over common protocols)
    ThreatClass.C2_BEACONING: ("T1071",),
    # T1041 Exfiltration Over C2 Channel; T1048 Exfiltration Over Alternative Protocol
    ThreatClass.DATA_EXFILTRATION: ("T1041", "T1048"),
    # T1071.004 Application Layer Protocol: DNS; T1572 Protocol Tunneling
    ThreatClass.DNS_TUNNELLING: ("T1071.004", "T1572"),
    # T1568.002 Dynamic Resolution: Domain Generation Algorithms
    ThreatClass.DGA_DETECTED: ("T1568.002",),
    # T1573 Encrypted Channel
    ThreatClass.ENCRYPTED_SESSION_ANOMALY: ("T1573",),
    # A statistical deviation is not evidence of a specific technique.
    ThreatClass.STATISTICAL_ANOMALY: (),
}

# Extra techniques added when evidence supports them
ENCRYPTED_CHANNEL = "T1573"        # beaconing/exfiltration over TLS
NON_STANDARD_PORT = "T1571"        # traffic on an unusual port for its protocol


def techniques_for(threat_class: ThreatClass, *extra: str) -> list[str]:
    """ATT&CK technique IDs for a threat class, plus any evidence-specific extras."""
    techniques = list(MITRE_TECHNIQUES.get(threat_class, ()))
    for technique in extra:
        if technique and technique not in techniques:
            techniques.append(technique)
    return techniques
