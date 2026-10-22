"""
UniShield — Threat-intelligence enrichment

Adds intel matches to the alerts of the other detectors: an alert whose
source or destination address, or a domain in its evidence, is on an
imported list gets ``evidence["intel_matches"]``, the indicators' ATT&CK
techniques and (optionally) a severity one level higher.

SECURITY CONSTRAINTS:
    - Pure computation over alerts and indicators already in memory. No network I/O.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Iterable, Optional

from unishield.correlation import severity as sev
from unishield.intel.matcher import IntelEntry, IntelMatcher
from unishield.schemas.alert import Alert, ThreatClass
from unishield.schemas.timeutil import utc_now

MAX_EVIDENCE_MATCHES = 10


def _matches(alert: Alert, matcher: IntelMatcher, now: datetime) -> list[tuple[str, str, IntelEntry]]:
    """(field, observed value, entry) for the alert's addresses, evidence domains and blocklisted JA3s."""
    out: list[tuple[str, str, IntelEntry]] = []
    for field in ("source_ip", "destination_ip"):
        observed = getattr(alert, field)
        out += [(field, observed, e) for e in matcher.match_ip(observed, now)]
    evidence = alert.evidence or {}
    domains = [evidence.get("base_domain")] + list(evidence.get("examples") or [])
    for name in dict.fromkeys(d for d in domains if isinstance(d, str)):
        out += [("domain", name, e) for e in matcher.match_domain(name, now)]
    for ja3 in evidence.get("blocklisted_ja3") or {}:
        out += [("ja3", ja3, e) for e in matcher.match_ja3(ja3, now)]
    return out


def alert_matches(alert: Alert, matcher: IntelMatcher, now: Optional[datetime] = None) -> list[dict[str, Any]]:
    """Intel evidence entries for one alert."""
    return [e.to_evidence(field, observed) for field, observed, e in _matches(alert, matcher, now or utc_now())]


def enrich_alerts(alerts: Iterable[Alert], matcher: IntelMatcher, escalate: bool = True,
                  now: Optional[datetime] = None) -> int:
    """
    Add ``evidence["intel_matches"]`` to alerts (other than INTEL_MATCH) that
    involve a listed address or domain, add the indicators' ATT&CK techniques,
    and with ``escalate`` raise the severity one level. JA3 matches are added
    as evidence only: the encrypted-session detector already rated them.
    Returns the number of alerts enriched.
    """
    if matcher.empty:
        return 0
    now = now or utc_now()
    enriched = 0
    for alert in alerts:
        if alert.threat_class == ThreatClass.INTEL_MATCH:
            continue
        found = _matches(alert, matcher, now)
        if not found:
            continue
        enriched += 1
        alert.evidence = dict(alert.evidence or {}, intel_matches=[
            e.to_evidence(field, observed) for field, observed, e in found[:MAX_EVIDENCE_MATCHES]])
        for technique in sorted({t for _, _, e in found for t in e.techniques}):
            if technique not in alert.mitre_techniques:
                alert.mitre_techniques.append(technique)
        if escalate and any(e.kind != "ja3" for _, _, e in found):
            raised = sev.escalate(alert.severity)
            if raised != alert.severity:
                alert.evidence["intel_escalated_from"] = alert.severity.value
                alert.severity = raised
    return enriched
