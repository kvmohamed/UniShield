"""
UniShield — STIX 2.1 export

Builds a STIX 2.1 bundle from alerts and incidents:

    identity        the UniShield sensor (identity_class "system"), creator of
                    every object and the place sightings were made
    attack-pattern  one per ATT&CK technique, with a ``mitre-attack``
                    external reference (ID and URL)
    ipv4-addr / ipv6-addr / domain-name
                    observables of an alert (real addresses only; anonymised
                    hashes are not valid observables)
    observed-data   the alert's window and observables
    indicator       a STIX pattern for the alert's adversary side: the listed
                    value for INTEL_MATCH, a domain the alert is about, the
                    endpoints outside ``network.home_networks``, else the
                    source; ``anomalous-activity``, or ``malicious-activity``
                    for intel matches. A monitored destination alone (a
                    flood's victim) is not made an indicator.
    sighting        of the indicator (or, without one, of the first ATT&CK
                    technique) in the alert's window, with the observed data,
                    sighted by the sensor
    relationship    indicator ``indicates`` attack-pattern; incident
                    ``related-to`` the indicators of its alerts
    incident        a correlated incident (STIX 2.1 incident object)

Identifiers of objects derived from an alert or incident are UUIDv5 values
of their UniShield IDs, so re-exporting the same alert yields the same
objects and consumers can de-duplicate rotated or repeated exports. Cyber-
observable IDs follow the specification's deterministic scheme. Custom
properties use the ``x_unishield_`` prefix.

SECURITY CONSTRAINTS:
    - Pure formatting of alerts already stored. No network I/O.
"""

from __future__ import annotations

import ipaddress
import json
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Optional

from unishield import __version__
from unishield.correlation.mitre_mapping import TECHNIQUE_NAMES, technique_url
from unishield.export.formats import CLASS_NAMES, evidence_summary, intel_sources
from unishield.schemas.alert import Alert, ThreatClass

SPEC_VERSION = "2.1"
#: Namespace for UniShield object identifiers (fixed, randomly generated once).
UNISHIELD_NAMESPACE = uuid.UUID("6f1f6c43-2b0e-4b8e-9d5c-7a3e2d1b9c40")
#: Namespace the STIX 2.1 specification defines for deterministic SCO identifiers.
SCO_NAMESPACE = uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")
#: Creation time of the static reference objects (identity, attack patterns).
_REFERENCE_TIME = datetime(2026, 1, 1, tzinfo=timezone.utc)


def stix_time(value: datetime) -> str:
    """RFC 3339 UTC timestamp with millisecond precision, as STIX requires (``Z`` suffix)."""
    value = value.astimezone(timezone.utc)
    return value.strftime("%Y-%m-%dT%H:%M:%S.") + f"{value.microsecond // 1000:03d}Z"


def sdo_id(object_type: str, key: str) -> str:
    return f"{object_type}--{uuid.uuid5(UNISHIELD_NAMESPACE, f'{object_type}|{key}')}"


def sco_id(object_type: str, value: str) -> str:
    """Deterministic SCO id: UUIDv5 over the canonical JSON of the ID-contributing property (value)."""
    canonical = json.dumps({"value": value}, separators=(",", ":"), ensure_ascii=False)
    return f"{object_type}--{uuid.uuid5(SCO_NAMESPACE, canonical)}"


def _quote(value: str) -> str:
    return "'" + value.replace("\\", "\\\\").replace("'", "\\'") + "'"


class StixBundleBuilder:
    """Accumulates STIX objects for alerts and incidents; ``bundle()`` returns the bundle dict."""

    def __init__(self, home_networks: Iterable[str] = (), indicator_valid_days: int = 30):
        self._home = [ipaddress.ip_network(n, strict=False) for n in home_networks]
        self._valid = timedelta(days=indicator_valid_days) if indicator_valid_days else None
        self._objects: dict[str, dict[str, Any]] = {}
        self._indicator_for_alert: dict[str, str] = {}
        self.alerts_added = 0
        self.alerts_without_objects = 0
        self.incidents_added = 0
        self.identity_id = sdo_id("identity", "unishield-sensor")
        self._put({
            "type": "identity", "spec_version": SPEC_VERSION, "id": self.identity_id,
            "created": stix_time(_REFERENCE_TIME), "modified": stix_time(_REFERENCE_TIME),
            "name": "UniShield passive sensor", "identity_class": "system",
            "description": "Passive, read-only network monitoring on the receiving side of a one-way link "
                           f"(UniShield {__version__}).",
        })

    def _put(self, obj: dict[str, Any]) -> str:
        current = self._objects.get(obj["id"])
        if current is None or obj.get("modified", "") >= current.get("modified", ""):
            self._objects[obj["id"]] = obj
        return obj["id"]

    def __len__(self) -> int:
        return len(self._objects)

    # --- helpers --------------------------------------------------------------

    def _common(self, object_type: str, key: str, created: datetime, modified: Optional[datetime] = None) -> dict:
        return {"type": object_type, "spec_version": SPEC_VERSION, "id": sdo_id(object_type, key),
                "created": stix_time(created), "modified": stix_time(modified or created),
                "created_by_ref": self.identity_id}

    def _attack_pattern(self, technique: str) -> str:
        return self._put({
            **self._common("attack-pattern", technique, _REFERENCE_TIME),
            "name": TECHNIQUE_NAMES.get(technique, technique),
            "external_references": [{"source_name": "mitre-attack", "external_id": technique,
                                     "url": technique_url(technique)}],
        })

    def _address(self, value: Optional[str]) -> Optional[tuple[str, str, bool]]:
        """(SCO type, canonical value, is home) for a real address; None for hashes/empty."""
        if not value:
            return None
        try:
            addr = ipaddress.ip_address(value)
        except ValueError:
            return None
        return ("ipv4-addr" if addr.version == 4 else "ipv6-addr", str(addr), any(addr in n for n in self._home))

    def _observable(self, object_type: str, value: str) -> str:
        return self._put({"type": object_type, "spec_version": SPEC_VERSION, "id": sco_id(object_type, value),
                          "value": value})

    @staticmethod
    def _references(alert_or_incident_id: str, techniques: Iterable[str], description: str) -> list[dict]:
        refs = [{"source_name": "unishield", "external_id": alert_or_incident_id, "description": description}]
        refs += [{"source_name": "mitre-attack", "external_id": t, "url": technique_url(t)} for t in techniques]
        return refs

    def _pattern(self, alert: Alert, addresses: dict[str, tuple[str, str, bool]],
                 domains: list[str]) -> Optional[str]:
        """
        Pattern for the alert's adversary side: the listed value of an intel
        match, a domain the alert is about, the endpoints outside the home
        networks, else the source. None when only a monitored destination is
        known (e.g. a flood's victim), which is not an indicator.
        """
        evidence = alert.evidence or {}
        if alert.threat_class == ThreatClass.INTEL_MATCH and evidence.get("matched_field") != "dns_query":
            observed = self._address(evidence.get("observed"))
            return f"[{observed[0]}:value = {_quote(observed[1])}]" if observed else None
        if domains:
            return "[" + " OR ".join(f"domain-name:value = {_quote(d)}" for d in domains) + "]"
        actors = [a for a in addresses.values() if not a[2]] or             ([addresses["source_ip"]] if "source_ip" in addresses else [])
        if not actors:
            return None
        return "[" + " OR ".join(f"{t}:value = {_quote(v)}" for t, v, _ in dict.fromkeys(actors)) + "]"

    # --- alerts and incidents --------------------------------------------------

    def add_alert(self, alert: Alert) -> Optional[str]:
        """
        Add the objects describing one alert; returns its indicator id (None if
        no pattern applies). An alert with neither a pattern nor an ATT&CK
        technique has nothing to sight and adds no objects.
        """
        self.alerts_added += 1
        evidence = alert.evidence or {}
        addresses = {f: a for f in ("source_ip", "destination_ip") if (a := self._address(getattr(alert, f)))}
        domains = [d for d in [evidence.get("base_domain")] if isinstance(d, str) and d]
        if alert.threat_class == ThreatClass.INTEL_MATCH and evidence.get("matched_field") == "dns_query":
            domains = [m.get("indicator") for m in evidence.get("intel_matches") or []
                       if m.get("kind") == "domain"][:1]
        techniques = list(alert.mitre_techniques)
        pattern = self._pattern(alert, addresses, domains)
        if pattern is None and not techniques:
            self.alerts_without_objects += 1
            return None

        pattern_ids = [self._attack_pattern(t) for t in techniques]
        observables = [self._observable(t, v) for t, v, _ in addresses.values()]
        observables += [self._observable("domain-name", d) for d in domains]
        description = (f"{evidence_summary(alert)} — {alert.severity.value} from {alert.detector_name} "
                       f"(confidence {alert.confidence:.2f}; a rule/anomaly score unless the detector is the "
                       "calibrated ML model).")
        custom: dict[str, Any] = {"x_unishield_alert_id": alert.alert_id,
                                  "x_unishield_threat_class": alert.threat_class.value,
                                  "x_unishield_severity": alert.severity.value}
        if intel_sources(alert):
            custom["x_unishield_intel_sources"] = intel_sources(alert)

        indicator_id = None
        if pattern:
            indicator = {
                **self._common("indicator", alert.alert_id, alert.timestamp),
                "name": f"UniShield {alert.threat_class.value} {alert.alert_id}",
                "description": description,
                "indicator_types": ["malicious-activity" if alert.threat_class == ThreatClass.INTEL_MATCH
                                    else "anomalous-activity"],
                "pattern": pattern,
                "pattern_type": "stix",
                "pattern_version": SPEC_VERSION,
                "valid_from": stix_time(alert.window_start),
                "confidence": int(round(alert.confidence * 100)),
                "labels": [alert.threat_class.value.lower(), alert.severity.value.lower()],
                "external_references": self._references(alert.alert_id, techniques,
                                                        CLASS_NAMES.get(alert.threat_class.value, "")),
                **custom,
            }
            if self._valid is not None:
                indicator["valid_until"] = stix_time(max(alert.window_end, alert.window_start) + self._valid)
            indicator_id = self._put(indicator)
            self._indicator_for_alert[alert.alert_id] = indicator_id
            for pattern_id in pattern_ids:
                self._relationship(indicator_id, "indicates", pattern_id, alert.alert_id, alert.timestamp)

        sighting = {
            **self._common("sighting", alert.alert_id, alert.timestamp),
            "description": description,
            "first_seen": stix_time(alert.window_start),
            "last_seen": stix_time(alert.window_end),
            "count": 1,
            "sighting_of_ref": indicator_id or pattern_ids[0],
            "where_sighted_refs": [self.identity_id],
            "external_references": self._references(alert.alert_id, techniques, "UniShield alert"),
            **custom,
        }
        if observables:
            flows = evidence.get("flows")
            sighting["observed_data_refs"] = [self._put({
                **self._common("observed-data", alert.alert_id, alert.timestamp),
                "first_observed": stix_time(alert.window_start),
                "last_observed": stix_time(alert.window_end),
                "number_observed": flows if isinstance(flows, int) and 1 <= flows <= 999_999_999 else 1,
                "object_refs": list(dict.fromkeys(observables)),
            })]
        self._put(sighting)
        return indicator_id

    def _relationship(self, source: str, kind: str, target: str, key: str, when: datetime,
                      modified: Optional[datetime] = None) -> str:
        return self._put({
            **self._common("relationship", f"{key}|{kind}|{source}|{target}", when, modified),
            "relationship_type": kind, "source_ref": source, "target_ref": target,
        })

    def add_incident(self, incident: dict[str, Any], alerts_by_id: Optional[dict[str, Alert]] = None) -> str:
        """Add an incident (dict from AlertCorrelator) and link it to the indicators of its alerts."""
        self.incidents_added += 1
        alerts_by_id = alerts_by_id or {}
        members = [alerts_by_id[a] for a in incident.get("alert_ids", []) if a in alerts_by_id]
        first_seen = datetime.fromisoformat(incident["first_seen"])
        last_seen = datetime.fromisoformat(incident["last_seen"])
        created = min((a.timestamp for a in members), default=last_seen)
        modified = max((a.timestamp for a in members), default=last_seen)
        techniques = incident.get("mitre_techniques", [])
        classes = ", ".join(incident.get("threat_classes", []))
        incident_obj = {
            **self._common("incident", incident["incident_id"], created, max(created, modified)),
            "name": f"UniShield incident {incident['incident_id']}: {classes}",
            "description": (f"{incident.get('alert_count')} alerts for {incident.get('entity')} between "
                            f"{incident['first_seen']} and {incident['last_seen']}; severity "
                            f"{incident.get('severity')}."),
            "labels": [c.lower() for c in incident.get("threat_classes", [])] or ["incident"],
            "external_references": self._references(incident["incident_id"], techniques, "UniShield incident"),
            "x_unishield_severity": incident.get("severity"),
            "x_unishield_alert_count": incident.get("alert_count"),
            "x_unishield_first_seen": stix_time(first_seen),
            "x_unishield_last_seen": stix_time(last_seen),
        }
        incident_id = self._put(incident_obj)
        for alert_id in incident.get("alert_ids", []):
            indicator_id = self._indicator_for_alert.get(alert_id)
            if indicator_id:
                self._relationship(incident_id, "related-to", indicator_id, incident["incident_id"],
                                   created, max(created, modified))
        for technique in techniques:
            self._relationship(incident_id, "related-to", self._attack_pattern(technique), incident["incident_id"],
                               created, max(created, modified))
        return incident_id

    def bundle(self) -> dict[str, Any]:
        return {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": list(self._objects.values())}


def build_bundle(alerts: Iterable[Alert], incidents: Iterable[dict[str, Any]] = (),
                 home_networks: Iterable[str] = (), indicator_valid_days: int = 30) -> dict[str, Any]:
    alerts = list(alerts)
    builder = StixBundleBuilder(home_networks, indicator_valid_days)
    for alert in alerts:
        builder.add_alert(alert)
    by_id = {a.alert_id: a for a in alerts}
    for incident in incidents:
        builder.add_incident(incident, by_id)
    return builder.bundle()
