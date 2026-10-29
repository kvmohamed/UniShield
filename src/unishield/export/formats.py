"""
UniShield — Export record formats (JSON lines and CEF)

    JSON lines  one alert (Alert.model_dump) or incident per line
    CEF         ArcSight Common Event Format, version 0: one line per alert or
                incident, header fields and extension values escaped as the
                format requires (no raw newlines, ``|`` and ``=`` escaped)

``redact_ips`` replaces addresses with ``redacted`` and drops the free-form
evidence (which can contain addresses), keeping only its summary.

SECURITY CONSTRAINTS:
    - Pure formatting of alerts already stored. No network I/O.
"""

from __future__ import annotations

import ipaddress
import json
from datetime import datetime
from typing import Any, Optional

from unishield import __version__
from unishield.schemas.alert import Alert, Severity

REDACTED = "redacted"
IP_FIELDS = ("source_ip", "destination_ip", "source_ip_hash", "destination_ip_hash")

CEF_SEVERITY = {Severity.CRITICAL: 10, Severity.HIGH: 8, Severity.MEDIUM: 5, Severity.LOW: 3, Severity.INFO: 1}
CLASS_NAMES = {
    "DDOS_VOLUMETRIC": "Volumetric denial of service",
    "DDOS_PROTOCOL": "Protocol denial of service",
    "SYN_FLOOD": "SYN flood",
    "UDP_FLOOD": "UDP flood",
    "PORT_SCAN": "Port scan",
    "HOST_SCAN": "Host scan",
    "RECONNAISSANCE": "Reconnaissance",
    "C2_BEACONING": "Command-and-control beaconing",
    "DATA_EXFILTRATION": "Possible data exfiltration",
    "DNS_TUNNELLING": "DNS tunnelling",
    "DGA_DETECTED": "Generated domain names (DGA)",
    "ENCRYPTED_SESSION_ANOMALY": "Suspicious encrypted-session behaviour",
    "STATISTICAL_ANOMALY": "Statistical anomaly",
    "INTEL_MATCH": "Threat-intelligence match",
    "BRUTE_FORCE": "Login brute force",
    "SPAM_ACTIVITY": "Spam sending",
}


def is_ip(value: Any) -> bool:
    try:
        ipaddress.ip_address(str(value))
        return True
    except ValueError:
        return False


def evidence_summary(alert: Alert) -> str:
    summary = (alert.evidence or {}).get("summary")
    return str(summary) if summary else CLASS_NAMES.get(alert.threat_class.value, alert.threat_class.value)


def intel_sources(alert: Alert) -> list[str]:
    return sorted({str(m.get("source")) for m in (alert.evidence or {}).get("intel_matches") or []
                   if isinstance(m, dict) and m.get("source")})


def alert_record(alert: Alert, redact_ips: bool = False) -> dict[str, Any]:
    record = alert.model_dump(mode="json")
    if redact_ips:
        for name in IP_FIELDS:
            if record.get(name):
                record[name] = REDACTED
        record["evidence"] = {"summary": evidence_summary(alert)}
    return record


def incident_record(incident: dict[str, Any], redact_ips: bool = False) -> dict[str, Any]:
    record = dict(incident)
    if redact_ips:
        for name in ("entity", "source_ip"):
            if record.get(name):
                record[name] = REDACTED
    return record


def json_line(record: dict[str, Any]) -> str:
    return json.dumps(record, ensure_ascii=False, separators=(",", ":"), default=str)


# --- CEF ----------------------------------------------------------------------

def _header(value: Any) -> str:
    return str(value).replace("\\", "\\\\").replace("|", "\\|").replace("\r", " ").replace("\n", " ")


def _extension(value: Any) -> str:
    return (str(value).replace("\\", "\\\\").replace("=", "\\=")
            .replace("\r", "\\r").replace("\n", "\\n"))


def _ms(value: Optional[datetime]) -> Optional[int]:
    return int(value.timestamp() * 1000) if value is not None else None


def _cef(event_class: str, name: str, severity: Severity, fields: list[tuple[str, Any]]) -> str:
    header = "|".join(_header(v) for v in (
        "CEF:0", "UniShield", "UniShield", __version__, event_class, name, CEF_SEVERITY[severity]))
    extension = " ".join(f"{k}={_extension(v)}" for k, v in fields if v not in (None, "", []))
    return f"{header}|{extension}"


def _endpoint_fields(src: Optional[str], dst: Optional[str], redact_ips: bool) -> list[tuple[str, Any]]:
    """src/dst for real addresses; anonymised hashes go to cs5/cs6; nothing when redacted."""
    if redact_ips:
        return []
    fields: list[tuple[str, Any]] = []
    for key, label_key, label, value in (("src", "cs5Label", "sourceAnonymised", src),
                                         ("dst", "cs6Label", "destinationAnonymised", dst)):
        if not value:
            continue
        if is_ip(value):
            fields.append((key, value))
        else:
            fields += [(label_key, label), (label_key.replace("Label", ""), value)]
    return fields


def alert_to_cef(alert: Alert, redact_ips: bool = False) -> str:
    evidence = alert.evidence or {}
    port = evidence.get("destination_port")
    fields: list[tuple[str, Any]] = [
        ("rt", _ms(alert.timestamp)),
        ("start", _ms(alert.window_start)),
        ("end", _ms(alert.window_end)),
        *_endpoint_fields(alert.source_ip, alert.destination_ip, redact_ips),
        ("dpt", port if isinstance(port, int) and not redact_ips else None),
        ("externalId", alert.alert_id),
        ("cat", alert.threat_class.value),
        ("msg", evidence_summary(alert)),
        ("cs1Label", "mitreTechniques"), ("cs1", ",".join(alert.mitre_techniques) or None),
        ("cs2Label", "detector"), ("cs2", f"{alert.detector_name} {alert.model_version}"),
        ("cs3Label", "runId"), ("cs3", alert.run_id),
        ("cs4Label", "intelSources"), ("cs4", ",".join(intel_sources(alert)) or None),
        ("cfp1Label", "confidence"), ("cfp1", round(alert.confidence, 4)),
    ]
    return _cef(alert.threat_class.value, CLASS_NAMES.get(alert.threat_class.value, alert.threat_class.value),
                alert.severity, _drop_orphan_labels(fields))


def incident_to_cef(incident: dict[str, Any], redact_ips: bool = False) -> str:
    def ms(iso: Optional[str]) -> Optional[int]:
        return _ms(datetime.fromisoformat(iso)) if iso else None

    kind = "multi-vector" if incident.get("is_multi_vector") else "multi-stage" if incident.get("is_multi_stage") \
        else "repeated"
    entity = incident.get("source_ip") or incident.get("entity")
    fields: list[tuple[str, Any]] = [
        ("start", ms(incident.get("first_seen"))),
        ("end", ms(incident.get("last_seen"))),
        *_endpoint_fields(entity if incident.get("source_ip") else None,
                          None if incident.get("source_ip") else entity, redact_ips),
        ("cnt", incident.get("alert_count")),
        ("externalId", incident.get("incident_id")),
        ("cat", "INCIDENT"),
        ("msg", f"{kind} incident: {', '.join(incident.get('threat_classes', []))}"),
        ("cs1Label", "mitreTechniques"), ("cs1", ",".join(incident.get("mitre_techniques", [])) or None),
        ("cs2Label", "threatClasses"), ("cs2", ",".join(incident.get("threat_classes", [])) or None),
        ("cs3Label", "alertIds"), ("cs3", ",".join(incident.get("alert_ids", [])[:20]) or None),
        ("cfp1Label", "averageConfidence"), ("cfp1", incident.get("avg_confidence")),
    ]
    return _cef("INCIDENT", f"Correlated incident ({incident.get('alert_count', 0)} alerts)",
                Severity(incident.get("severity", "INFO")), _drop_orphan_labels(fields))


def _drop_orphan_labels(fields: list[tuple[str, Any]]) -> list[tuple[str, Any]]:
    """Remove ``csNLabel`` / ``cfpNLabel`` entries whose value field is empty."""
    present = {k for k, v in fields if v not in (None, "", [])}
    return [(k, v) for k, v in fields if not k.endswith("Label") or k[:-5] in present]
