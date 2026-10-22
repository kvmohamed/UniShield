"""
UniShield — Syslog forwarding (RFC 5424) to an analyst-side SIEM

Each alert (and, optionally, each new or changed incident) becomes one
RFC 5424 message:

    <PRI>1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID [SD-ID params...] MSG

PRI combines ``syslog.facility`` with the alert severity (CRITICAL → crit,
HIGH → err, MEDIUM → warning, LOW → notice, INFO → info); MSGID is the
threat class or ``INCIDENT``; structured data carries the alert ID, class,
severity, confidence, detector, addresses (unless redacted) and ATT&CK IDs;
MSG is the CEF line or the JSON record. A MSG that is not pure ASCII is
prefixed with the UTF-8 BOM as RFC 5424 requires.

Transports: UDP (RFC 5426, one message per datagram, truncated to
``max_message_bytes``), TCP and TLS (RFC 6587 / RFC 5425 octet-counting
framing). Destinations must pass the outbound policy (see export.policy);
delivery goes through export.transport. Failed TCP/TLS batches are kept
(bounded) and retried with the next batch.
"""

from __future__ import annotations

import json
import logging
import os
import platform
from collections import deque
from datetime import datetime
from typing import Any, Optional

from unishield.correlation import severity as sev
from unishield.export import transport
from unishield.export.formats import (
    alert_record,
    alert_to_cef,
    incident_record,
    incident_to_cef,
    is_ip,
)
from unishield.export.policy import DestinationPolicy, DestinationRefused
from unishield.schemas.alert import Alert, Severity
from unishield.schemas.timeutil import ensure_utc, utc_now

logger = logging.getLogger("unishield.export.syslog")

FACILITIES = {
    "kern": 0, "user": 1, "mail": 2, "daemon": 3, "auth": 4, "syslog": 5, "lpr": 6, "news": 7, "uucp": 8,
    "cron": 9, "authpriv": 10, "ftp": 11, "local0": 16, "local1": 17, "local2": 18, "local3": 19,
    "local4": 20, "local5": 21, "local6": 22, "local7": 23,
}
SEVERITY_CODES = {Severity.CRITICAL: 2, Severity.HIGH: 3, Severity.MEDIUM: 4, Severity.LOW: 5, Severity.INFO: 6}
DEFAULT_PORTS = {"udp": 514, "tcp": 514, "tls": 6514}
_BOM = b"\xef\xbb\xbf"
_RETRY_LIMIT = 1000


def _ascii_field(value: Any, limit: int) -> str:
    """PRINTUSASCII header field (no spaces), truncated; '-' when empty."""
    text = "".join(ch for ch in str(value or "") if 33 <= ord(ch) <= 126)[:limit]
    return text or "-"


def _param(value: Any) -> str:
    return str(value).replace("\\", "\\\\").replace('"', '\\"').replace("]", "\\]")


def rfc5424_timestamp(value: datetime) -> str:
    value = ensure_utc(value)
    return value.strftime("%Y-%m-%dT%H:%M:%S.") + f"{value.microsecond // 1000:03d}Z"


def format_message(*, severity: Severity, facility: int, timestamp: datetime, hostname: str, app_name: str,
                   procid: Any, msgid: str, sd_id: str, params: dict[str, Any], msg: str,
                   max_bytes: Optional[int] = None) -> bytes:
    """One RFC 5424 message; ``max_bytes`` truncates MSG (on a UTF-8 character boundary) to fit."""
    pri = facility * 8 + SEVERITY_CODES[severity]
    header = (f"<{pri}>1 {rfc5424_timestamp(timestamp)} {_ascii_field(hostname, 255)} "
              f"{_ascii_field(app_name, 48)} {_ascii_field(procid, 128)} {_ascii_field(msgid, 32)}")
    pairs = "".join(f' {name}="{_param(value)}"' for name, value in params.items() if value not in (None, ""))
    structured = f"[{_ascii_field(sd_id, 32)}{pairs}]"
    head = f"{header} {structured} ".encode("ascii", "replace")
    body = msg.encode("utf-8")
    if not msg.isascii():
        body = _BOM + body
    if max_bytes is not None and len(head) + len(body) > max_bytes:
        room = max(0, max_bytes - len(head))
        body = body[:room].decode("utf-8", "ignore").encode("utf-8")
    return head + body


def octet_frame(message: bytes) -> bytes:
    """RFC 6587 / RFC 5425 octet counting: 'MSG-LEN SP SYSLOG-MSG'."""
    return str(len(message)).encode("ascii") + b" " + message


class SyslogForwarder:
    """Forwards alerts and incidents to one configured syslog destination."""

    def __init__(self, destination, syslog_config, policy: DestinationPolicy, timeout: float = 5.0):
        d = destination
        self.name = d.name
        self.host = d.host
        self.protocol = d.protocol
        self.port = d.port or DEFAULT_PORTS[d.protocol]
        self.message_format = d.message_format
        self.min_severity = Severity(d.min_severity)
        self.include_incidents = d.include_incidents
        self.redact_ips = d.redact_ips
        self.max_bytes = d.max_message_bytes or (2048 if d.protocol == "udp" else 65536)
        self.tls = transport.TLSSettings(d.tls.ca_file, d.tls.cert_file, d.tls.key_file, d.tls.verify) \
            if d.protocol == "tls" else None
        self.facility = FACILITIES[syslog_config.facility]
        self.app_name = syslog_config.app_name
        self.hostname = syslog_config.hostname or platform.node() or "unishield"
        self.sd_id = syslog_config.sd_id
        self.policy = policy
        self.timeout = timeout
        self._retry: deque[bytes] = deque(maxlen=_RETRY_LIMIT)
        self.sent = 0
        self.failed_batches = 0
        self.dropped = 0
        self.last_success: Optional[str] = None
        self.last_error: Optional[str] = None

    # --- formatting -----------------------------------------------------------

    def _params(self, values: dict[str, Any]) -> dict[str, Any]:
        if self.redact_ips:
            values = {k: v for k, v in values.items() if k not in ("src", "dst")}
        return values

    def alert_message(self, alert: Alert) -> bytes:
        if self.message_format == "json":
            msg = json.dumps(dict(alert_record(alert, self.redact_ips), record_type="alert"),
                             ensure_ascii=False, separators=(",", ":"), default=str)
        else:
            msg = alert_to_cef(alert, self.redact_ips)
        return format_message(
            severity=alert.severity, facility=self.facility, timestamp=alert.timestamp, hostname=self.hostname,
            app_name=self.app_name, procid=os.getpid(), msgid=alert.threat_class.value, sd_id=self.sd_id,
            params=self._params({
                "alertId": alert.alert_id, "class": alert.threat_class.value, "severity": alert.severity.value,
                "confidence": f"{alert.confidence:.4f}", "detector": alert.detector_name,
                "src": alert.source_ip if alert.source_ip and is_ip(alert.source_ip) else None,
                "dst": alert.destination_ip if alert.destination_ip and is_ip(alert.destination_ip) else None,
                "mitre": ",".join(alert.mitre_techniques),
            }),
            msg=msg, max_bytes=self.max_bytes)

    def incident_message(self, incident: dict[str, Any]) -> bytes:
        if self.message_format == "json":
            msg = json.dumps(dict(incident_record(incident, self.redact_ips), record_type="incident"),
                             ensure_ascii=False, separators=(",", ":"), default=str)
        else:
            msg = incident_to_cef(incident, self.redact_ips)
        source = incident.get("source_ip")
        return format_message(
            severity=Severity(incident.get("severity", "INFO")), facility=self.facility, timestamp=utc_now(),
            hostname=self.hostname, app_name=self.app_name, procid=os.getpid(), msgid="INCIDENT", sd_id=self.sd_id,
            params=self._params({
                "incidentId": incident.get("incident_id"), "severity": incident.get("severity"),
                "alerts": incident.get("alert_count"), "classes": ",".join(incident.get("threat_classes", [])),
                "src": source if source and is_ip(source) else None,
                "mitre": ",".join(incident.get("mitre_techniques", [])),
            }),
            msg=msg, max_bytes=self.max_bytes)

    # --- delivery -------------------------------------------------------------

    def forward(self, alerts: list[Alert], incidents: list[dict[str, Any]]) -> int:
        """Format and deliver; failures are recorded, never raised. Returns messages delivered."""
        floor = sev.RANK[self.min_severity]
        messages = [self.alert_message(a) for a in alerts if sev.RANK[a.severity] >= floor]
        if self.include_incidents:
            messages += [self.incident_message(i) for i in incidents
                         if sev.RANK[Severity(i.get("severity", "INFO"))] >= floor]
        if self.protocol != "udp" and self._retry:
            messages = list(self._retry) + messages
            self._retry.clear()
        if not messages:
            return 0
        try:
            if self.protocol == "udp":
                delivered = transport.deliver_datagrams(self.policy, self.host, self.port, messages, self.timeout,
                                                        label=f"syslog {self.name!r}")
            else:
                delivered = transport.deliver_stream(self.policy, self.host, self.port,
                                                     [octet_frame(m) for m in messages], self.timeout, self.tls,
                                                     label=f"syslog {self.name!r}")
        except (transport.DeliveryError, DestinationRefused, OSError) as exc:
            self.failed_batches += 1
            self.last_error = str(exc)[:300]
            if self.protocol == "udp" or isinstance(exc, DestinationRefused):
                self.dropped += len(messages)
            else:
                overflow = max(0, len(messages) - _RETRY_LIMIT)
                self.dropped += overflow
                self._retry.extend(messages[overflow:])
            logger.warning("Syslog delivery to %s failed: %s", self.name, exc)
            return 0
        self.sent += delivered
        self.last_success = utc_now().isoformat()
        return delivered

    def status(self) -> dict[str, Any]:
        return {
            "name": self.name, "protocol": self.protocol, "host": self.host, "port": self.port,
            "format": self.message_format, "min_severity": self.min_severity.value,
            "redact_ips": self.redact_ips, "tls_verify": self.tls.verify if self.tls else None,
            "sent": self.sent, "failed_batches": self.failed_batches, "dropped": self.dropped,
            "pending_retry": len(self._retry), "last_success": self.last_success, "last_error": self.last_error,
        }
