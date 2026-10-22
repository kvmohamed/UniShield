"""
UniShield — Email and webhook notifications (analyst side)

Alerts at or above a channel's ``min_severity`` are announced by email (to
the configured SMTP relay) or as a JSON POST to a webhook. Each channel:

    content     only the configured ``fields`` of an alert (never the raw
                evidence, at most its one-line summary); ``redact_ips``
                replaces addresses with "redacted"
    rate limit  at most one message per ``min_interval_sec`` and at most
                ``max_per_hour`` messages per rolling hour
    digest      alerts arriving while the channel must wait are collected and
                sent together as one digest (the ``digest_max_alerts`` most
                severe listed, the rest counted)

The first alert after a quiet period goes out at once; a burst becomes a
digest. A failed delivery keeps the alerts for the next attempt and counts
as an attempt for the rate limit, so a broken relay is not hammered.
Destinations must pass the outbound policy; delivery goes through
export.transport.
"""

from __future__ import annotations

import json
import logging
import os
import time
from collections import Counter, deque
from email.message import EmailMessage
from typing import Any, Callable, Optional

from unishield import __version__
from unishield.correlation import severity as sev
from unishield.export import transport
from unishield.export.formats import REDACTED, evidence_summary, intel_sources
from unishield.export.policy import DestinationPolicy, DestinationRefused, webhook_host
from unishield.schemas.alert import Alert, Severity
from unishield.schemas.timeutil import utc_now

logger = logging.getLogger("unishield.export.notify")

DEFAULT_FIELDS = ("alert_id", "window_end", "threat_class", "severity", "confidence", "detector_name",
                  "source_ip", "destination_ip", "mitre_techniques", "summary")
ALLOWED_FIELDS = DEFAULT_FIELDS + ("window_start", "timestamp", "run_id", "model_version", "intel_sources")
_IP_FIELDS = ("source_ip", "destination_ip")
FOOTER = ("Sent by UniShield from the analyst network. UniShield is passive: it never connects to, "
          "probes or blocks anything in the monitored network.")


def notification_view(alert: Alert, fields: tuple[str, ...] = DEFAULT_FIELDS, redact_ips: bool = False) -> dict:
    """The configured fields of an alert, JSON-ready (no raw evidence)."""
    view: dict[str, Any] = {}
    for name in fields:
        if name == "summary":
            view[name] = evidence_summary(alert)
        elif name == "intel_sources":
            view[name] = intel_sources(alert)
        elif name in ALLOWED_FIELDS:
            value = getattr(alert, name)
            view[name] = value.isoformat() if hasattr(value, "isoformat") else getattr(value, "value", value)
    if redact_ips:
        for name in _IP_FIELDS:
            if view.get(name):
                view[name] = REDACTED
    return view


def _rank(view: dict[str, Any]) -> int:
    value = view.get("severity")
    return sev.RANK[Severity(value)] if value in Severity.__members__ else 0


class Throttle:
    """Rate limit plus digest buffer for one channel."""

    def __init__(self, min_interval_sec: float, max_per_hour: int, digest_max_alerts: int,
                 clock: Callable[[], float] = time.monotonic):
        self.min_interval = min_interval_sec
        self.max_per_hour = max_per_hour
        self.digest_max = digest_max_alerts
        self.clock = clock
        self.pending: list[dict[str, Any]] = []
        self.pending_total = 0
        self.pending_counts: Counter[str] = Counter()
        self.pending_classes: Counter[str] = Counter()
        self._attempts: deque[float] = deque()
        self._last: Optional[float] = None

    def offer(self, view: dict[str, Any]) -> None:
        self.pending_total += 1
        self.pending_counts[str(view.get("severity", ""))] += 1
        self.pending_classes[str(view.get("threat_class", ""))] += 1
        if len(self.pending) < self.digest_max:
            self.pending.append(view)
            return
        weakest = min(range(len(self.pending)), key=lambda i: _rank(self.pending[i]))
        if _rank(view) > _rank(self.pending[weakest]):
            self.pending[weakest] = view

    def due(self) -> bool:
        if not self.pending_total:
            return False
        now = self.clock()
        while self._attempts and now - self._attempts[0] >= 3600:
            self._attempts.popleft()
        if len(self._attempts) >= self.max_per_hour:
            return False
        return self._last is None or now - self._last >= self.min_interval

    def take(self) -> tuple[list[dict[str, Any]], int, dict[str, int], dict[str, int]]:
        batch = (self.pending, self.pending_total, dict(self.pending_counts), dict(self.pending_classes))
        self.pending, self.pending_total = [], 0
        self.pending_counts, self.pending_classes = Counter(), Counter()
        now = self.clock()
        self._attempts.append(now)
        self._last = now
        return batch

    def restore(self, views: list[dict[str, Any]], total: int, counts: dict[str, int], classes: dict[str, int]) -> None:
        """Put a failed batch back (merged with anything that arrived meanwhile)."""
        newer = self.pending
        self.pending = []
        for view in views + newer:
            if len(self.pending) < self.digest_max:
                self.pending.append(view)
        self.pending_total += total
        self.pending_counts.update(counts)
        self.pending_classes.update(classes)


def _counts_text(counts: dict[str, int]) -> str:
    order = [s.value for s in reversed(sev.ORDER)]
    return ", ".join(f"{counts[s]} {s}" for s in order if counts.get(s))


def build_email(views: list[dict[str, Any]], total: int, counts: dict[str, int], *, sender: str,
                recipients: list[str], subject_prefix: str) -> EmailMessage:
    message = EmailMessage()
    if total == 1 and views:
        v = views[0]
        subject = f"{subject_prefix} {v.get('severity', '')} {v.get('threat_class', 'alert')}".strip()
        intro = "UniShield raised an alert."
    else:
        subject = f"{subject_prefix} digest: {total} alerts ({_counts_text(counts)})"
        intro = f"UniShield raised {total} alerts ({_counts_text(counts)}); " + (
            f"the {len(views)} most severe are listed." if len(views) < total else "all are listed.")
    lines = [intro, ""]
    for v in views:
        lines += [f"{k}: {', '.join(map(str, val)) if isinstance(val, list) else val}" for k, val in v.items()]
        lines.append("")
    lines.append(FOOTER)
    message["Subject"] = subject.replace("\r", " ").replace("\n", " ")
    message["From"] = sender
    message["To"] = ", ".join(recipients)
    message["X-Mailer"] = f"UniShield {__version__}"
    message.set_content("\n".join(lines))
    return message


def build_webhook_body(views: list[dict[str, Any]], total: int, counts: dict[str, int],
                       classes: dict[str, int]) -> bytes:
    payload = {
        "source": "unishield",
        "kind": "alert" if total == 1 else "digest",
        "generated_at": utc_now().isoformat(),
        "total_alerts": total,
        "counts_by_severity": counts,
        "counts_by_class": classes,
        "alerts": views,
        "omitted": max(0, total - len(views)),
    }
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":"), default=str).encode("utf-8")


class NotificationChannel:
    """One email or webhook channel: severity filter, throttle/digest, delivery and counters."""

    def __init__(self, kind: str, name: str, settings, deliver: Callable[[list, int, dict, dict], None],
                 target: str, clock: Callable[[], float] = time.monotonic):
        self.kind = kind
        self.name = name
        self.target = target                        # host:port only (URLs can embed tokens)
        self.min_severity = Severity(settings.min_severity)
        self.fields = tuple(settings.fields)
        self.redact_ips = settings.redact_ips
        self.throttle = Throttle(settings.min_interval_sec, settings.max_per_hour, settings.digest_max_alerts, clock)
        self._deliver = deliver
        self.messages_sent = 0
        self.alerts_notified = 0
        self.digests_sent = 0
        self.failures = 0
        self.last_success: Optional[str] = None
        self.last_error: Optional[str] = None

    def offer(self, alert: Alert) -> bool:
        if sev.RANK[alert.severity] < sev.RANK[self.min_severity]:
            return False
        self.throttle.offer(notification_view(alert, self.fields, self.redact_ips))
        return True

    def flush(self) -> bool:
        """Send one message (single alert or digest) if the rate limit allows; True if sent."""
        if not self.throttle.due():
            return False
        views, total, counts, classes = self.throttle.take()
        try:
            self._deliver(views, total, counts, classes)
        except (transport.DeliveryError, DestinationRefused, OSError, ValueError) as exc:
            self.failures += 1
            self.last_error = str(exc)[:300]
            if not isinstance(exc, DestinationRefused):
                self.throttle.restore(views, total, counts, classes)
            logger.warning("%s notification via %s failed: %s", self.kind, self.name, exc)
            return False
        self.messages_sent += 1
        self.alerts_notified += total
        self.digests_sent += 1 if total > 1 else 0
        self.last_success = utc_now().isoformat()
        return True

    def status(self) -> dict[str, Any]:
        return {
            "kind": self.kind, "name": self.name, "target": self.target, "min_severity": self.min_severity.value,
            "redact_ips": self.redact_ips, "fields": list(self.fields),
            "min_interval_sec": self.throttle.min_interval, "max_per_hour": self.throttle.max_per_hour,
            "messages_sent": self.messages_sent, "digests_sent": self.digests_sent,
            "alerts_notified": self.alerts_notified, "pending": self.throttle.pending_total,
            "failures": self.failures, "last_success": self.last_success, "last_error": self.last_error,
        }


def email_channel(config, policy: DestinationPolicy, timeout: float,
                  clock: Callable[[], float] = time.monotonic) -> NotificationChannel:
    e = config
    port = e.smtp_port or {"starttls": 587, "ssl": 465, "none": 25}[e.security]
    tls = transport.TLSSettings(e.tls.ca_file, e.tls.cert_file, e.tls.key_file, e.tls.verify)

    def deliver(views, total, counts, _classes) -> None:
        message = build_email(views, total, counts, sender=e.sender, recipients=e.recipients,
                              subject_prefix=e.subject_prefix)
        password = os.environ.get(e.password_env) if e.username and e.password_env else None
        if e.username and not password:
            raise ValueError(f"SMTP password variable {e.password_env} is not set")
        transport.deliver_email(policy, message, host=e.smtp_host, port=port, security=e.security, tls=tls,
                                username=e.username, password=password, timeout=timeout)

    return NotificationChannel("email", "email", e, deliver, f"{e.smtp_host}:{port}", clock)


def webhook_channel(destination, policy: DestinationPolicy, timeout: float,
                    clock: Callable[[], float] = time.monotonic) -> NotificationChannel:
    d = destination
    scheme, host, port = webhook_host(d.url)
    tls = transport.TLSSettings(d.tls.ca_file, d.tls.cert_file, d.tls.key_file, d.tls.verify)

    def deliver(views, total, counts, classes) -> None:
        headers = {"Content-Type": "application/json", "User-Agent": f"UniShield/{__version__}"}
        for header, variable in d.headers_from_env.items():
            value = os.environ.get(variable)
            if not value:
                raise ValueError(f"webhook header variable {variable} is not set")
            headers[header] = value
        transport.deliver_http_post(policy, d.url, build_webhook_body(views, total, counts, classes), headers,
                                    timeout, tls, label=f"webhook {d.name!r}")

    return NotificationChannel("webhook", d.name, d, deliver, f"{scheme}://{host}:{port}", clock)
