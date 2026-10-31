"""
UniShield — Analyst Feedback Storage

Verdicts: one per alert (the latest), set by an analyst with an optional
note; deleted with the alert. ``true_positive`` and ``benign_true_positive``
(real activity that is authorised, e.g. a scheduled scan) both mean the
detection was right; ``false_positive`` means it was not. The review
summary turns them into a reviewed precision per detector and class, and
the export gives labelled alerts for threshold tuning or retraining.

Suppression rules: a threat class plus a source and/or destination (an
address, a CIDR range, or an anonymised address hash), optionally one
detector, with a reason and an expiry (at most ``max_days``). Alerts they
match are stored and marked, not dropped, so a suppression can always be
reviewed. Alerts that matched imported threat intelligence are never
suppressed. Every change goes through the API's audit log.
"""

from __future__ import annotations

import ipaddress
import threading
import time
from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from sqlalchemy import delete, func, insert, select, update
from sqlalchemy.engine import Engine

from unishield.schemas.alert import Alert, ThreatClass
from unishield.schemas.timeutil import utc_now
from unishield.storage.database import (
    alert_feedback_table,
    alerts_table,
    suppression_rules_table,
    write_lock,
)

VERDICTS = ("true_positive", "benign_true_positive", "false_positive")
CONFIRMED = ("true_positive", "benign_true_positive")
_HASH_CHARS = set("0123456789abcdef")


def _naive(value: datetime) -> datetime:
    return value.astimezone(timezone.utc).replace(tzinfo=None) if value.tzinfo else value


def _aware(value: Optional[datetime]) -> Optional[str]:
    return value.replace(tzinfo=timezone.utc).isoformat() if isinstance(value, datetime) else None


class FeedbackStore:
    """Analyst verdicts on stored alerts."""

    def __init__(self, engine: Engine):
        self.engine = engine
        self._lock = write_lock(engine)

    @staticmethod
    def _row(row) -> dict[str, Any]:
        data = dict(row._mapping)
        for key in ("created_at", "updated_at"):
            data[key] = _aware(data.get(key))
        return data

    def set_verdict(self, alert_id: str, verdict: str, analyst: str, note: Optional[str] = None) -> dict[str, Any]:
        if verdict not in VERDICTS:
            raise ValueError(f"verdict must be one of {VERDICTS}")
        now = _naive(utc_now())
        t = alert_feedback_table
        with self._lock, self.engine.begin() as conn:
            if conn.execute(select(alerts_table.c.alert_id).where(alerts_table.c.alert_id == alert_id)).first() \
                    is None:
                raise KeyError(alert_id)
            values = {"verdict": verdict, "note": note or None, "analyst": analyst, "updated_at": now}
            if conn.execute(select(t.c.alert_id).where(t.c.alert_id == alert_id)).first() is None:
                conn.execute(insert(t).values(alert_id=alert_id, created_at=now, **values))
            else:
                conn.execute(update(t).where(t.c.alert_id == alert_id).values(**values))
        return self.get(alert_id)

    def get(self, alert_id: str) -> Optional[dict[str, Any]]:
        t = alert_feedback_table
        with self.engine.connect() as conn:
            row = conn.execute(select(t).where(t.c.alert_id == alert_id)).first()
        return self._row(row) if row is not None else None

    def get_many(self, alert_ids: list[str]) -> dict[str, dict[str, Any]]:
        if not alert_ids:
            return {}
        t = alert_feedback_table
        with self.engine.connect() as conn:
            rows = conn.execute(select(t).where(t.c.alert_id.in_(alert_ids))).all()
        return {r.alert_id: self._row(r) for r in rows}

    def clear(self, alert_id: str) -> bool:
        with self._lock, self.engine.begin() as conn:
            return bool(conn.execute(delete(alert_feedback_table)
                                     .where(alert_feedback_table.c.alert_id == alert_id)).rowcount)

    def summary(self) -> dict[str, Any]:
        """Reviewed precision per detector and threat class (alerts suppressed by a rule excluded)."""
        a, f = alerts_table.c, alert_feedback_table.c
        visible = a.suppressed_by.is_(None)
        with self.engine.connect() as conn:
            totals = conn.execute(select(a.detector_name, a.threat_class, func.count())
                                  .where(visible).group_by(a.detector_name, a.threat_class)).all()
            reviewed = conn.execute(
                select(a.detector_name, a.threat_class, f.verdict, func.count())
                .select_from(alerts_table.join(alert_feedback_table, a.alert_id == f.alert_id))
                .where(visible).group_by(a.detector_name, a.threat_class, f.verdict)).all()
        verdicts: dict[tuple[str, str], Counter] = {}
        for detector, threat, verdict, n in reviewed:
            verdicts.setdefault((detector, threat), Counter())[verdict] += int(n)
        rows = []
        overall: Counter = Counter()
        for detector, threat, total in sorted(totals):
            counts = verdicts.get((detector, threat), Counter())
            confirmed = sum(counts[v] for v in CONFIRMED)
            judged = confirmed + counts["false_positive"]
            overall.update(counts)
            overall["alerts"] += int(total)
            rows.append({
                "detector": detector, "threat_class": threat, "alerts": int(total), "reviewed": judged,
                **{v: counts[v] for v in VERDICTS},
                "reviewed_precision": round(confirmed / judged, 3) if judged else None,
            })
        judged = sum(overall[v] for v in VERDICTS)
        confirmed = sum(overall[v] for v in CONFIRMED)
        return {
            "alerts": overall["alerts"], "reviewed": judged, **{v: overall[v] for v in VERDICTS},
            "reviewed_precision": round(confirmed / judged, 3) if judged else None,
            "by_detector": rows,
            "note": "Precision among reviewed alerts only; it is biased towards whichever alerts analysts chose to "
                    "review and says nothing about missed attacks.",
        }

    def labelled(self, verdict: Optional[str] = None, limit: int = 100_000) -> list[dict[str, Any]]:
        """Reviewed alerts with their verdicts, oldest first."""
        a, f = alerts_table.c, alert_feedback_table.c
        stmt = (select(alerts_table, f.verdict, f.note, f.analyst, f.updated_at.label("reviewed_at"))
                .select_from(alerts_table.join(alert_feedback_table, a.alert_id == f.alert_id))
                .order_by(a.window_end, a.alert_id).limit(limit))
        if verdict is not None:
            stmt = stmt.where(f.verdict == verdict)
        out = []
        with self.engine.connect() as conn:
            for row in conn.execute(stmt).all():
                data = dict(row._mapping)
                for key, value in list(data.items()):
                    if isinstance(value, datetime):
                        data[key] = _aware(value)
                out.append(data)
        return out


def _check_endpoint(value: Optional[str]) -> Optional[str]:
    """An address, a CIDR range or an anonymised address hash; None stays None."""
    if value is None or value == "":
        return None
    value = value.strip()
    if len(value) > 64:
        raise ValueError("address too long")
    try:
        return str(ipaddress.ip_network(value, strict=False)) if "/" in value else str(ipaddress.ip_address(value))
    except ValueError:
        if 8 <= len(value) <= 64 and set(value) <= _HASH_CHARS:
            return value                                         # anonymised address (security.anonymize_ips)
        raise ValueError(f"{value!r} is not an IP address, CIDR range or address hash") from None


def _endpoint_matches(rule_value: Optional[str], observed: Optional[str]) -> bool:
    if rule_value is None:
        return True
    if observed is None:
        return False
    if rule_value == observed:
        return True
    if "/" in rule_value:
        try:
            return ipaddress.ip_address(observed) in ipaddress.ip_network(rule_value)
        except ValueError:
            return False
    return False


class SuppressionStore:
    """Scoped, expiring suppression rules and the matching of new alerts against them."""

    def __init__(self, engine: Engine, max_days: int = 90, cache_sec: float = 5.0):
        self.engine = engine
        self._lock = write_lock(engine)
        self.max_days = max_days
        self.cache_sec = cache_sec
        self._active: Optional[list[dict[str, Any]]] = None
        self._loaded_at = 0.0
        self._cache_lock = threading.Lock()

    @staticmethod
    def _row(row) -> dict[str, Any]:
        data = dict(row._mapping)
        for key in ("created_at", "expires_at", "last_hit_at"):
            data[key] = _aware(data.get(key))
        return data

    def _invalidate(self) -> None:
        with self._cache_lock:
            self._active = None

    def create(self, *, threat_class: str, reason: str, created_by: str, days: int,
               source: Optional[str] = None, destination: Optional[str] = None,
               detector_name: Optional[str] = None, from_alert_id: Optional[str] = None) -> dict[str, Any]:
        threat = ThreatClass(threat_class).value
        if threat == ThreatClass.INTEL_MATCH.value:
            raise ValueError("threat-intel matches cannot be suppressed; remove the indicator instead")
        source, destination = _check_endpoint(source), _check_endpoint(destination)
        if source is None and destination is None:
            raise ValueError("give a source or a destination: a whole threat class is tuned with thresholds or "
                             "asset roles, not suppressed")
        if not 1 <= days <= self.max_days:
            raise ValueError(f"days must be between 1 and {self.max_days}")
        reason = (reason or "").strip()
        if len(reason) < 5:
            raise ValueError("give a reason (at least 5 characters)")
        now = _naive(utc_now())
        values = {"threat_class": threat, "source": source, "destination": destination,
                  "detector_name": detector_name or None, "reason": reason[:500], "from_alert_id": from_alert_id,
                  "created_by": created_by, "created_at": now, "expires_at": now + timedelta(days=days),
                  "enabled": True, "hits": 0}
        with self._lock, self.engine.begin() as conn:
            rule_id = conn.execute(insert(suppression_rules_table).values(**values)).inserted_primary_key[0]
        self._invalidate()
        return self.get(int(rule_id))

    def get(self, rule_id: int) -> Optional[dict[str, Any]]:
        t = suppression_rules_table
        with self.engine.connect() as conn:
            row = conn.execute(select(t).where(t.c.id == rule_id)).first()
        return self._row(row) if row is not None else None

    def list(self, include_expired: bool = True) -> list[dict[str, Any]]:
        t = suppression_rules_table
        stmt = select(t).order_by(t.c.created_at.desc(), t.c.id.desc())
        if not include_expired:
            stmt = stmt.where(t.c.expires_at > _naive(utc_now()))
        with self.engine.connect() as conn:
            rules = [self._row(r) for r in conn.execute(stmt).all()]
        now = utc_now().isoformat()
        for rule in rules:
            rule["active"] = bool(rule["enabled"]) and rule["expires_at"] > now
        return rules

    def set_enabled(self, rule_id: int, enabled: bool) -> Optional[dict[str, Any]]:
        t = suppression_rules_table
        with self._lock, self.engine.begin() as conn:
            changed = conn.execute(update(t).where(t.c.id == rule_id).values(enabled=enabled)).rowcount
        self._invalidate()
        return self.get(rule_id) if changed else None

    def delete(self, rule_id: int) -> bool:
        with self._lock, self.engine.begin() as conn:
            deleted = conn.execute(delete(suppression_rules_table)
                                   .where(suppression_rules_table.c.id == rule_id)).rowcount
        self._invalidate()
        return bool(deleted)

    def _active_rules(self) -> list[dict[str, Any]]:
        with self._cache_lock:
            if self._active is None or time.monotonic() - self._loaded_at > self.cache_sec:
                t = suppression_rules_table
                with self.engine.connect() as conn:
                    rows = conn.execute(select(t).where(t.c.enabled.is_(True),
                                                        t.c.expires_at > _naive(utc_now()))).all()
                self._active = [dict(r._mapping) for r in rows]
                self._loaded_at = time.monotonic()
            return self._active

    def match(self, alert: Alert) -> Optional[int]:
        """Id of the first active rule matching the alert (never for alerts with threat-intel matches)."""
        if alert.threat_class == ThreatClass.INTEL_MATCH or (alert.evidence or {}).get("intel_matches"):
            return None
        now = _naive(utc_now())
        for rule in self._active_rules():
            if (rule["threat_class"] == alert.threat_class.value and rule["expires_at"] > now
                    and (rule["detector_name"] is None or rule["detector_name"] == alert.detector_name)
                    and _endpoint_matches(rule["source"], alert.source_ip)
                    and _endpoint_matches(rule["destination"], alert.destination_ip)):
                return int(rule["id"])
        return None

    def record_hit(self, rule_id: int) -> None:
        t = suppression_rules_table
        with self._lock, self.engine.begin() as conn:
            conn.execute(update(t).where(t.c.id == rule_id).values(hits=t.c.hits + 1,
                                                                   last_hit_at=_naive(utc_now())))
