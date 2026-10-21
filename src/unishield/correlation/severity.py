"""
UniShield — Severity helpers

Ordering, comparison and escalation of alert severities, and threshold-based
severity assignment shared by all detectors and the correlator.
"""

from __future__ import annotations

from typing import Iterable, Mapping

from unishield.schemas.alert import Severity

ORDER: tuple[Severity, ...] = (Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL)
RANK: dict[Severity, int] = {s: i for i, s in enumerate(ORDER)}


def max_severity(severities: Iterable[Severity]) -> Severity:
    """Highest severity in ``severities`` (INFO if empty)."""
    return max(severities, key=RANK.__getitem__, default=Severity.INFO)


def at_least(severity: Severity, floor: Severity) -> Severity:
    """``severity``, raised to ``floor`` if lower."""
    return severity if RANK[severity] >= RANK[floor] else floor


def escalate(severity: Severity, steps: int = 1) -> Severity:
    """Raise a severity by ``steps`` levels, capped at CRITICAL."""
    return ORDER[min(RANK[severity] + steps, len(ORDER) - 1)]


def from_levels(
    value: float,
    levels: Mapping[str, Mapping[str, float]],
    key: str,
    default: Severity = Severity.LOW,
) -> Severity:
    """
    Severity from threshold levels, e.g. ``{"critical": {key: 100}, "high": {key: 50}}``:
    the highest level whose threshold ``value`` reaches, else ``default``.
    """
    for name in ("critical", "high", "medium", "low"):
        threshold = levels.get(name, {}).get(key)
        if threshold is not None and value >= threshold:
            return Severity(name.upper())
    return default
