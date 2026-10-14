"""
UniShield — UTC time helpers

All timestamps inside UniShield are timezone-aware UTC. Mixing naive and
aware datetimes raises TypeError on comparison, so every schema normalises
its datetime fields through ``ensure_utc``.
"""

from __future__ import annotations

from datetime import datetime, timezone


def utc_now() -> datetime:
    """Current time as a timezone-aware UTC datetime."""
    return datetime.now(timezone.utc)


def ensure_utc(value: datetime) -> datetime:
    """Treat naive datetimes as UTC; convert aware ones to UTC."""
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)
