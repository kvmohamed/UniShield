"""
UniShield — UTC time helpers

All timestamps inside UniShield are timezone-aware UTC. Mixing naive and
aware datetimes raises TypeError on comparison, so every schema normalises
its datetime fields through ``ensure_utc``.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
_MICROSECOND = timedelta(microseconds=1)


def utc_now() -> datetime:
    """Current time as a timezone-aware UTC datetime."""
    return datetime.now(timezone.utc)


def ensure_utc(value: datetime) -> datetime:
    """Treat naive datetimes as UTC; convert aware ones to UTC."""
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def to_epoch_us(value: datetime) -> int:
    """Microseconds since the Unix epoch, exactly (compact, lossless serialisation)."""
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return (value - _EPOCH) // _MICROSECOND            # aware subtraction handles any offset


def from_epoch_us(value: int) -> datetime:
    """Inverse of ``to_epoch_us``: a timezone-aware UTC datetime."""
    return _EPOCH + int(value) * _MICROSECOND
