"""
UniShield — Event-Time Sliding Window

Groups flow records into overlapping time windows for analysis.

DESIGN:
    - Windows are aligned to a fixed grid in traffic (event) time: every
      ``slide_interval_sec`` a window ``[end - window_size_sec, end)`` closes.
    - A window closes once the watermark — the latest record time seen minus
      ``allowed_lateness_sec`` — has passed its end. ``advance()`` moves the
      watermark without a record (for clock-driven closing on live input).
    - ``flush()`` closes the remaining windows at end of input, so short
      captures and attacks at the end of a file are still analysed.
    - A record older than every still-open window is "late": it is dropped
      and counted, never silently lost.
    - Each closed window reports ``observed_seconds``: how much of it lies
      within the span the input actually covers. Rates are computed over this
      (not over first-to-last record time), so one flow after a quiet period
      is not mistaken for a flood, and a 3-second capture is not diluted to
      10 seconds. A 1-second floor prevents tiny denominators.
    - Windows with no records are skipped (counted in ``empty_windows``).

SECURITY CONSTRAINTS:
    - No network communication.
    - Records are processed incrementally (causal — no future data).
"""

from __future__ import annotations

import bisect
import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Optional

from unishield.schemas.flow import NormalisedFlow

logger = logging.getLogger("unishield.processing.window")

_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


@dataclass(frozen=True)
class Window:
    """One closed analysis window."""
    index: int
    start: datetime
    end: datetime
    records: list[NormalisedFlow]
    observed_seconds: float


def _ts(flow: NormalisedFlow) -> datetime:
    return flow.timestamp


class SlidingWindow:
    """Event-time sliding window over flow records."""

    def __init__(
        self,
        window_size_sec: int = 10,
        slide_interval_sec: int = 5,
        max_records: int = 50000,
        allowed_lateness_sec: float = 0.0,
        min_observed_sec: float = 1.0,
    ):
        if slide_interval_sec <= 0 or window_size_sec < slide_interval_sec:
            raise ValueError("need 0 < slide_interval_sec <= window_size_sec")
        self.window_size = timedelta(seconds=window_size_sec)
        self.slide_interval = timedelta(seconds=slide_interval_sec)
        self.allowed_lateness = timedelta(seconds=allowed_lateness_sec)
        self.max_records = max_records
        self.min_observed_sec = min_observed_sec

        self._records: list[NormalisedFlow] = []      # sorted by timestamp
        self._next_end: Optional[datetime] = None
        self._observed_from: Optional[datetime] = None
        self._watermark: Optional[datetime] = None

        self.total_ingested = 0
        self.late_dropped = 0
        self.overflow_evicted = 0
        self.windows_emitted = 0
        self.empty_windows = 0

    # ------------------------------------------------------------------ API

    @property
    def size(self) -> int:
        """Records currently held."""
        return len(self._records)

    def add(self, flow: NormalisedFlow) -> list[Window]:
        """Add a record; return the windows its event time closes."""
        self.total_ingested += 1
        ts = flow.timestamp
        if self._next_end is None:
            self._observed_from = ts
            self._next_end = self._boundary_after(ts)
        elif ts < self._next_end - self.window_size:
            self.late_dropped += 1
            if self.late_dropped == 1:
                logger.warning(
                    "Dropping records older than the open windows (first: %s); "
                    "increase processing.allowed_lateness_sec for unordered input", ts.isoformat())
            return []

        if self._records and ts >= self._records[-1].timestamp:
            self._records.append(flow)
        else:
            bisect.insort(self._records, flow, key=_ts)
        if len(self._records) > self.max_records:
            del self._records[0]
            self.overflow_evicted += 1

        if self._watermark is None or ts > self._watermark:
            self._watermark = ts
        return self._close_until(self._watermark - self.allowed_lateness)

    def advance(self, now: datetime) -> list[Window]:
        """Move event time forward without a record (e.g. on a clock tick)."""
        if self._next_end is None:
            return []
        if self._watermark is None or now > self._watermark:
            self._watermark = now
        return self._close_until(self._watermark - self.allowed_lateness)

    def flush(self) -> list[Window]:
        """End of input: close every window that still holds records."""
        closed: list[Window] = []
        while self._records:
            closed.extend(self._close_until(self._next_end))
        return closed

    def stats(self) -> dict:
        return {
            "window_size_sec": self.window_size.total_seconds(),
            "slide_interval_sec": self.slide_interval.total_seconds(),
            "allowed_lateness_sec": self.allowed_lateness.total_seconds(),
            "records_held": len(self._records),
            "total_ingested": self.total_ingested,
            "windows_emitted": self.windows_emitted,
            "empty_windows": self.empty_windows,
            "late_dropped": self.late_dropped,
            "overflow_evicted": self.overflow_evicted,
            "watermark": self._watermark.isoformat() if self._watermark else None,
        }

    # ------------------------------------------------------------ internals

    def _boundary_after(self, ts: datetime) -> datetime:
        """First grid boundary strictly after ``ts``."""
        slides = (ts - _EPOCH) // self.slide_interval
        return _EPOCH + (slides + 1) * self.slide_interval

    def _close_until(self, until: datetime) -> list[Window]:
        closed: list[Window] = []
        while self._next_end <= until:
            if not self._records:
                self._skip_to(self._boundary_after(until))
                break
            first = self._records[0].timestamp
            if first >= self._next_end:
                # No records before this end: jump to the first window holding one.
                self._skip_to(min(self._boundary_after(first), self._boundary_after(until)))
                continue
            closed.append(self._close_next())
        return closed

    def _skip_to(self, new_end: datetime) -> None:
        if new_end > self._next_end:
            self.empty_windows += (new_end - self._next_end) // self.slide_interval
            self._next_end = new_end

    def _close_next(self) -> Window:
        end = self._next_end
        start = end - self.window_size
        keys = [r.timestamp for r in self._records]
        lo = bisect.bisect_left(keys, start)
        hi = bisect.bisect_left(keys, end)
        records = self._records[lo:hi]

        observed_until = min(end, self._watermark)
        observed = (observed_until - max(start, self._observed_from)).total_seconds()
        window = Window(
            index=self.windows_emitted,
            start=start,
            end=end,
            records=records,
            observed_seconds=max(observed, self.min_observed_sec),
        )
        self.windows_emitted += 1

        self._next_end = end + self.slide_interval
        keep_from = bisect.bisect_left(keys, self._next_end - self.window_size)
        del self._records[:keep_from]
        logger.debug("Window %d [%s, %s): %d records", window.index, start.isoformat(),
                     end.isoformat(), len(records))
        return window
