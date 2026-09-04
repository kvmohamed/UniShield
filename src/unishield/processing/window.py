"""
UniShield — Streaming Window Manager

Manages rolling (sliding) windows of NormalisedFlow records for
incremental, streaming analysis.

DESIGN:
    - Window is defined by (window_size_sec, slide_interval_sec).
    - Records are inserted as they arrive.
    - When the window slides, the oldest records outside the current
      window boundary are evicted.
    - Multiple concurrent windows can exist (per-source-IP, global, etc.).

SECURITY CONSTRAINTS:
    - No network communication.
    - Records are processed incrementally (causal — no future data).
"""

from __future__ import annotations

import logging
import time
from collections import deque
from datetime import datetime, timedelta, timezone
from typing import Callable, Optional

from unishield.schemas.flow import NormalisedFlow

logger = logging.getLogger("unishield.processing.window")


class SlidingWindow:
    """
    Time-based sliding window for flow records.

    Records are maintained in a deque sorted by timestamp.
    The window emits batches when the slide interval elapses.
    """

    def __init__(
        self,
        window_size_sec: int = 10,
        slide_interval_sec: int = 5,
        max_records: int = 50000,
    ):
        self.window_size = timedelta(seconds=window_size_sec)
        self.slide_interval = timedelta(seconds=slide_interval_sec)
        self.max_records = max_records

        self._records: deque[NormalisedFlow] = deque()
        self._window_start: Optional[datetime] = None
        self._window_end: Optional[datetime] = None
        self._last_slide: Optional[datetime] = None
        self._total_ingested: int = 0
        self._total_evicted: int = 0
        self._window_count: int = 0

    @property
    def size(self) -> int:
        """Number of records currently in the window."""
        return len(self._records)

    @property
    def total_ingested(self) -> int:
        return self._total_ingested

    @property
    def total_evicted(self) -> int:
        return self._total_evicted

    @property
    def window_count(self) -> int:
        """Number of windows emitted so far."""
        return self._window_count

    @property
    def window_start(self) -> Optional[datetime]:
        return self._window_start

    @property
    def window_end(self) -> Optional[datetime]:
        return self._window_end

    def add(self, flow: NormalisedFlow) -> None:
        """
        Add a flow record to the window.

        If the window is at capacity, the oldest record is evicted
        regardless of time (backpressure).
        """
        self._total_ingested += 1

        # Initialise window on first record
        if self._window_start is None:
            self._window_start = flow.timestamp
            self._window_end = flow.timestamp + self.window_size

        self._records.append(flow)

        # Backpressure: evict oldest if over capacity
        if len(self._records) > self.max_records:
            self._records.popleft()
            self._total_evicted += 1

    def should_emit(self, current_time: datetime) -> bool:
        """
        Check if enough time has elapsed to emit a new window.
        """
        if self._window_start is None:
            return False

        if self._last_slide is None:
            # First slide happens after the window fills
            return current_time >= self._window_start + self.window_size

        return current_time >= self._last_slide + self.slide_interval

    def emit(self, current_time: datetime) -> list[NormalisedFlow]:
        """
        Emit the current window contents and slide forward.

        Returns the list of records in the current window.
        Evicts records that fall outside the new window boundary.
        """
        if self._window_start is None:
            return []

        # The window covers [current_time - window_size, current_time]
        window_boundary = current_time - self.window_size

        # Collect records within the window
        window_records = [
            r for r in self._records
            if r.timestamp >= window_boundary
        ]

        # Evict old records
        evict_count = 0
        while self._records and self._records[0].timestamp < window_boundary:
            self._records.popleft()
            evict_count += 1

        self._total_evicted += evict_count
        self._last_slide = current_time
        self._window_start = window_boundary
        self._window_end = current_time
        self._window_count += 1

        logger.debug(
            "Window %d emitted: %d records, evicted %d, boundary=%s",
            self._window_count,
            len(window_records),
            evict_count,
            window_boundary.isoformat(),
        )

        return window_records

    def get_current_records(self) -> list[NormalisedFlow]:
        """Return a snapshot of all records currently in the window."""
        return list(self._records)

    def clear(self) -> None:
        """Clear all records and reset the window."""
        self._records.clear()
        self._window_start = None
        self._window_end = None
        self._last_slide = None

    def stats(self) -> dict:
        """Return window statistics."""
        return {
            "size": self.size,
            "total_ingested": self._total_ingested,
            "total_evicted": self._total_evicted,
            "window_count": self._window_count,
            "window_start": self._window_start.isoformat() if self._window_start else None,
            "window_end": self._window_end.isoformat() if self._window_end else None,
        }


class WindowManager:
    """
    Manages multiple sliding windows and coordinates record distribution.

    Provides a global window and optional per-key windows (e.g., per source IP).
    """

    def __init__(
        self,
        window_size_sec: int = 10,
        slide_interval_sec: int = 5,
        max_records: int = 50000,
        enable_per_source_windows: bool = False,
        max_tracked_sources: int = 10000,
    ):
        self.window_size_sec = window_size_sec
        self.slide_interval_sec = slide_interval_sec
        self.max_records = max_records
        self.enable_per_source = enable_per_source_windows
        self.max_tracked_sources = max_tracked_sources

        # Global window
        self.global_window = SlidingWindow(
            window_size_sec=window_size_sec,
            slide_interval_sec=slide_interval_sec,
            max_records=max_records,
        )

        # Per-source-IP windows (optional)
        self._source_windows: dict[str, SlidingWindow] = {}

    def add(self, flow: NormalisedFlow) -> None:
        """Add a flow record to all applicable windows."""
        self.global_window.add(flow)

        if self.enable_per_source:
            key = flow.source_ip
            if key not in self._source_windows:
                if len(self._source_windows) >= self.max_tracked_sources:
                    # Evict the least recently used source window
                    oldest_key = next(iter(self._source_windows))
                    del self._source_windows[oldest_key]

                self._source_windows[key] = SlidingWindow(
                    window_size_sec=self.window_size_sec,
                    slide_interval_sec=self.slide_interval_sec,
                    max_records=self.max_records // 10,
                )

            self._source_windows[key].add(flow)

    def get_source_window(self, source_ip: str) -> Optional[SlidingWindow]:
        """Get the per-source window for a given IP."""
        return self._source_windows.get(source_ip)

    def get_active_source_count(self) -> int:
        """Return the number of tracked source IPs."""
        return len(self._source_windows)

    def clear(self) -> None:
        """Clear all windows."""
        self.global_window.clear()
        self._source_windows.clear()

    def stats(self) -> dict:
        """Return manager statistics."""
        return {
            "global": self.global_window.stats(),
            "tracked_sources": len(self._source_windows),
        }
