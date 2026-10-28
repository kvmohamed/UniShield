"""
UniShield — Login Rate Limiter

Counts failed credential attempts (passwords and X-API-Key values) per
client address in a sliding window; once ``limit`` failures fall inside
``window_sec``, further attempts from that address are refused until the
oldest failure leaves the window. Successful logins do not clear the count,
so knowing one password does not buy more guesses at others.

The state lives in the process: it is reset by a restart and is not shared
between processes (UniShield runs one worker). The per-account lockout in
``AccountStore`` is stored in the database and survives restarts.
"""

from __future__ import annotations

import threading
import time
from collections import OrderedDict, deque
from typing import Callable


class LoginRateLimiter:
    def __init__(self, limit: int, window_sec: float, max_keys: int = 10_000,
                 clock: Callable[[], float] = time.monotonic):
        self.limit, self.window, self.max_keys, self.clock = limit, float(window_sec), max_keys, clock
        self._failures: "OrderedDict[str, deque[float]]" = OrderedDict()
        self._lock = threading.Lock()

    def _recent(self, key: str, now: float) -> deque[float]:
        times = self._failures.get(key)
        if times is None:
            return deque()
        while times and times[0] <= now - self.window:
            times.popleft()
        if not times:
            del self._failures[key]
        return times

    def retry_after(self, key: str) -> float:
        """Seconds until ``key`` may try again; 0 if it may try now."""
        with self._lock:
            now = self.clock()
            times = self._recent(key, now)
            if len(times) < self.limit:
                return 0.0
            return max(0.0, times[-self.limit] + self.window - now)

    def failure(self, key: str) -> bool:
        """Record a failure; True if this failure reached the limit (the address is now blocked)."""
        with self._lock:
            now = self.clock()
            times = self._recent(key, now)
            if key not in self._failures:
                self._failures[key] = times
            times.append(now)
            self._failures.move_to_end(key)
            while len(self._failures) > self.max_keys:
                self._failures.popitem(last=False)
            return len(times) == self.limit
