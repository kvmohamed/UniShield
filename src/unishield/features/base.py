"""
UniShield — Base Feature Extractor

Abstract interface for all feature extraction modules.
Features are computed from normalised flow records within
rolling windows. No future data is used (causal constraint).
"""

from __future__ import annotations

import math
from abc import ABC, abstractmethod
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Callable, Iterable

from unishield.schemas.flow import NormalisedFlow

MIN_OBSERVED_SEC = 1.0


@dataclass(frozen=True)
class WindowContext:
    """Time bounds of the window being analysed."""
    start: datetime
    end: datetime
    observed_seconds: float     # part of [start, end) the input actually covers

    @classmethod
    def from_flows(cls, flows: list[NormalisedFlow]) -> "WindowContext":
        """Context for a bare list of flows (tests, ad-hoc use): span of start times, >= 1 s."""
        start = min(f.timestamp for f in flows)
        span = (max(f.timestamp for f in flows) - start).total_seconds()
        observed = max(span, MIN_OBSERVED_SEC)
        return cls(start=start, end=start + timedelta(seconds=observed), observed_seconds=observed)


def resolve_window(flows: list[NormalisedFlow], window: WindowContext | None) -> WindowContext:
    return window if window is not None else WindowContext.from_flows(flows)


def peak_per_second(
    flows: Iterable[NormalisedFlow],
    window: WindowContext,
    weight: Callable[[NormalisedFlow], float],
) -> float:
    """
    Highest per-second total of ``weight`` within the window.

    Each flow's weight is spread evenly over its duration and only the part
    inside the window counts, so a long transfer is not mistaken for a burst.
    Zero-duration flows count entirely in the second they start.
    """
    horizon = (window.end - window.start).total_seconds()
    bins: dict[int, float] = defaultdict(float)
    for f in flows:
        w = weight(f)
        if not w:
            continue
        start = (f.timestamp - window.start).total_seconds()
        duration = f.duration or 0.0
        if duration <= 0:
            if 0 <= start < horizon:
                bins[math.floor(start)] += w
            continue
        end = start + duration
        lo, hi = max(start, 0.0), min(end, horizon)
        if hi <= lo:
            continue
        rate = w / duration
        for b in range(math.floor(lo), math.ceil(hi)):
            overlap = min(hi, b + 1) - max(lo, b)
            if overlap > 0:
                bins[b] += rate * overlap
    return max(bins.values(), default=0.0)


def entropy(counts: Iterable[float]) -> float:
    """Shannon entropy (bits) of a count distribution."""
    values = [c for c in counts if c > 0]
    total = sum(values)
    if total == 0:
        return 0.0
    return -sum((c / total) * math.log2(c / total) for c in values)


class BaseFeatureExtractor(ABC):
    """
    Abstract base for feature extractors.

    Feature extractors operate on lists of NormalisedFlow records
    within a time window and produce feature dictionaries.

    CONSTRAINT: Features must be computed causally — no future
    records may be used in computation.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Name of this feature extractor."""
        ...

    @property
    @abstractmethod
    def feature_names(self) -> list[str]:
        """List of feature names produced by this extractor."""
        ...

    @abstractmethod
    def extract(self, flows: list[NormalisedFlow], window: WindowContext | None = None) -> dict[str, Any]:
        """
        Extract features from a window of flow records.

        Args:
            flows: List of normalised flow records in the window.
            window: Window bounds; rates use ``window.observed_seconds``.
                When omitted, the span of the flows' start times is used.

        Returns:
            Dictionary mapping feature names to their values.
        """
        ...

    def validate_features(self, features: dict[str, Any]) -> bool:
        """Check that all expected features are present."""
        return all(name in features for name in self.feature_names)
