"""
UniShield — Base Feature Extractor

Abstract interface for all feature extraction modules.
Features are computed from normalised flow records within
rolling windows. No future data is used (causal constraint).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from unishield.schemas.flow import NormalisedFlow


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
    def extract(self, flows: list[NormalisedFlow]) -> dict[str, Any]:
        """
        Extract features from a window of flow records.

        Args:
            flows: List of normalised flow records in the window.

        Returns:
            Dictionary mapping feature names to their values.
        """
        ...

    def validate_features(self, features: dict[str, Any]) -> bool:
        """Check that all expected features are present."""
        return all(name in features for name in self.feature_names)
