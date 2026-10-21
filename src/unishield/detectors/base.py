"""
UniShield — Base Detector Interface

Abstract interface for all threat detectors.
Detectors receive feature dictionaries and flow windows,
and produce Alert objects when threats are identified.

SECURITY CONSTRAINTS:
    - Detectors are passive — they never send packets, probe
      endpoints, decrypt payloads, or issue remediation commands.
    - Detectors operate only on extracted features and flow metadata.
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from typing import Any

from unishield.correlation.severity import from_levels as severity_from_levels
from unishield.schemas.alert import Alert, Severity, ThreatClass
from unishield.schemas.flow import NormalisedFlow


class BaseDetector(ABC):
    """
    Abstract base for all threat detectors.

    Each detector:
    1. Receives a window of flows and their extracted features.
    2. Applies detection logic (rule-based, statistical, or ML).
    3. Returns a list of Alert objects (empty if no threats detected).
    """

    #: When True the pipeline runs this detector after the rule detectors and
    #: passes the classes they raised in ``features["rule_alert_classes"]``.
    runs_after_rules: bool = False

    def __init__(self, thresholds: dict[str, Any] | None = None):
        self._thresholds = thresholds or {}
        #: Classes this detector matched in its last call but did not report
        #: because the same finding was reported recently (re-alert suppression).
        #: The pipeline treats such windows as explained.
        self.suppressed_classes: set[ThreatClass] = set()
        self._alerts_generated: int = 0
        self._windows_analysed: int = 0

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique name for this detector."""
        ...

    @property
    @abstractmethod
    def threat_classes(self) -> list[ThreatClass]:
        """Threat classes this detector can identify."""
        ...

    @property
    @abstractmethod
    def mitre_techniques(self) -> list[str]:
        """MITRE ATT&CK technique IDs relevant to this detector."""
        ...

    @property
    def version(self) -> str:
        """Detector version string."""
        return "v1.0.0"

    @abstractmethod
    def detect(
        self,
        flows: list[NormalisedFlow],
        features: dict[str, Any],
        window_start: Any,
        window_end: Any,
    ) -> list[Alert]:
        """
        Run detection on a window of flows.

        Args:
            flows: NormalisedFlow records in the current window.
            features: Pre-extracted feature dictionary.
            window_start: Window start timestamp.
            window_end: Window end timestamp.

        Returns:
            List of Alert objects (empty if no threats detected).
        """
        ...

    def _determine_severity(
        self, metric_value: float, severity_levels: dict[str, dict[str, float]], metric_key: str
    ) -> Severity:
        """
        Determine severity based on threshold levels.

        Checks critical → high → medium → low in order.
        """
        return severity_from_levels(metric_value, severity_levels, metric_key)

    def _measure_latency(self, start_time: float) -> float:
        """Compute detection latency in milliseconds."""
        return (time.time() - start_time) * 1000.0

    @property
    def alerts_generated(self) -> int:
        return self._alerts_generated

    @property
    def windows_analysed(self) -> int:
        return self._windows_analysed

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}("
            f"alerts={self._alerts_generated}, "
            f"windows={self._windows_analysed})"
        )
