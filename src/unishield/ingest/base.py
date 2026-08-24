"""
UniShield — Base Input Adapter

Abstract interface for all input readers (PCAP, Zeek, Flow).
Every adapter must produce NormalisedFlow records without sending
any packets or contacting external systems.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import AsyncIterator, Iterator

from unishield.schemas.flow import NormalisedFlow


class BaseReader(ABC):
    """
    Abstract base class for traffic input adapters.

    SECURITY CONSTRAINT: Readers must only READ from files or local
    streams. They must NEVER:
    - Send packets to any network
    - Perform DNS lookups on observed addresses
    - Contact external services
    - Decrypt payload content
    """

    def __init__(self, source_path: Path | str | None = None):
        self.source_path = Path(source_path) if source_path else None
        self._records_read: int = 0
        self._errors: int = 0

    @abstractmethod
    def read(self) -> Iterator[NormalisedFlow]:
        """
        Read records from the source and yield normalised flows.

        Yields:
            NormalisedFlow: Each record normalised to the standard schema.
        """
        ...

    @abstractmethod
    def validate_source(self) -> bool:
        """
        Validate the source file/path exists and is readable.

        Returns:
            True if the source is valid and readable.
        """
        ...

    @property
    def records_read(self) -> int:
        """Number of records successfully read."""
        return self._records_read

    @property
    def errors(self) -> int:
        """Number of read errors encountered."""
        return self._errors

    @property
    def source_type(self) -> str:
        """Return the input source type identifier."""
        return self.__class__.__name__

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(source={self.source_path}, read={self._records_read})"
