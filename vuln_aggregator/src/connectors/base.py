"""Abstract scanner connector (a driven port implemented by each adapter)."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import ClassVar

from src.models.enums import ScanStatus
from src.models.vulnerability import NormalizedVulnerability


class BaseScannerConnector(ABC):
    """Contract every scanner adapter must satisfy.

    Concrete adapters translate a vendor API (GMP XML, Tenable JSON, Trivy
    JSON, ...) into the platform's :class:`NormalizedVulnerability` model. The
    three-method lifecycle (start -> poll -> fetch) lets the orchestration
    layer treat all scanners uniformly.
    """

    #: Stable identifier used in fingerprints and connector registries.
    scanner_name: ClassVar[str]

    @abstractmethod
    async def start_scan(self, target: str) -> str:
        """Launch a scan against ``target`` and return an opaque job identifier."""

    @abstractmethod
    async def check_scan_status(self, job_id: str) -> ScanStatus:
        """Return the current lifecycle state of a previously started job."""

    @abstractmethod
    async def fetch_and_normalize(self, job_id: str) -> list[NormalizedVulnerability]:
        """Fetch a completed job's report and normalize it into the domain model."""
