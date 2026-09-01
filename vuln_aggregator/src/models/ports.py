"""Ports (interfaces) for the hexagonal architecture.

The application/service layer depends only on these ``Protocol`` definitions,
never on concrete adapters. This keeps domain logic decoupled from FastAPI,
SQLAlchemy, Redis, Celery, and the scanner SDKs.
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

from src.models.enrichment import EnrichmentData
from src.models.enums import ScanStatus, Severity
from src.models.posture import PostureMetrics
from src.models.scan import ScanJob
from src.models.vulnerability import NormalizedVulnerability


@runtime_checkable
class ThreatIntelPort(Protocol):
    """Enriches a set of CVE identifiers with multi-feed intelligence."""

    async def enrich(self, cve_ids: set[str]) -> dict[str, EnrichmentData]: ...


@runtime_checkable
class CachePort(Protocol):
    """A minimal async key/value cache with TTL semantics."""

    async def get_json(self, key: str) -> Any | None: ...

    async def set_json(self, key: str, value: Any, ttl_seconds: int) -> None: ...


@runtime_checkable
class VulnerabilityRepositoryPort(Protocol):
    """Persistence port for normalized findings."""

    async def bulk_upsert(
        self,
        vulns: list[NormalizedVulnerability],
        scan_job_id: str | None = None,
    ) -> int: ...

    async def get(self, vuln_id: str) -> NormalizedVulnerability | None: ...

    async def list(
        self,
        *,
        cursor: str | None = None,
        limit: int = 50,
        severity: Severity | None = None,
        epss_min: float | None = None,
        epss_max: float | None = None,
        asset_group: str | None = None,
        only_known_exploited: bool = False,
    ) -> tuple[list[NormalizedVulnerability], str | None]: ...

    async def posture(self) -> PostureMetrics: ...


@runtime_checkable
class ScanJobRepositoryPort(Protocol):
    """Persistence port for aggregated scan jobs."""

    async def create(self, targets: list[str], scanners: list[str]) -> ScanJob: ...

    async def get(self, job_id: str) -> ScanJob | None: ...

    async def set_status(
        self,
        job_id: str,
        status: ScanStatus,
        *,
        total_findings: int | None = None,
        error: str | None = None,
    ) -> None: ...


@runtime_checkable
class TaskDispatcherPort(Protocol):
    """Dispatches long-running scan work to a background worker pool."""

    def dispatch_scan(self, job_id: str, targets: list[str], scanners: list[str]) -> str: ...
