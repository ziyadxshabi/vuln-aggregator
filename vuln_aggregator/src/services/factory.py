"""Composition helpers that wire concrete adapters into the ScanService.

Kept separate from the service itself so the use case stays free of
infrastructure knowledge.
"""

from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncSession

from src.config import Settings, get_settings
from src.connectors import CONNECTOR_REGISTRY, scanner_is_ready
from src.connectors.base import BaseScannerConnector
from src.database.repository import AssetRepository, ScanJobRepository, VulnerabilityRepository
from src.enrichment.cache import InMemoryTTLCache, RedisTTLCache
from src.enrichment.pipeline import EnrichmentPipeline, build_default_pipeline
from src.models.ports import CachePort
from src.services.scan_service import ScanService


def build_connectors(settings: Settings) -> dict[str, BaseScannerConnector]:
    """Instantiate every registered scanner connector."""
    return {name: cls(settings) for name, cls in CONNECTOR_REGISTRY.items()}


def build_cache(settings: Settings) -> CachePort:
    """Redis-backed cache in normal operation; in-memory as a safe fallback."""
    try:
        return RedisTTLCache(settings.redis_url)
    except Exception:  # noqa: BLE001 - redis optional/unavailable
        return InMemoryTTLCache()


def build_scan_service(
    session: AsyncSession,
    dialect_name: str,
    *,
    settings: Settings | None = None,
    pipeline: EnrichmentPipeline | None = None,
) -> ScanService:
    """Assemble a fully wired :class:`ScanService` for a worker/request."""
    resolved = settings or get_settings()
    cache = build_cache(resolved)
    enrichment = pipeline or build_default_pipeline(resolved, cache)
    return ScanService(
        vuln_repo=VulnerabilityRepository(session, dialect_name),
        job_repo=ScanJobRepository(session),
        asset_repo=AssetRepository(session, dialect_name),
        connectors=build_connectors(resolved),
        enrichment=enrichment,
        allowlist=list(resolved.scan_allowlist),
        scanner_ready=lambda name: scanner_is_ready(name, resolved),
        poll_interval_seconds=resolved.scan_poll_interval_seconds,
        poll_timeout_seconds=resolved.scan_poll_timeout_seconds,
    )
