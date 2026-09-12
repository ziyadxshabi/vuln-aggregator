"""Celery tasks that run long-lived scan and enrichment work off the request path."""

from __future__ import annotations

import asyncio

from src.config import get_settings
from src.connectors import DEFAULT_NETWORK_SCANNERS
from src.database.base import Database
from src.database.repository import ScanJobRepository
from src.enrichment.cisa_kev import CISAKEVCatalog
from src.observability.logging import get_logger
from src.services.factory import build_cache, build_scan_service
from src.workers.celery_app import celery_app

_logger = get_logger(__name__)


@celery_app.task(name="scans.run", bind=True, max_retries=0)
def run_scan_task(
    self: object,
    job_id: str,
    targets: list[str],
    scanners: list[str],
    profile: str = "home",
    requested_by: str | None = None,
) -> int:
    """Execute an aggregation run for an already-created scan job."""
    return asyncio.run(_run_scan(job_id, targets, scanners, profile=profile, requested_by=requested_by))


async def _run_scan(
    job_id: str,
    targets: list[str],
    scanners: list[str],
    *,
    profile: str = "home",
    requested_by: str | None = None,
) -> int:
    settings = get_settings()
    db = Database(settings.database_url)
    try:
        async with db.session() as session:
            service = build_scan_service(session, db.dialect_name, settings=settings)
            return await service.execute(
                job_id,
                targets,
                scanners,
                profile=profile,
                requested_by=requested_by,
            )
    finally:
        await db.dispose()


@celery_app.task(name="intel.refresh_kev")
def refresh_kev_task() -> int:
    """Refresh the CISA KEV catalog cache."""
    return asyncio.run(_refresh_kev())


async def _refresh_kev() -> int:
    settings = get_settings()
    cache = build_cache(settings)
    catalog = CISAKEVCatalog(cache, settings)
    count = await catalog.refresh()
    _logger.info("kev_refreshed", entries=count)
    return count


@celery_app.task(name="scans.scheduled")
def scheduled_scan_task() -> int:
    """Run a scheduled scan of the configured estate targets."""
    return asyncio.run(_scheduled_scan())


async def _scheduled_scan() -> int:
    settings = get_settings()
    if not settings.scan_targets:
        _logger.info("scheduled_scan_skipped", reason="no SCAN_TARGETS configured")
        return 0
    scanners = list(DEFAULT_NETWORK_SCANNERS)
    profile = settings.scan_profile
    db = Database(settings.database_url)
    try:
        async with db.session() as session:
            job = await ScanJobRepository(session).create(
                settings.scan_targets,
                scanners,
                requested_by="scheduler",
                profile=profile,
            )
        async with db.session() as session:
            service = build_scan_service(session, db.dialect_name, settings=settings)
            return await service.execute(
                job.id,
                settings.scan_targets,
                scanners,
                profile=profile,
                requested_by="scheduler",
            )
    finally:
        await db.dispose()
