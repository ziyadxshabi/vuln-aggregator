"""The core scan use case: orchestrate -> normalize -> enrich -> score -> persist.

This service depends only on ports (repositories, threat-intel) and the
scanner connector abstraction, keeping it independent of FastAPI, Celery, and
concrete infrastructure.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable

from src.connectors.base import BaseScannerConnector
from src.engine.risk_engine import compute_risk
from src.models.enrichment import EnrichmentData
from src.models.enums import ScanStatus
from src.models.ports import (
    ScanJobRepositoryPort,
    ThreatIntelPort,
    VulnerabilityRepositoryPort,
)
from src.models.vulnerability import NormalizedVulnerability, RiskResult, RiskSignal
from src.observability.logging import get_logger

_logger = get_logger(__name__)


class ScanService:
    """Coordinates a full aggregation run for a single scan job."""

    def __init__(
        self,
        vuln_repo: VulnerabilityRepositoryPort,
        job_repo: ScanJobRepositoryPort,
        connectors: dict[str, BaseScannerConnector],
        enrichment: ThreatIntelPort,
        *,
        poll_interval_seconds: float = 10.0,
        poll_timeout_seconds: float = 7_200.0,
        asset_criticality_multiplier: float = 1.0,
        risk_fn: Callable[[RiskSignal], RiskResult] = compute_risk,
    ) -> None:
        self._vuln_repo = vuln_repo
        self._job_repo = job_repo
        self._connectors = connectors
        self._enrichment = enrichment
        self._poll_interval = poll_interval_seconds
        self._poll_timeout = poll_timeout_seconds
        self._asset_multiplier = asset_criticality_multiplier
        self._risk_fn = risk_fn

    async def execute(self, job_id: str, targets: list[str], scanners: list[str]) -> int:
        """Run the full pipeline and persist results. Returns findings stored."""
        await self._job_repo.set_status(job_id, ScanStatus.RUNNING)
        try:
            findings = await self._collect(targets, scanners)
            await self._enrich(findings)
            self._score(findings)
            stored = await self._vuln_repo.bulk_upsert(findings, scan_job_id=job_id)
            await self._job_repo.set_status(
                job_id, ScanStatus.COMPLETED, total_findings=stored
            )
            _logger.info("scan_completed", job_id=job_id, findings=stored)
            return stored
        except Exception as exc:  # noqa: BLE001 - persisted then re-raised
            await self._job_repo.set_status(job_id, ScanStatus.FAILED, error=str(exc))
            _logger.exception("scan_failed", job_id=job_id)
            raise

    async def _collect(
        self, targets: list[str], scanners: list[str]
    ) -> list[NormalizedVulnerability]:
        tasks = [
            self._scan_one(self._connectors[name], target)
            for name in scanners
            if name in self._connectors
            for target in targets
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        findings: list[NormalizedVulnerability] = []
        for result in results:
            if isinstance(result, BaseException):
                _logger.warning("scanner_task_failed", error=str(result))
                continue
            findings.extend(result)
        return findings

    async def _scan_one(
        self, connector: BaseScannerConnector, target: str
    ) -> list[NormalizedVulnerability]:
        job_id = await connector.start_scan(target)
        await self._poll(connector, job_id, target)
        return await connector.fetch_and_normalize(job_id)

    async def _poll(self, connector: BaseScannerConnector, job_id: str, target: str) -> None:
        loop = asyncio.get_running_loop()
        deadline = loop.time() + self._poll_timeout
        while True:
            status = await connector.check_scan_status(job_id)
            if status is ScanStatus.COMPLETED:
                return
            if status is ScanStatus.FAILED:
                raise RuntimeError(f"{connector.scanner_name} scan failed for {target!r}")
            if loop.time() > deadline:
                raise TimeoutError(
                    f"{connector.scanner_name} scan on {target!r} exceeded "
                    f"{self._poll_timeout:.0f}s"
                )
            await asyncio.sleep(self._poll_interval)

    async def _enrich(self, findings: list[NormalizedVulnerability]) -> None:
        cve_ids = {f.cve_id for f in findings if f.cve_id}
        if not cve_ids:
            return
        intel = await self._enrichment.enrich(cve_ids)
        for finding in findings:
            if finding.cve_id and finding.cve_id.upper() in intel:
                _apply_enrichment(finding, intel[finding.cve_id.upper()])

    def _score(self, findings: list[NormalizedVulnerability]) -> None:
        for finding in findings:
            result = self._risk_fn(finding.to_risk_signal(self._asset_multiplier))
            finding.risk_score = result.score
            finding.risk_tier = result.tier


def _apply_enrichment(finding: NormalizedVulnerability, data: EnrichmentData) -> None:
    finding.epss_score = data.epss_score
    finding.epss_percentile = data.epss_percentile
    finding.is_known_exploited = data.is_known_exploited
    finding.has_weaponized_exploit = data.has_weaponized_exploit
    if finding.cvss_v3_score is None and data.cvss_v3_score is not None:
        finding.cvss_v3_score = data.cvss_v3_score
    if finding.cvss_v3_vector is None and data.cvss_v3_vector is not None:
        finding.cvss_v3_vector = data.cvss_v3_vector
    merged = list(finding.enrichment_sources)
    for source in data.sources:
        if source not in merged:
            merged.append(source)
    finding.enrichment_sources = merged
