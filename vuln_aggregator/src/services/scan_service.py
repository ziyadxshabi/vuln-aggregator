"""The core scan use case: classify -> discover -> assess -> enrich -> score -> persist.

Network targets run nmap then Nuclei (never in parallel on the same CIDR).
Container image refs go to Trivy only. GVM/Nessus run only when configured.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable

from src.connectors import (
    DEFAULT_IMAGE_SCANNERS,
    DEFAULT_NETWORK_SCANNERS,
    OPTIONAL_SCANNERS,
)
from src.connectors.base import BaseScannerConnector
from src.connectors.nmap import hygiene_findings
from src.connectors.nuclei import endpoints_from_assets
from src.engine.profiles import get_profile
from src.engine.risk_engine import compute_risk
from src.engine.scope import ScopeError, prepare_scan
from src.models.asset import Asset
from src.models.enrichment import EnrichmentData
from src.models.enums import ScanStatus
from src.models.ports import (
    AssetRepositoryPort,
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
        asset_repo: AssetRepositoryPort | None = None,
        allowlist: list[str] | None = None,
        scanner_ready: Callable[[str], bool] | None = None,
        poll_interval_seconds: float = 10.0,
        poll_timeout_seconds: float = 7_200.0,
        asset_criticality_multiplier: float = 1.0,
        risk_fn: Callable[[RiskSignal], RiskResult] = compute_risk,
    ) -> None:
        self._vuln_repo = vuln_repo
        self._job_repo = job_repo
        self._asset_repo = asset_repo
        self._connectors = connectors
        self._enrichment = enrichment
        self._allowlist = allowlist
        self._scanner_ready = scanner_ready or (lambda _name: True)
        self._poll_interval = poll_interval_seconds
        self._poll_timeout = poll_timeout_seconds
        self._asset_multiplier = asset_criticality_multiplier
        self._risk_fn = risk_fn

    async def execute(
        self,
        job_id: str,
        targets: list[str],
        scanners: list[str] | None = None,
        *,
        profile: str = "home",
        requested_by: str | None = None,
    ) -> int:
        """Run the full pipeline and persist results. Returns findings stored."""
        await self._job_repo.set_status(job_id, ScanStatus.RUNNING)
        try:
            profile_cfg = get_profile(profile)
            prepared = prepare_scan(targets, profile_cfg, self._allowlist)
            selected = self._resolve_scanners(scanners, prepared.network_targets, prepared.image_targets)
            if not selected:
                raise ScopeError("No scanners are available for the requested targets")

            await self._progress(
                job_id,
                phase="discovery",
                hosts_found=0,
                hosts_done=0,
                findings_so_far=0,
            )

            findings: list[NormalizedVulnerability] = []
            assets: list[Asset] = []

            if prepared.network_targets and "nmap" in selected:
                nmap = self._connectors.get("nmap")
                scan_network = getattr(nmap, "scan_network", None)
                if callable(scan_network):
                    assets = await scan_network(prepared.nmap_chunks, profile_cfg)
                    if self._asset_repo is not None and assets:
                        await self._asset_repo.bulk_upsert(assets, scan_job_id=job_id)
                    findings.extend(hygiene_findings(assets))
                    await self._progress(
                        job_id,
                        phase="assessment",
                        hosts_found=len(assets),
                        hosts_done=len(assets),
                        findings_so_far=len(findings),
                    )

            # If nmap ran and found nobody, skip Nuclei rather than hanging on empty input.
            if prepared.network_targets and "nuclei" in selected and (assets or "nmap" not in selected):
                nuclei = self._connectors.get("nuclei")
                scan_endpoints = getattr(nuclei, "scan_endpoints", None)
                if callable(scan_endpoints):
                    endpoints = (
                        endpoints_from_assets(assets) if assets else list(prepared.network_targets)
                    )
                    if endpoints:
                        findings.extend(await scan_endpoints(endpoints, profile_cfg))
                    await self._progress(
                        job_id,
                        phase="assessment",
                        hosts_found=len(assets),
                        hosts_done=len(assets),
                        findings_so_far=len(findings),
                    )

            if prepared.image_targets and "trivy" in selected:
                extra = await self._collect(prepared.image_targets, ["trivy"])
                findings.extend(extra)

            optional = [name for name in selected if name in OPTIONAL_SCANNERS]
            if optional and prepared.network_targets:
                extra = await self._collect(prepared.network_targets, optional)
                findings.extend(extra)

            await self._progress(
                job_id,
                phase="enrichment",
                hosts_found=len(assets),
                hosts_done=len(assets),
                findings_so_far=len(findings),
            )
            await self._enrich(findings)
            self._score(findings, assets)
            stored = await self._vuln_repo.bulk_upsert(findings, scan_job_id=job_id)
            await self._job_repo.set_status(
                job_id, ScanStatus.COMPLETED, total_findings=stored
            )
            await self._progress(
                job_id,
                phase="complete",
                hosts_found=len(assets),
                hosts_done=len(assets),
                findings_so_far=stored,
            )
            _logger.info("scan_completed", job_id=job_id, findings=stored, requested_by=requested_by)
            return stored
        except Exception as exc:  # noqa: BLE001 - persisted then re-raised
            await self._job_repo.set_status(job_id, ScanStatus.FAILED, error=str(exc))
            _logger.exception("scan_failed", job_id=job_id)
            raise

    def _resolve_scanners(
        self,
        requested: list[str] | None,
        network_targets: list[str],
        image_targets: list[str],
    ) -> list[str]:
        if requested:
            names = list(requested)
        else:
            names = []
            if network_targets:
                names.extend(DEFAULT_NETWORK_SCANNERS)
            if image_targets:
                names.extend(DEFAULT_IMAGE_SCANNERS)

        selected: list[str] = []
        for name in names:
            if name not in self._connectors:
                continue
            if name in OPTIONAL_SCANNERS and not self._scanner_ready(name):
                _logger.warning("scanner_skipped_unconfigured", scanner=name)
                continue
            if name == "trivy" and not image_targets:
                continue
            if name != "trivy" and not network_targets:
                continue
            selected.append(name)
        return selected

    async def _progress(self, job_id: str, **progress: object) -> None:
        await self._job_repo.set_progress(job_id, dict(progress))

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

    def _score(self, findings: list[NormalizedVulnerability], assets: list[Asset]) -> None:
        by_ip = {asset.ip: asset for asset in assets}
        for finding in findings:
            asset = by_ip.get(finding.asset_ip)
            multiplier = asset.criticality.multiplier if asset is not None else self._asset_multiplier
            result = self._risk_fn(finding.to_risk_signal(multiplier))
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
