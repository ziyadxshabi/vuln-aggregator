"""Pydantic v2 request/response schemas for the API layer."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from src.models.enums import ScanStatus, Severity
from src.models.posture import PostureMetrics
from src.models.scan import ScanJob
from src.models.vulnerability import NormalizedVulnerability


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int


class ScanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    targets: list[str] = Field(min_length=1, description="IPs, hostnames, CIDRs, or image refs")
    scanners: list[str] = Field(default_factory=lambda: ["gvm", "nessus", "trivy"])


class ScanJobResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    status: ScanStatus
    targets: list[str]
    scanners: list[str]
    total_findings: int
    error: str | None
    created_at: datetime
    updated_at: datetime
    task_id: str | None = None

    @classmethod
    def from_domain(cls, job: ScanJob, task_id: str | None = None) -> ScanJobResponse:
        return cls(
            id=job.id,
            status=job.status,
            targets=job.targets,
            scanners=job.scanners,
            total_findings=job.total_findings,
            error=job.error,
            created_at=job.created_at,
            updated_at=job.updated_at,
            task_id=task_id,
        )


class VulnerabilityResponse(BaseModel):
    id: str
    scanner: str
    scanner_vuln_id: str
    cve_id: str | None
    asset_host: str
    asset_ip: str
    asset_os: str | None
    port: int
    protocol: str
    service: str | None
    title: str
    description: str
    solution: str | None
    severity: Severity
    cvss_v2_score: float | None
    cvss_v3_score: float | None
    cvss_v3_vector: str | None
    epss_score: float | None
    epss_percentile: float | None
    is_known_exploited: bool
    has_weaponized_exploit: bool
    enrichment_sources: list[str]
    risk_score: float
    risk_tier: Severity

    @classmethod
    def from_domain(cls, vuln: NormalizedVulnerability) -> VulnerabilityResponse:
        return cls(
            id=vuln.id,
            scanner=vuln.scanner,
            scanner_vuln_id=vuln.scanner_vuln_id,
            cve_id=vuln.cve_id,
            asset_host=vuln.asset_host,
            asset_ip=vuln.asset_ip,
            asset_os=vuln.asset_os,
            port=vuln.port,
            protocol=vuln.protocol,
            service=vuln.service,
            title=vuln.title,
            description=vuln.description,
            solution=vuln.solution,
            severity=vuln.severity,
            cvss_v2_score=vuln.cvss_v2_score,
            cvss_v3_score=vuln.cvss_v3_score,
            cvss_v3_vector=vuln.cvss_v3_vector,
            epss_score=vuln.epss_score,
            epss_percentile=vuln.epss_percentile,
            is_known_exploited=vuln.is_known_exploited,
            has_weaponized_exploit=vuln.has_weaponized_exploit,
            enrichment_sources=vuln.enrichment_sources,
            risk_score=vuln.risk_score,
            risk_tier=vuln.risk_tier,
        )


class VulnerabilityListResponse(BaseModel):
    items: list[VulnerabilityResponse]
    count: int
    next_cursor: str | None = None
    has_more: bool = False


class PostureResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    total_findings: int
    open_findings: int
    severity_counts: dict[str, int]
    known_exploited_count: int
    weaponized_count: int
    exposure_score: float
    mean_finding_age_days: float | None
    mttr_days: float | None

    @classmethod
    def from_domain(cls, metrics: PostureMetrics) -> PostureResponse:
        return cls(
            total_findings=metrics.total_findings,
            open_findings=metrics.open_findings,
            severity_counts=metrics.severity_counts,
            known_exploited_count=metrics.known_exploited_count,
            weaponized_count=metrics.weaponized_count,
            exposure_score=metrics.exposure_score,
            mean_finding_age_days=metrics.mean_finding_age_days,
            mttr_days=metrics.mttr_days,
        )
