"""Async repositories: batch upsert, cursor pagination, posture aggregation."""

from __future__ import annotations

import base64
import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import Select, and_, asc, desc, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.database.base import utcnow
from src.database.orm import ScanJobRow, VulnerabilityRow
from src.models.enums import FindingStatus, ScanStatus, Severity
from src.models.posture import PostureMetrics
from src.models.scan import ScanJob
from src.models.vulnerability import NormalizedVulnerability

# Columns refreshed when a finding already exists (identity/first_seen preserved).
_UPSERT_UPDATE_COLUMNS = (
    "cve_id",
    "asset_host",
    "asset_os",
    "service",
    "title",
    "description",
    "solution",
    "severity",
    "cvss_v2_score",
    "cvss_v3_score",
    "cvss_v3_vector",
    "epss_score",
    "epss_percentile",
    "is_known_exploited",
    "has_weaponized_exploit",
    "enrichment_sources",
    "risk_score",
    "risk_tier",
    "status",
    "scan_job_id",
    "last_seen",
    "resolved_at",
)


def _encode_cursor(risk_score: float, vuln_id: str) -> str:
    raw = f"{risk_score}:{vuln_id}".encode()
    return base64.urlsafe_b64encode(raw).decode("ascii")


def _decode_cursor(cursor: str) -> tuple[float, str]:
    raw = base64.urlsafe_b64decode(cursor.encode("ascii")).decode("utf-8")
    score_str, _, vuln_id = raw.partition(":")
    return float(score_str), vuln_id


def _as_utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


class VulnerabilityRepository:
    """Persistence for :class:`NormalizedVulnerability` findings."""

    def __init__(self, session: AsyncSession, dialect_name: str) -> None:
        self._session = session
        self._dialect = dialect_name

    def _row_values(
        self, vuln: NormalizedVulnerability, scan_job_id: str | None, now: datetime
    ) -> dict[str, Any]:
        return {
            "id": vuln.id,
            "scanner": vuln.scanner,
            "scanner_vuln_id": vuln.scanner_vuln_id,
            "cve_id": vuln.cve_id,
            "asset_host": vuln.asset_host,
            "asset_ip": vuln.asset_ip,
            "asset_os": vuln.asset_os,
            "port": vuln.port,
            "protocol": vuln.protocol,
            "service": vuln.service,
            "title": vuln.title,
            "description": vuln.description,
            "solution": vuln.solution,
            "severity": vuln.severity.value,
            "cvss_v2_score": vuln.cvss_v2_score,
            "cvss_v3_score": vuln.cvss_v3_score,
            "cvss_v3_vector": vuln.cvss_v3_vector,
            "epss_score": vuln.epss_score,
            "epss_percentile": vuln.epss_percentile,
            "is_known_exploited": vuln.is_known_exploited,
            "has_weaponized_exploit": vuln.has_weaponized_exploit,
            "enrichment_sources": list(vuln.enrichment_sources),
            "risk_score": vuln.risk_score,
            "risk_tier": vuln.risk_tier.value,
            "status": vuln.status.value,
            "scan_job_id": scan_job_id,
            "first_seen": now,
            "last_seen": now,
            "resolved_at": None,
        }

    async def bulk_upsert(
        self, vulns: list[NormalizedVulnerability], scan_job_id: str | None = None
    ) -> int:
        if not vulns:
            return 0

        now = utcnow()
        # De-duplicate within the batch (identical id) keeping the highest risk.
        by_id: dict[str, NormalizedVulnerability] = {}
        for vuln in vulns:
            existing = by_id.get(vuln.id)
            if existing is None or vuln.risk_score > existing.risk_score:
                by_id[vuln.id] = vuln
        values = [self._row_values(v, scan_job_id, now) for v in by_id.values()]

        if self._dialect == "postgresql":
            from sqlalchemy.dialects.postgresql import insert as dialect_insert
        else:
            from sqlalchemy.dialects.sqlite import insert as dialect_insert

        stmt = dialect_insert(VulnerabilityRow).values(values)
        stmt = stmt.on_conflict_do_update(
            index_elements=[VulnerabilityRow.id],
            set_={col: getattr(stmt.excluded, col) for col in _UPSERT_UPDATE_COLUMNS},
        )
        await self._session.execute(stmt)
        await self._session.commit()
        return len(values)

    async def get(self, vuln_id: str) -> NormalizedVulnerability | None:
        row = await self._session.get(VulnerabilityRow, vuln_id)
        return _row_to_domain(row) if row is not None else None

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
    ) -> tuple[list[NormalizedVulnerability], str | None]:
        limit = max(1, min(limit, 500))
        stmt: Select[tuple[VulnerabilityRow]] = select(VulnerabilityRow)

        if severity is not None:
            stmt = stmt.where(VulnerabilityRow.severity == severity.value)
        if epss_min is not None:
            stmt = stmt.where(VulnerabilityRow.epss_score >= epss_min)
        if epss_max is not None:
            stmt = stmt.where(VulnerabilityRow.epss_score <= epss_max)
        if asset_group:
            stmt = stmt.where(
                or_(
                    VulnerabilityRow.asset_ip.like(f"{asset_group}%"),
                    VulnerabilityRow.asset_host.like(f"%{asset_group}%"),
                )
            )
        if only_known_exploited:
            stmt = stmt.where(VulnerabilityRow.is_known_exploited.is_(True))
        if cursor:
            score, vuln_id = _decode_cursor(cursor)
            stmt = stmt.where(
                or_(
                    VulnerabilityRow.risk_score < score,
                    and_(
                        VulnerabilityRow.risk_score == score,
                        VulnerabilityRow.id > vuln_id,
                    ),
                )
            )

        stmt = stmt.order_by(desc(VulnerabilityRow.risk_score), asc(VulnerabilityRow.id)).limit(
            limit + 1
        )
        rows = list((await self._session.execute(stmt)).scalars().all())
        has_more = len(rows) > limit
        rows = rows[:limit]
        next_cursor = (
            _encode_cursor(rows[-1].risk_score, rows[-1].id) if has_more and rows else None
        )
        return [_row_to_domain(row) for row in rows], next_cursor

    async def posture(self) -> PostureMetrics:
        session = self._session

        severity_rows = (
            await session.execute(
                select(VulnerabilityRow.severity, func.count()).group_by(VulnerabilityRow.severity)
            )
        ).all()
        severity_counts = {str(sev): int(count) for sev, count in severity_rows}
        total = sum(severity_counts.values())

        open_count = int(
            (
                await session.execute(
                    select(func.count()).where(VulnerabilityRow.status == FindingStatus.OPEN.value)
                )
            ).scalar_one()
        )
        kev_count = int(
            (
                await session.execute(
                    select(func.count()).where(VulnerabilityRow.is_known_exploited.is_(True))
                )
            ).scalar_one()
        )
        weaponized_count = int(
            (
                await session.execute(
                    select(func.count()).where(VulnerabilityRow.has_weaponized_exploit.is_(True))
                )
            ).scalar_one()
        )
        avg_risk = (
            await session.execute(
                select(func.avg(VulnerabilityRow.risk_score)).where(
                    VulnerabilityRow.status == FindingStatus.OPEN.value
                )
            )
        ).scalar_one()

        open_first_seen = (
            (
                await session.execute(
                    select(VulnerabilityRow.first_seen).where(
                        VulnerabilityRow.status == FindingStatus.OPEN.value
                    )
                )
            )
            .scalars()
            .all()
        )
        resolved_rows = (
            await session.execute(
                select(VulnerabilityRow.first_seen, VulnerabilityRow.resolved_at).where(
                    VulnerabilityRow.status == FindingStatus.RESOLVED.value,
                    VulnerabilityRow.resolved_at.is_not(None),
                )
            )
        ).all()

        now = utcnow()
        mean_age = _mean_days(
            [(now - dt).total_seconds() for dt in (_as_utc(v) for v in open_first_seen) if dt]
        )
        mttr = _mean_days(
            [
                (_as_utc(resolved) - _as_utc(first)).total_seconds()  # type: ignore[operator]
                for first, resolved in resolved_rows
                if _as_utc(first) and _as_utc(resolved)
            ]
        )

        return PostureMetrics(
            total_findings=total,
            open_findings=open_count,
            severity_counts=severity_counts,
            known_exploited_count=kev_count,
            weaponized_count=weaponized_count,
            exposure_score=round(float(avg_risk), 2) if avg_risk is not None else 0.0,
            mean_finding_age_days=mean_age,
            mttr_days=mttr,
        )


class ScanJobRepository:
    """Persistence for aggregated scan jobs."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def create(self, targets: list[str], scanners: list[str]) -> ScanJob:
        now = utcnow()
        row = ScanJobRow(
            id=uuid.uuid4().hex,
            status=ScanStatus.PENDING.value,
            targets=list(targets),
            scanners=list(scanners),
            total_findings=0,
            created_at=now,
            updated_at=now,
        )
        self._session.add(row)
        await self._session.commit()
        return _job_to_domain(row)

    async def get(self, job_id: str) -> ScanJob | None:
        row = await self._session.get(ScanJobRow, job_id)
        return _job_to_domain(row) if row is not None else None

    async def set_status(
        self,
        job_id: str,
        status: ScanStatus,
        *,
        total_findings: int | None = None,
        error: str | None = None,
    ) -> None:
        row = await self._session.get(ScanJobRow, job_id)
        if row is None:
            return
        row.status = status.value
        row.updated_at = utcnow()
        if total_findings is not None:
            row.total_findings = total_findings
        if error is not None:
            row.error = error
        await self._session.commit()


def _mean_days(seconds_values: list[float]) -> float | None:
    if not seconds_values:
        return None
    return round(sum(seconds_values) / len(seconds_values) / 86_400.0, 2)


def _row_to_domain(row: VulnerabilityRow) -> NormalizedVulnerability:
    return NormalizedVulnerability(
        scanner=row.scanner,
        scanner_vuln_id=row.scanner_vuln_id,
        cve_id=row.cve_id,
        asset_host=row.asset_host,
        asset_ip=row.asset_ip,
        asset_os=row.asset_os,
        port=row.port,
        protocol=row.protocol,
        service=row.service,
        title=row.title,
        description=row.description,
        solution=row.solution,
        severity=Severity(row.severity),
        cvss_v2_score=row.cvss_v2_score,
        cvss_v3_score=row.cvss_v3_score,
        cvss_v3_vector=row.cvss_v3_vector,
        epss_score=row.epss_score,
        epss_percentile=row.epss_percentile,
        is_known_exploited=row.is_known_exploited,
        has_weaponized_exploit=row.has_weaponized_exploit,
        enrichment_sources=list(row.enrichment_sources or []),
        risk_score=row.risk_score,
        risk_tier=Severity(row.risk_tier),
        status=FindingStatus(row.status),
    )


def _job_to_domain(row: ScanJobRow) -> ScanJob:
    return ScanJob(
        id=row.id,
        status=ScanStatus(row.status),
        targets=list(row.targets or []),
        scanners=list(row.scanners or []),
        total_findings=row.total_findings,
        error=row.error,
        created_at=row.created_at,
        updated_at=row.updated_at,
    )
