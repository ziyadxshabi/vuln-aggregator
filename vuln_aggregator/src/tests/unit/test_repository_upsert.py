"""Unit tests for the dialect-aware upsert and in-batch de-duplication."""

from __future__ import annotations

from src.database.base import Database
from src.database.repository import VulnerabilityRepository
from src.models.enums import Severity
from src.models.vulnerability import NormalizedVulnerability


def _vuln(risk: float, *, description: str = "initial") -> NormalizedVulnerability:
    return NormalizedVulnerability(
        scanner="nessus",
        scanner_vuln_id="19506",
        cve_id="CVE-2016-2107",
        asset_ip="10.0.0.10",
        port=443,
        protocol="tcp",
        description=description,
        severity=Severity.HIGH,
        cvss_v3_score=7.4,
        risk_score=risk,
        risk_tier=Severity.HIGH,
    )


async def test_upsert_is_idempotent_on_identity(database: Database) -> None:
    async with database.session() as session:
        repo = VulnerabilityRepository(session, database.dialect_name)
        await repo.bulk_upsert([_vuln(5.0)])
        await repo.bulk_upsert([_vuln(8.5, description="rescan")])

        items, _ = await repo.list(limit=100)
        assert len(items) == 1  # same fingerprint -> single row
        assert items[0].risk_score == 8.5
        assert items[0].description == "rescan"


async def test_in_batch_dedup_keeps_highest_risk(database: Database) -> None:
    async with database.session() as session:
        repo = VulnerabilityRepository(session, database.dialect_name)
        stored = await repo.bulk_upsert([_vuln(3.0), _vuln(9.1), _vuln(6.0)])
        assert stored == 1

        items, _ = await repo.list(limit=100)
        assert len(items) == 1
        assert items[0].risk_score == 9.1


async def test_cursor_pagination_orders_by_risk(database: Database) -> None:
    async with database.session() as session:
        repo = VulnerabilityRepository(session, database.dialect_name)
        vulns = [
            NormalizedVulnerability(
                scanner="nessus",
                scanner_vuln_id=str(i),
                asset_ip="10.0.0.10",
                port=i,
                severity=Severity.MEDIUM,
                risk_score=float(i),
                risk_tier=Severity.MEDIUM,
            )
            for i in range(1, 6)
        ]
        await repo.bulk_upsert(vulns)

        page1, cursor1 = await repo.list(limit=2)
        assert [v.risk_score for v in page1] == [5.0, 4.0]
        assert cursor1 is not None

        page2, cursor2 = await repo.list(limit=2, cursor=cursor1)
        assert [v.risk_score for v in page2] == [3.0, 2.0]
        assert cursor2 is not None

        page3, cursor3 = await repo.list(limit=2, cursor=cursor2)
        assert [v.risk_score for v in page3] == [1.0]
        assert cursor3 is None
