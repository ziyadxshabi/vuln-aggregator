"""Unit tests for the phased nmap → nuclei ScanService pipeline."""

from __future__ import annotations

from src.models.asset import Asset, DiscoveredPort
from src.models.enums import ScanStatus, Severity
from src.models.vulnerability import NormalizedVulnerability
from src.services.scan_service import ScanService


class _JobRepo:
    def __init__(self) -> None:
        self.statuses: list[tuple[str, ScanStatus, int | None]] = []
        self.progress: list[dict[str, object]] = []

    async def create(self, *args: object, **kwargs: object) -> None:  # pragma: no cover
        return None

    async def get(self, job_id: str) -> None:  # pragma: no cover
        return None

    async def set_status(
        self,
        job_id: str,
        status: ScanStatus,
        *,
        total_findings: int | None = None,
        error: str | None = None,
    ) -> None:
        self.statuses.append((job_id, status, total_findings))

    async def set_progress(self, job_id: str, progress: dict[str, object]) -> None:
        self.progress.append(progress)


class _VulnRepo:
    def __init__(self) -> None:
        self.stored: list[NormalizedVulnerability] = []

    async def bulk_upsert(
        self, vulns: list[NormalizedVulnerability], scan_job_id: str | None = None
    ) -> int:
        self.stored = list(vulns)
        return len(vulns)

    async def get(self, vuln_id: str) -> None:  # pragma: no cover
        return None

    async def set_status(self, *args: object, **kwargs: object) -> None:  # pragma: no cover
        return None

    async def list(self, **kwargs: object) -> tuple[list[NormalizedVulnerability], None]:
        return [], None

    async def posture(self) -> None:  # pragma: no cover
        return None


class _AssetRepo:
    def __init__(self) -> None:
        self.assets: list[Asset] = []

    async def bulk_upsert(self, assets: list[Asset], scan_job_id: str | None = None) -> int:
        self.assets = list(assets)
        return len(assets)

    async def list(self, *, limit: int = 500) -> list[Asset]:
        return list(self.assets)

    async def count(self) -> int:
        return len(self.assets)


class _Enrichment:
    async def enrich(self, cve_ids: set[str]) -> dict[str, object]:
        return {}


class _Nmap:
    scanner_name = "nmap"

    def __init__(self, assets: list[Asset]) -> None:
        self._assets = assets
        self.calls: list[list[str]] = []

    async def scan_network(self, targets: list[str], profile: object) -> list[Asset]:
        self.calls.append(list(targets))
        return list(self._assets)


class _Nuclei:
    scanner_name = "nuclei"

    def __init__(self) -> None:
        self.calls: list[list[str]] = []

    async def scan_endpoints(
        self, endpoints: list[str], profile: object
    ) -> list[NormalizedVulnerability]:
        self.calls.append(list(endpoints))
        return [
            NormalizedVulnerability(
                scanner="nuclei",
                scanner_vuln_id="detected",
                asset_ip="192.168.1.10",
                asset_host="192.168.1.10",
                port=80,
                title="Nuclei finding",
                severity=Severity.MEDIUM,
            )
        ]


class _Trivy:
    scanner_name = "trivy"
    started: list[str]

    def __init__(self) -> None:
        self.started = []

    async def start_scan(self, target: str) -> str:
        self.started.append(target)
        return f"trivy-{target}"

    async def check_scan_status(self, job_id: str) -> ScanStatus:
        return ScanStatus.COMPLETED

    async def fetch_and_normalize(self, job_id: str) -> list[NormalizedVulnerability]:
        return [
            NormalizedVulnerability(
                scanner="trivy",
                scanner_vuln_id="CVE-2021-44228",
                cve_id="CVE-2021-44228",
                asset_ip=job_id,
                title="Image CVE",
                severity=Severity.CRITICAL,
                cvss_v3_score=10.0,
            )
        ]


def _host() -> Asset:
    return Asset(
        ip="192.168.1.10",
        hostname="nas.lan",
        ports=[
            DiscoveredPort(port=80, protocol="tcp", service="http"),
            DiscoveredPort(port=445, protocol="tcp", service="microsoft-ds"),
        ],
    )


async def test_network_scan_runs_nmap_before_nuclei() -> None:
    nmap = _Nmap([_host()])
    nuclei = _Nuclei()
    jobs = _JobRepo()
    vulns = _VulnRepo()
    assets = _AssetRepo()
    service = ScanService(
        vuln_repo=vulns,  # type: ignore[arg-type]
        job_repo=jobs,  # type: ignore[arg-type]
        connectors={"nmap": nmap, "nuclei": nuclei},  # type: ignore[arg-type]
        enrichment=_Enrichment(),  # type: ignore[arg-type]
        asset_repo=assets,  # type: ignore[arg-type]
    )

    stored = await service.execute("job-1", ["192.168.1.0/24"], profile="home")
    assert nmap.calls == [["192.168.1.0/24"]]
    assert nuclei.calls
    assert "http://192.168.1.10:80" in nuclei.calls[0]
    assert assets.assets[0].ip == "192.168.1.10"
    assert stored >= 2  # hygiene SMB + nuclei
    assert jobs.statuses[-1][1] is ScanStatus.COMPLETED
    assert jobs.progress[-1]["phase"] == "complete"


async def test_zero_hosts_skips_nuclei() -> None:
    nmap = _Nmap([])
    nuclei = _Nuclei()
    service = ScanService(
        vuln_repo=_VulnRepo(),  # type: ignore[arg-type]
        job_repo=_JobRepo(),  # type: ignore[arg-type]
        connectors={"nmap": nmap, "nuclei": nuclei},  # type: ignore[arg-type]
        enrichment=_Enrichment(),  # type: ignore[arg-type]
        asset_repo=_AssetRepo(),  # type: ignore[arg-type]
    )
    stored = await service.execute("job-empty", ["192.168.1.0/24"])
    assert stored == 0
    assert nuclei.calls == []


async def test_image_target_uses_trivy_only() -> None:
    nmap = _Nmap([_host()])
    nuclei = _Nuclei()
    trivy = _Trivy()
    vulns = _VulnRepo()
    service = ScanService(
        vuln_repo=vulns,  # type: ignore[arg-type]
        job_repo=_JobRepo(),  # type: ignore[arg-type]
        connectors={"nmap": nmap, "nuclei": nuclei, "trivy": trivy},  # type: ignore[arg-type]
        enrichment=_Enrichment(),  # type: ignore[arg-type]
    )
    stored = await service.execute("job-img", ["nginx:1.19"])
    assert nmap.calls == []
    assert nuclei.calls == []
    assert trivy.started == ["nginx:1.19"]
    assert stored == 1
    assert vulns.stored[0].scanner == "trivy"
