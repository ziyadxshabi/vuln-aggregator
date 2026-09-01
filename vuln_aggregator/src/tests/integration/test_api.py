"""Integration tests for the API routes against an isolated SQLite database."""

from __future__ import annotations

from collections.abc import Awaitable, Callable

import httpx

from src.models.enums import Severity
from src.models.vulnerability import NormalizedVulnerability
from tests.conftest import FakeDispatcher, auth_token

SeedFn = Callable[[list[NormalizedVulnerability]], Awaitable[int]]


def _sample_vulns() -> list[NormalizedVulnerability]:
    return [
        NormalizedVulnerability(
            scanner="nessus",
            scanner_vuln_id="critical-1",
            cve_id="CVE-2021-44228",
            asset_ip="10.0.0.1",
            asset_host="app-prod",
            port=8080,
            severity=Severity.CRITICAL,
            cvss_v3_score=10.0,
            is_known_exploited=True,
            risk_score=10.0,
            risk_tier=Severity.CRITICAL,
        ),
        NormalizedVulnerability(
            scanner="gvm",
            scanner_vuln_id="high-1",
            cve_id="CVE-2019-0708",
            asset_ip="10.0.0.2",
            port=3389,
            severity=Severity.HIGH,
            cvss_v3_score=8.1,
            risk_score=7.5,
            risk_tier=Severity.HIGH,
        ),
        NormalizedVulnerability(
            scanner="trivy",
            scanner_vuln_id="low-1",
            asset_ip="10.0.0.3",
            port=0,
            severity=Severity.LOW,
            risk_score=2.0,
            risk_tier=Severity.LOW,
        ),
    ]


async def test_list_requires_authentication(client: httpx.AsyncClient) -> None:
    resp = await client.get("/api/v1/vulnerabilities")
    assert resp.status_code == 401
    body = resp.json()
    assert body["error"]["type"] == "authentication_error"
    assert "request_id" in body["error"]


async def test_health_is_public(client: httpx.AsyncClient) -> None:
    resp = await client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


async def test_list_sorted_by_risk_with_pagination(
    client: httpx.AsyncClient, seed: SeedFn
) -> None:
    await seed(_sample_vulns())
    token = await auth_token(client, "viewer", "viewer123")
    headers = {"Authorization": f"Bearer {token}"}

    first = await client.get("/api/v1/vulnerabilities", params={"limit": 2}, headers=headers)
    assert first.status_code == 200
    payload = first.json()
    assert [item["risk_score"] for item in payload["items"]] == [10.0, 7.5]
    assert payload["has_more"] is True
    assert payload["next_cursor"]

    second = await client.get(
        "/api/v1/vulnerabilities",
        params={"limit": 2, "cursor": payload["next_cursor"]},
        headers=headers,
    )
    assert [item["risk_score"] for item in second.json()["items"]] == [2.0]


async def test_severity_filter(client: httpx.AsyncClient, seed: SeedFn) -> None:
    await seed(_sample_vulns())
    token = await auth_token(client, "viewer", "viewer123")
    headers = {"Authorization": f"Bearer {token}"}

    resp = await client.get(
        "/api/v1/vulnerabilities", params={"severity": "CRITICAL"}, headers=headers
    )
    items = resp.json()["items"]
    assert len(items) == 1
    assert items[0]["cve_id"] == "CVE-2021-44228"
    assert items[0]["is_known_exploited"] is True


async def test_get_detail_and_not_found(client: httpx.AsyncClient, seed: SeedFn) -> None:
    vulns = _sample_vulns()
    await seed(vulns)
    token = await auth_token(client, "viewer", "viewer123")
    headers = {"Authorization": f"Bearer {token}"}

    found = await client.get(f"/api/v1/vulnerabilities/{vulns[0].id}", headers=headers)
    assert found.status_code == 200
    assert found.json()["scanner_vuln_id"] == "critical-1"

    missing = await client.get("/api/v1/vulnerabilities/does-not-exist", headers=headers)
    assert missing.status_code == 404
    assert missing.json()["error"]["type"] == "not_found"


async def test_posture_metrics(client: httpx.AsyncClient, seed: SeedFn) -> None:
    await seed(_sample_vulns())
    token = await auth_token(client, "viewer", "viewer123")
    headers = {"Authorization": f"Bearer {token}"}

    resp = await client.get("/api/v1/metrics/posture", headers=headers)
    assert resp.status_code == 200
    metrics = resp.json()
    assert metrics["total_findings"] == 3
    assert metrics["known_exploited_count"] == 1
    assert metrics["severity_counts"].get("CRITICAL") == 1
    assert metrics["exposure_score"] > 0


async def test_rbac_read_only_cannot_launch_scan(client: httpx.AsyncClient) -> None:
    token = await auth_token(client, "viewer", "viewer123")
    resp = await client.post(
        "/api/v1/scans",
        json={"targets": ["10.0.0.0/24"], "scanners": ["gvm"]},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 403
    assert resp.json()["error"]["type"] == "permission_denied"


async def test_analyst_can_launch_scan(
    client: httpx.AsyncClient, dispatcher: FakeDispatcher
) -> None:
    token = await auth_token(client, "analyst", "analyst123")
    headers = {"Authorization": f"Bearer {token}"}

    resp = await client.post(
        "/api/v1/scans",
        json={"targets": ["10.0.0.0/24"], "scanners": ["gvm", "nessus"]},
        headers=headers,
    )
    assert resp.status_code == 202
    body = resp.json()
    assert body["status"] == "PENDING"
    assert body["task_id"] == f"task-{body['id']}"
    assert len(dispatcher.calls) == 1

    status_resp = await client.get(f"/api/v1/scans/{body['id']}", headers=headers)
    assert status_resp.status_code == 200
    assert status_resp.json()["targets"] == ["10.0.0.0/24"]
