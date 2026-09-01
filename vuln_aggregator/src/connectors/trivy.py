"""Trivy connector for container images and software supply-chain scanning.

Trivy is a CLI tool: :meth:`start_scan` shells out to ``trivy`` and writes a
JSON report to a temp file whose path is used as the job id. Parsing
(:func:`normalize_report`) is pure and works directly on Trivy JSON fixtures.
"""

from __future__ import annotations

import asyncio
import json
import tempfile
from pathlib import Path
from typing import Any, ClassVar

from src.config import Settings, get_settings
from src.connectors.base import BaseScannerConnector
from src.models.enums import ScanStatus, Severity
from src.models.vulnerability import NormalizedVulnerability

_TRIVY_SEVERITY: dict[str, Severity] = {
    "UNKNOWN": Severity.INFO,
    "LOW": Severity.LOW,
    "MEDIUM": Severity.MEDIUM,
    "HIGH": Severity.HIGH,
    "CRITICAL": Severity.CRITICAL,
}


def _cvss_from_entry(cvss: dict[str, Any]) -> tuple[float | None, str | None]:
    """Pull the best available CVSS v3 score/vector from Trivy's CVSS map."""
    for source in ("nvd", "redhat", "ghsa"):
        entry = cvss.get(source)
        if isinstance(entry, dict) and entry.get("V3Score") is not None:
            score = entry.get("V3Score")
            return (float(score) if score is not None else None, entry.get("V3Vector"))
    return None, None


def normalize_report(report: dict[str, Any]) -> list[NormalizedVulnerability]:
    """Normalize a Trivy JSON report into domain findings."""

    artifact = str(report.get("ArtifactName", "") or report.get("Target", "") or "unknown")
    findings: list[NormalizedVulnerability] = []

    for result in report.get("Results", []):
        target = str(result.get("Target", artifact))
        for vuln in result.get("Vulnerabilities", []) or []:
            vuln_id = str(vuln.get("VulnerabilityID", ""))
            pkg = str(vuln.get("PkgName", ""))
            severity = _TRIVY_SEVERITY.get(str(vuln.get("Severity", "UNKNOWN")).upper(), Severity.INFO)
            cvss_score, cvss_vector = _cvss_from_entry(vuln.get("CVSS", {}) or {})
            cve_id = vuln_id if vuln_id.upper().startswith("CVE") else None
            fixed = vuln.get("FixedVersion")
            solution = f"Upgrade {pkg} to {fixed}" if fixed else None

            finding = NormalizedVulnerability(
                scanner=TrivyConnector.scanner_name,
                scanner_vuln_id=f"{pkg}:{vuln_id}",
                cve_id=cve_id,
                asset_host=artifact,
                asset_ip=artifact,
                asset_os=str(result.get("Type", "") or "") or None,
                port=0,
                protocol="pkg",
                service=pkg,
                title=str(vuln.get("Title", "") or vuln_id),
                description=str(vuln.get("Description", "") or ""),
                solution=solution,
                severity=severity if cvss_score is None else Severity.from_cvss(cvss_score),
                cvss_v3_score=cvss_score,
                cvss_v3_vector=cvss_vector,
            )
            _ = target  # target retained for potential future asset mapping
            findings.append(finding)

    return findings


class TrivyConnector(BaseScannerConnector):
    """Adapter that runs Trivy and ingests its JSON output."""

    scanner_name: ClassVar[str] = "trivy"

    def __init__(self, settings: Settings | None = None) -> None:
        self._settings = settings or get_settings()

    async def start_scan(self, target: str) -> str:
        out_path = Path(tempfile.gettempdir()) / f"trivy-{abs(hash(target))}.json"
        process = await asyncio.create_subprocess_exec(
            self._settings.trivy_binary,
            "image",
            "--quiet",
            "--format",
            "json",
            "--output",
            str(out_path),
            target,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await process.communicate()
        if process.returncode != 0:
            raise RuntimeError(f"trivy scan of {target!r} failed (exit {process.returncode})")
        return str(out_path)

    async def check_scan_status(self, job_id: str) -> ScanStatus:
        return ScanStatus.COMPLETED if Path(job_id).exists() else ScanStatus.RUNNING

    async def fetch_and_normalize(self, job_id: str) -> list[NormalizedVulnerability]:
        raw = await asyncio.to_thread(Path(job_id).read_text, "utf-8")
        return normalize_report(json.loads(raw))
