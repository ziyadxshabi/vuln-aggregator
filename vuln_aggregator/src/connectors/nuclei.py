"""Nuclei connector for detection-only vulnerability templates.

Templates tagged ``intrusive``, ``dos``, or ``fuzz`` are always excluded.
``default-login`` templates are enabled only on the thorough profile.
Parsing (:func:`normalize_report`) is pure JSONL and unit-tested against fixtures.
"""

from __future__ import annotations

import asyncio
import json
import tempfile
from pathlib import Path
from typing import Any, ClassVar
from urllib.parse import urlparse

from src.config import Settings, get_settings
from src.connectors.base import BaseScannerConnector
from src.engine.profiles import ScanProfileConfig, get_profile
from src.models.asset import Asset
from src.models.enums import ScanStatus, Severity
from src.models.vulnerability import NormalizedVulnerability

_HTTP_PORTS = {80, 8080, 8000, 8888, 8008, 5000, 3000}
_HTTPS_PORTS = {443, 8443, 9443, 4443}

_NUCLEI_SEVERITY: dict[str, Severity] = {
    "info": Severity.INFO,
    "unknown": Severity.INFO,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
}

_ALWAYS_EXCLUDE_TAGS = ("intrusive", "dos", "fuzz")


def exclude_tags_for_profile(profile: ScanProfileConfig) -> list[str]:
    """Tags Nuclei must never run, plus default-login except on thorough scans."""
    tags = list(_ALWAYS_EXCLUDE_TAGS)
    if not profile.include_default_login:
        tags.append("default-login")
    return tags


def endpoints_from_assets(assets: list[Asset]) -> list[str]:
    """Build Nuclei input URLs/hosts from discovered ports."""
    endpoints: list[str] = []
    seen: set[str] = set()

    def _add(value: str) -> None:
        if value not in seen:
            seen.add(value)
            endpoints.append(value)

    for asset in assets:
        _add(asset.ip)
        for port in asset.ports:
            if port.protocol != "tcp":
                continue
            service = (port.service or "").lower()
            if port.port in _HTTPS_PORTS or "https" in service or "ssl" in service:
                _add(f"https://{asset.ip}:{port.port}")
            elif port.port in _HTTP_PORTS or service in {"http", "http-proxy", "http-alt"}:
                _add(f"http://{asset.ip}:{port.port}")
            else:
                _add(f"{asset.ip}:{port.port}")
    return endpoints


def _parse_matched(matched: str) -> tuple[str, int, str]:
    """Extract host, port, and protocol hint from a Nuclei matched-at value."""
    raw = matched.strip()
    if "://" in raw:
        parsed = urlparse(raw)
        host = parsed.hostname or raw
        if parsed.port:
            port = parsed.port
        elif parsed.scheme == "https":
            port = 443
        elif parsed.scheme == "http":
            port = 80
        else:
            port = 0
        return host, port, "tcp"
    if raw.count(":") == 1:
        host, _, port_s = raw.partition(":")
        try:
            return host, int(port_s.split("/")[0]), "tcp"
        except ValueError:
            return raw, 0, "tcp"
    return raw, 0, "tcp"


def _first_cve(info: dict[str, Any], template_id: str) -> str | None:
    classification = info.get("classification") or {}
    cves = classification.get("cve-id") or classification.get("cve_id") or info.get("cve-id")
    if isinstance(cves, list) and cves:
        value = str(cves[0]).strip().upper()
        return value if value.startswith("CVE-") else None
    if isinstance(cves, str) and cves.strip().upper().startswith("CVE-"):
        return cves.strip().upper()
    tid = template_id.strip().upper()
    if tid.startswith("CVE-"):
        return tid
    return None


def normalize_report(jsonl_text: str) -> list[NormalizedVulnerability]:
    """Parse Nuclei JSONL output into domain findings."""
    findings: list[NormalizedVulnerability] = []
    for line in jsonl_text.splitlines():
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(event, dict):
            continue
        info = event.get("info") if isinstance(event.get("info"), dict) else {}
        template_id = str(
            event.get("template-id")
            or event.get("template_id")
            or event.get("templateID")
            or ""
        )
        matched = str(
            event.get("matched-at") or event.get("host") or event.get("matched") or ""
        )
        host, port, protocol = _parse_matched(matched)
        severity_raw = str(info.get("severity") or "info").lower()
        severity = _NUCLEI_SEVERITY.get(severity_raw, Severity.INFO)
        classification = info.get("classification") if isinstance(info.get("classification"), dict) else {}
        cvss_raw = classification.get("cvss-score") or classification.get("cvss_score")
        try:
            cvss = float(cvss_raw) if cvss_raw is not None else None
        except (TypeError, ValueError):
            cvss = None
        if cvss is not None:
            severity = Severity.from_cvss(cvss)
        findings.append(
            NormalizedVulnerability(
                scanner=NucleiConnector.scanner_name,
                scanner_vuln_id=template_id or matched,
                cve_id=_first_cve(info, template_id),
                asset_host=host,
                asset_ip=host,
                port=port,
                protocol=protocol,
                title=str(info.get("name") or template_id),
                description=str(info.get("description") or ""),
                severity=severity,
                cvss_v3_score=cvss,
            )
        )
    return findings


class NucleiConnector(BaseScannerConnector):
    """Adapter that runs Nuclei in detection-only mode."""

    scanner_name: ClassVar[str] = "nuclei"

    def __init__(self, settings: Settings | None = None) -> None:
        self._settings = settings or get_settings()

    async def start_scan(self, target: str) -> str:
        profile = get_profile("home")
        return await self._run_nuclei([target], profile)

    async def check_scan_status(self, job_id: str) -> ScanStatus:
        if await asyncio.to_thread(Path(job_id).exists):
            return ScanStatus.COMPLETED
        return ScanStatus.RUNNING

    async def fetch_and_normalize(self, job_id: str) -> list[NormalizedVulnerability]:
        raw = await asyncio.to_thread(Path(job_id).read_text, "utf-8")
        return normalize_report(raw)

    async def scan_endpoints(
        self, endpoints: list[str], profile: ScanProfileConfig
    ) -> list[NormalizedVulnerability]:
        if not endpoints:
            return []
        out_path = await self._run_nuclei(endpoints, profile)
        try:
            raw = await asyncio.to_thread(Path(out_path).read_text, "utf-8")
        finally:
            await asyncio.to_thread(Path(out_path).unlink, missing_ok=True)
        return normalize_report(raw)

    async def _run_nuclei(self, endpoints: list[str], profile: ScanProfileConfig) -> str:
        with tempfile.NamedTemporaryFile(
            prefix="nuclei-targets-", suffix=".txt", delete=False, mode="w", encoding="utf-8"
        ) as handle:
            handle.write("\n".join(endpoints))
            list_path = handle.name
        out_path = list_path + ".jsonl"
        exclude = exclude_tags_for_profile(profile)
        cmd = [
            self._settings.nuclei_binary,
            "-l",
            list_path,
            "-jsonl",
            "-o",
            out_path,
            "-rl",
            str(profile.nuclei_rate_limit),
            "-c",
            str(profile.nuclei_concurrency),
            "-etags",
            ",".join(exclude),
            "-silent",
            "-nc",
        ]
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            _stdout, stderr = await process.communicate()
            # Nuclei returns 0 even with no findings; non-zero is a hard failure.
            if process.returncode not in (0, 1):
                err_text = stderr.decode("utf-8", errors="replace").strip()
                raise RuntimeError(
                    f"nuclei failed (exit {process.returncode}): {err_text}"
                )
            await asyncio.to_thread(Path(out_path).touch, exist_ok=True)
            return out_path
        finally:
            await asyncio.to_thread(Path(list_path).unlink, missing_ok=True)
