"""Greenbone Vulnerability Management (GVM/OpenVAS) connector.

Network access uses the synchronous ``python-gvm`` client wrapped in
``asyncio.to_thread`` so the event loop is never blocked. The XML report parser
(:func:`normalize_report`) is pure and has no dependency on the SDK, so it can
be unit tested against fixture reports.
"""

from __future__ import annotations

import asyncio
import xml.etree.ElementTree as ET
from typing import TYPE_CHECKING, Any, ClassVar

from tenacity import retry, stop_after_attempt, wait_exponential

from src.config import Settings, get_settings
from src.connectors.base import BaseScannerConnector
from src.models.enums import ScanStatus, Severity
from src.models.vulnerability import NormalizedVulnerability

if TYPE_CHECKING:  # pragma: no cover - typing only
    from gvm.protocols.gmp import Gmp

# Default OpenVAS "Full and fast" scan config and default scanner identifiers.
_FULL_AND_FAST_CONFIG = "daba56c8-73ec-11df-a475-002264764cea"
_OPENVAS_DEFAULT_SCANNER = "08b69003-1fc2-403c-a33e-1a361dccf2f7"

_GVM_STATUS_MAP: dict[str, ScanStatus] = {
    "New": ScanStatus.PENDING,
    "Requested": ScanStatus.PENDING,
    "Queued": ScanStatus.PENDING,
    "Running": ScanStatus.RUNNING,
    "Done": ScanStatus.COMPLETED,
    "Stopped": ScanStatus.FAILED,
    "Stop Requested": ScanStatus.FAILED,
    "Interrupted": ScanStatus.FAILED,
}

_THREAT_TO_SEVERITY: dict[str, Severity] = {
    "Critical": Severity.CRITICAL,
    "High": Severity.HIGH,
    "Medium": Severity.MEDIUM,
    "Low": Severity.LOW,
    "Log": Severity.INFO,
    "Debug": Severity.INFO,
    "False Positive": Severity.INFO,
}


def _extract_cve(nvt: ET.Element | None) -> str | None:
    if nvt is None:
        return None
    cve_elem = nvt.find("cve")
    if cve_elem is not None and cve_elem.text and cve_elem.text.upper().startswith("CVE"):
        return cve_elem.text.strip()
    for ref in nvt.findall("./refs/ref"):
        if ref.get("type") == "cve":
            ref_id = ref.get("id")
            if ref_id:
                return ref_id.strip()
    return None


def _parse_port(raw: str | None) -> tuple[int, str]:
    if not raw or "/" not in raw:
        return 0, "tcp"
    number, _, proto = raw.partition("/")
    try:
        return int(number), (proto or "tcp")
    except ValueError:
        return 0, (proto or "tcp")


def _to_float(value: str | None) -> float | None:
    if value is None:
        return None
    try:
        parsed = float(value)
    except ValueError:
        return None
    return parsed if parsed >= 0 else None


def normalize_report(xml_text: str, fallback_target: str = "") -> list[NormalizedVulnerability]:
    """Parse a GMP ``get_report`` XML document into normalized findings."""

    root = ET.fromstring(xml_text)
    findings: list[NormalizedVulnerability] = []

    for result in root.iter("result"):
        nvt = result.find("nvt")
        threat = (result.findtext("threat") or "Log").strip()
        severity = _THREAT_TO_SEVERITY.get(threat, Severity.INFO)

        cvss_base = _to_float(nvt.findtext("cvss_base") if nvt is not None else None)
        host = (result.findtext("host") or fallback_target).strip()
        port_number, protocol = _parse_port(result.findtext("port"))

        title = (nvt.findtext("name") if nvt is not None else None) or result.findtext("name") or ""
        finding = NormalizedVulnerability(
            scanner=GVMConnector.scanner_name,
            scanner_vuln_id=(nvt.get("oid") if nvt is not None else None) or result.get("id") or "",
            cve_id=_extract_cve(nvt),
            asset_host=fallback_target or host,
            asset_ip=host,
            port=port_number,
            protocol=protocol,
            service=result.findtext("port"),
            title=title.strip(),
            description=(result.findtext("description") or "").strip(),
            solution=(nvt.findtext("solution") if nvt is not None else None),
            severity=severity,
            cvss_v2_score=cvss_base,
        )
        findings.append(finding)

    return findings


class GVMConnector(BaseScannerConnector):
    """Adapter for Greenbone/OpenVAS via the GMP protocol."""

    scanner_name: ClassVar[str] = "gvm"

    def __init__(self, settings: Settings | None = None) -> None:
        self._settings = settings or get_settings()

    def _connect(self) -> Gmp:
        """Create an authenticated GMP session (blocking; call via a thread)."""
        from gvm.connections import TLSConnection
        from gvm.protocols.gmp import Gmp

        connection = TLSConnection(
            hostname=self._settings.gvm_host,
            port=self._settings.gvm_port,
        )
        gmp = Gmp(connection=connection)
        gmp.__enter__()
        gmp.authenticate(self._settings.gvm_username, self._settings.gvm_password)
        return gmp

    def _start_scan_blocking(self, target: str) -> str:
        gmp = self._connect()
        try:
            target_resp = gmp.create_target(
                name=f"vuln-platform:{target}",
                hosts=[target],
                comment="Created by vuln-platform",
            )
            target_id = _xml_attr(target_resp, "id")
            task_resp = gmp.create_task(
                name=f"vuln-platform-scan:{target}",
                config_id=_FULL_AND_FAST_CONFIG,
                target_id=target_id,
                scanner_id=_OPENVAS_DEFAULT_SCANNER,
            )
            task_id = _xml_attr(task_resp, "id")
            gmp.start_task(task_id)
            return task_id
        finally:
            gmp.__exit__(None, None, None)

    def _status_blocking(self, job_id: str) -> ScanStatus:
        gmp = self._connect()
        try:
            task = gmp.get_task(job_id)
            status_text = _xml_text(task, ".//status") or "Running"
            return _GVM_STATUS_MAP.get(status_text, ScanStatus.RUNNING)
        finally:
            gmp.__exit__(None, None, None)

    def _fetch_report_blocking(self, job_id: str) -> str:
        gmp = self._connect()
        try:
            task = gmp.get_task(job_id)
            report_id = _xml_attr_xpath(task, ".//report", "id")
            if not report_id:
                return "<report/>"
            report = gmp.get_report(report_id, details=True)
            return _to_xml_string(report)
        finally:
            gmp.__exit__(None, None, None)

    @retry(stop=stop_after_attempt(4), wait=wait_exponential(multiplier=1, max=30), reraise=True)
    async def start_scan(self, target: str) -> str:
        return await asyncio.to_thread(self._start_scan_blocking, target)

    @retry(stop=stop_after_attempt(4), wait=wait_exponential(multiplier=1, max=30), reraise=True)
    async def check_scan_status(self, job_id: str) -> ScanStatus:
        return await asyncio.to_thread(self._status_blocking, job_id)

    async def fetch_and_normalize(self, job_id: str) -> list[NormalizedVulnerability]:
        xml_text = await asyncio.to_thread(self._fetch_report_blocking, job_id)
        return normalize_report(xml_text)


def _to_xml_string(element: Any) -> str:
    if isinstance(element, str):
        return element
    if isinstance(element, ET.Element):
        return ET.tostring(element, encoding="unicode")
    return str(element)


def _as_element(element: Any) -> ET.Element | None:
    if isinstance(element, ET.Element):
        return element
    if isinstance(element, str):
        return ET.fromstring(element)
    return None


def _xml_attr(element: Any, attr: str) -> str:
    node = _as_element(element)
    return (node.get(attr) if node is not None else None) or ""


def _xml_attr_xpath(element: Any, path: str, attr: str) -> str:
    node = _as_element(element)
    if node is None:
        return ""
    found = node.find(path)
    return (found.get(attr) if found is not None else None) or ""


def _xml_text(element: Any, path: str) -> str:
    node = _as_element(element)
    if node is None:
        return ""
    found = node.find(path)
    return (found.text if found is not None and found.text else "") or ""
