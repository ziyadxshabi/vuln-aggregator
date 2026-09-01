"""Tenable Nessus connector.

Uses the Nessus REST API with API-key authentication. Report fetching walks
per-host detail pages (pagination) and assembles a normalized intermediate
structure that :func:`normalize_report` converts into domain findings. The
parser is pure and SDK-free for unit testing.
"""

from __future__ import annotations

from typing import Any, ClassVar

import httpx
from tenacity import retry, stop_after_attempt, wait_exponential

from src.config import Settings, get_settings
from src.connectors.base import BaseScannerConnector
from src.models.enums import ScanStatus, Severity
from src.models.vulnerability import NormalizedVulnerability

# Tenable numeric severity (0=Info .. 4=Critical) -> domain severity.
_NESSUS_SEVERITY: dict[int, Severity] = {
    0: Severity.INFO,
    1: Severity.LOW,
    2: Severity.MEDIUM,
    3: Severity.HIGH,
    4: Severity.CRITICAL,
}

_NESSUS_STATUS: dict[str, ScanStatus] = {
    "empty": ScanStatus.PENDING,
    "pending": ScanStatus.PENDING,
    "running": ScanStatus.RUNNING,
    "processing": ScanStatus.RUNNING,
    "completed": ScanStatus.COMPLETED,
    "canceled": ScanStatus.FAILED,
    "aborted": ScanStatus.FAILED,
    "stopped": ScanStatus.FAILED,
}


def _first_cve(raw: Any) -> str | None:
    if isinstance(raw, list) and raw:
        return str(raw[0])
    if isinstance(raw, str) and raw:
        return raw
    return None


def _to_float(value: Any) -> float | None:
    if value in (None, "", "None"):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def normalize_report(report: dict[str, Any]) -> list[NormalizedVulnerability]:
    """Normalize an assembled Nessus scan report.

    Expected shape (assembled by :meth:`NessusConnector._fetch_report`)::

        {
          "hosts": [
            {"hostname": str, "ip": str, "os": str | None,
             "vulnerabilities": [ {plugin_id, plugin_name, severity, cve,
                cvss3_base_score, cvss_base_score, cvss3_vector, port,
                protocol, svc_name, description, solution, see_also}, ... ]}
          ]
        }
    """

    findings: list[NormalizedVulnerability] = []
    for host in report.get("hosts", []):
        hostname = str(host.get("hostname") or host.get("ip") or "")
        ip = str(host.get("ip") or hostname)
        os_name = host.get("os")
        for item in host.get("vulnerabilities", []):
            sev = _NESSUS_SEVERITY.get(int(item.get("severity", 0)), Severity.INFO)
            cvss_v3 = _to_float(item.get("cvss3_base_score"))
            finding = NormalizedVulnerability(
                scanner=NessusConnector.scanner_name,
                scanner_vuln_id=str(item.get("plugin_id", "")),
                cve_id=_first_cve(item.get("cve")),
                asset_host=hostname,
                asset_ip=ip,
                asset_os=os_name,
                port=int(item.get("port", 0) or 0),
                protocol=str(item.get("protocol", "tcp") or "tcp"),
                service=item.get("svc_name"),
                title=str(item.get("plugin_name", "")),
                description=str(item.get("description", "") or ""),
                solution=item.get("solution"),
                severity=sev if cvss_v3 is None else Severity.from_cvss(cvss_v3),
                cvss_v2_score=_to_float(item.get("cvss_base_score")),
                cvss_v3_score=cvss_v3,
                cvss_v3_vector=item.get("cvss3_vector"),
            )
            findings.append(finding)
    return findings


class NessusConnector(BaseScannerConnector):
    """Adapter for Tenable Nessus / Tenable.io."""

    scanner_name: ClassVar[str] = "nessus"

    def __init__(self, settings: Settings | None = None) -> None:
        self._settings = settings or get_settings()

    def _client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            base_url=self._settings.nessus_url,
            headers={
                "X-ApiKeys": (
                    f"accessKey={self._settings.nessus_access_key};"
                    f"secretKey={self._settings.nessus_secret_key}"
                ),
                "Content-Type": "application/json",
            },
            verify=self._settings.nessus_verify_tls,
            timeout=self._settings.http_timeout_seconds,
        )

    @retry(stop=stop_after_attempt(4), wait=wait_exponential(multiplier=1, max=30), reraise=True)
    async def start_scan(self, target: str) -> str:
        async with self._client() as client:
            create = await client.post(
                "/scans",
                json={
                    "uuid": "ab4bacd2-05f6-425c-9d79-3ba7aa4b1b0e",
                    "settings": {"name": f"vuln-platform:{target}", "text_targets": target},
                },
            )
            create.raise_for_status()
            scan_id = str(create.json()["scan"]["id"])
            launch = await client.post(f"/scans/{scan_id}/launch")
            launch.raise_for_status()
            return scan_id

    @retry(stop=stop_after_attempt(4), wait=wait_exponential(multiplier=1, max=30), reraise=True)
    async def check_scan_status(self, job_id: str) -> ScanStatus:
        async with self._client() as client:
            resp = await client.get(f"/scans/{job_id}")
            resp.raise_for_status()
            status = str(resp.json().get("info", {}).get("status", "running")).lower()
            return _NESSUS_STATUS.get(status, ScanStatus.RUNNING)

    async def fetch_and_normalize(self, job_id: str) -> list[NormalizedVulnerability]:
        report = await self._fetch_report(job_id)
        return normalize_report(report)

    @retry(stop=stop_after_attempt(4), wait=wait_exponential(multiplier=1, max=30), reraise=True)
    async def _fetch_report(self, job_id: str) -> dict[str, Any]:
        """Assemble a normalized report by paginating host detail pages."""
        async with self._client() as client:
            scan_resp = await client.get(f"/scans/{job_id}")
            scan_resp.raise_for_status()
            scan = scan_resp.json()

            hosts_out: list[dict[str, Any]] = []
            for host in scan.get("hosts", []):
                host_id = host.get("host_id")
                if host_id is None:
                    continue
                detail = await client.get(f"/scans/{job_id}/hosts/{host_id}")
                detail.raise_for_status()
                detail_json = detail.json()
                info = detail_json.get("info", {})
                vulns: list[dict[str, Any]] = []
                for vuln in detail_json.get("vulnerabilities", []):
                    plugin_id = vuln.get("plugin_id")
                    plugin = await client.get(
                        f"/scans/{job_id}/hosts/{host_id}/plugins/{plugin_id}"
                    )
                    plugin.raise_for_status()
                    outputs = plugin.json().get("outputs", [])
                    ports = _extract_ports(outputs)
                    attrs = _plugin_attributes(plugin.json())
                    for port_number, protocol, svc in ports:
                        vulns.append(
                            {
                                "plugin_id": plugin_id,
                                "plugin_name": vuln.get("plugin_name"),
                                "severity": vuln.get("severity", 0),
                                "cve": attrs.get("cve"),
                                "cvss_base_score": attrs.get("cvss_base_score"),
                                "cvss3_base_score": attrs.get("cvss3_base_score"),
                                "cvss3_vector": attrs.get("cvss3_vector"),
                                "port": port_number,
                                "protocol": protocol,
                                "svc_name": svc,
                                "description": attrs.get("description", ""),
                                "solution": attrs.get("solution"),
                                "see_also": attrs.get("see_also", []),
                            }
                        )
                hosts_out.append(
                    {
                        "hostname": info.get("host-fqdn") or info.get("host-ip"),
                        "ip": info.get("host-ip"),
                        "os": info.get("operating-system"),
                        "vulnerabilities": vulns,
                    }
                )
            return {"scan_id": job_id, "hosts": hosts_out}


def _extract_ports(outputs: list[dict[str, Any]]) -> list[tuple[int, str, str | None]]:
    ports: list[tuple[int, str, str | None]] = []
    for output in outputs:
        for port_key, _hosts in output.get("ports", {}).items():
            number, _, proto = str(port_key).partition("/")
            svc = proto.split()[1] if len(proto.split()) > 1 else None
            protocol = proto.split()[0] if proto else "tcp"
            try:
                ports.append((int(number), protocol or "tcp", svc))
            except ValueError:
                ports.append((0, protocol or "tcp", svc))
    return ports or [(0, "tcp", None)]


def _plugin_attributes(plugin_json: dict[str, Any]) -> dict[str, Any]:
    attributes = plugin_json.get("info", {}).get("plugindescription", {}).get(
        "pluginattributes", {}
    )
    risk = attributes.get("risk_information", {})
    ref = attributes.get("ref_information", {}).get("ref", [])
    cves = [
        value.get("value")
        for entry in (ref if isinstance(ref, list) else [ref])
        for value in entry.get("values", {}).get("value", [])
        if isinstance(value, dict) and entry.get("name") == "cve"
    ]
    return {
        "cve": cves,
        "cvss_base_score": risk.get("cvss_base_score"),
        "cvss3_base_score": risk.get("cvss3_base_score"),
        "cvss3_vector": risk.get("cvss3_vector"),
        "description": attributes.get("description", ""),
        "solution": attributes.get("solution"),
        "see_also": attributes.get("see_also", []),
    }
