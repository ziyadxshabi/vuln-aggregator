"""nmap connector for defensive host/port/service discovery.

Uses TCP connect scans (``-sT``) so it runs without root or extra Docker
capabilities. Parsing (:func:`normalize_report`) is pure XML and unit-tested
against fixtures. :func:`hygiene_findings` turns well-known risky listeners
into normalized findings even before Nuclei runs.
"""

from __future__ import annotations

import asyncio
import ipaddress
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import ClassVar

from src.config import Settings, get_settings
from src.connectors.base import BaseScannerConnector
from src.engine.profiles import ScanProfileConfig, get_profile
from src.models.asset import Asset, DiscoveredPort
from src.models.enums import AssetCriticality, ScanStatus, Severity
from src.models.vulnerability import NormalizedVulnerability

RISKY_PORTS: dict[int, tuple[str, Severity, str, str]] = {
    21: (
        "ftp",
        Severity.HIGH,
        "FTP is unencrypted and often exposed with weak or default credentials.",
        "Disable FTP; prefer SFTP or FTPS, and restrict access.",
    ),
    23: (
        "telnet",
        Severity.CRITICAL,
        "Telnet transmits credentials in cleartext and is a common IoT backdoor.",
        "Disable Telnet; use SSH instead.",
    ),
    69: (
        "tftp",
        Severity.HIGH,
        "TFTP has no authentication and can leak device configuration.",
        "Disable TFTP unless required; bind it to management networks only.",
    ),
    135: (
        "msrpc",
        Severity.MEDIUM,
        "Windows RPC is frequently targeted for remote attacks.",
        "Block TCP 135 at the perimeter; apply current Windows patches.",
    ),
    139: (
        "netbios",
        Severity.HIGH,
        "NetBIOS/SMB legacy ports are a common ransomware entry point.",
        "Disable SMBv1/NetBIOS; restrict SMB to trusted hosts.",
    ),
    445: (
        "smb",
        Severity.HIGH,
        "SMB is a high-value target (EternalBlue and later worms).",
        "Patch the host; restrict SMB to internal trusted networks.",
    ),
    161: (
        "snmp",
        Severity.MEDIUM,
        "SNMP often uses default community strings and leaks inventory data.",
        "Use SNMPv3, change communities, and restrict source IPs.",
    ),
    512: (
        "exec",
        Severity.HIGH,
        "rexec is obsolete and unauthenticated by modern standards.",
        "Disable the r-services; use SSH.",
    ),
    513: (
        "login",
        Severity.HIGH,
        "rlogin is obsolete and unencrypted.",
        "Disable the r-services; use SSH.",
    ),
    514: (
        "shell",
        Severity.HIGH,
        "rsh is obsolete and unencrypted.",
        "Disable the r-services; use SSH.",
    ),
    1433: (
        "mssql",
        Severity.MEDIUM,
        "Microsoft SQL Server is exposed on the network.",
        "Bind to localhost or a management VLAN; require strong auth/TLS.",
    ),
    3306: (
        "mysql",
        Severity.MEDIUM,
        "MySQL/MariaDB is reachable from the network.",
        "Bind to localhost; require TLS and strong passwords.",
    ),
    3389: (
        "rdp",
        Severity.HIGH,
        "Remote Desktop is a frequent brute-force and ransomware target.",
        "Restrict RDP with VPN/NLA; do not expose it to untrusted networks.",
    ),
    5900: (
        "vnc",
        Severity.MEDIUM,
        "VNC is often unencrypted and weakly authenticated.",
        "Tunnel VNC over SSH or disable it.",
    ),
    27017: (
        "mongodb",
        Severity.MEDIUM,
        "MongoDB instances are frequently left unauthenticated on the network.",
        "Enable auth, bind to localhost, and firewall the port.",
    ),
}

RISKY_PORT_NUMBERS = frozenset(RISKY_PORTS)


def infer_criticality(ip: str) -> AssetCriticality:
    """Guess gateway-like hosts (*.1 / *.254) as HIGH; everyone else MEDIUM."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return AssetCriticality.MEDIUM
    if isinstance(addr, ipaddress.IPv4Address):
        last = int(str(addr).rsplit(".", 1)[-1])
        if last in (1, 254):
            return AssetCriticality.HIGH
    return AssetCriticality.MEDIUM


def normalize_report(xml_text: str) -> list[Asset]:
    """Parse an nmap XML document into live-host inventory."""
    root = ET.fromstring(xml_text)
    assets: list[Asset] = []
    for host in root.findall("host"):
        status = host.find("status")
        if status is not None and status.get("state") not in (None, "up"):
            continue
        ip = ""
        for addr in host.findall("address"):
            if addr.get("addrtype") in ("ipv4", "ipv6"):
                ip = addr.get("addr") or ""
                if addr.get("addrtype") == "ipv4":
                    break
        if not ip:
            continue
        hostname = None
        for hn in host.findall("./hostnames/hostname"):
            name = hn.get("name")
            if name:
                hostname = name
                break
        os_guess = None
        osmatch = host.find("./os/osmatch")
        if osmatch is not None:
            os_guess = osmatch.get("name")

        ports: list[DiscoveredPort] = []
        for port_el in host.findall("./ports/port"):
            state = port_el.find("state")
            if state is not None and state.get("state") != "open":
                continue
            try:
                port_num = int(port_el.get("portid") or "0")
            except ValueError:
                continue
            service_el = port_el.find("service")
            ports.append(
                DiscoveredPort(
                    port=port_num,
                    protocol=port_el.get("protocol") or "tcp",
                    service=service_el.get("name") if service_el is not None else None,
                    product=service_el.get("product") if service_el is not None else None,
                    version=service_el.get("version") if service_el is not None else None,
                )
            )
        assets.append(
            Asset(
                ip=ip,
                hostname=hostname,
                os_guess=os_guess,
                ports=ports,
                criticality=infer_criticality(ip),
            )
        )
    return assets


def hygiene_findings(assets: list[Asset]) -> list[NormalizedVulnerability]:
    """Emit defensive findings for well-known risky listeners and cleartext HTTP."""
    findings: list[NormalizedVulnerability] = []
    for asset in assets:
        open_ports = {p.port for p in asset.ports if p.protocol == "tcp"}
        for port in asset.ports:
            if port.protocol != "tcp" or port.port not in RISKY_PORTS:
                continue
            name, severity, description, solution = RISKY_PORTS[port.port]
            service = port.service or name
            findings.append(
                NormalizedVulnerability(
                    scanner=NmapConnector.scanner_name,
                    scanner_vuln_id=f"hygiene:{port.port}/{service}",
                    asset_host=asset.hostname or asset.ip,
                    asset_ip=asset.ip,
                    asset_os=asset.os_guess,
                    port=port.port,
                    protocol=port.protocol,
                    service=service,
                    title=f"Exposed {service.upper()} service on port {port.port}",
                    description=description,
                    solution=solution,
                    severity=severity,
                )
            )
        if 80 in open_ports and 443 not in open_ports:
            findings.append(
                NormalizedVulnerability(
                    scanner=NmapConnector.scanner_name,
                    scanner_vuln_id="hygiene:http-no-tls",
                    asset_host=asset.hostname or asset.ip,
                    asset_ip=asset.ip,
                    asset_os=asset.os_guess,
                    port=80,
                    protocol="tcp",
                    service="http",
                    title="Cleartext HTTP without HTTPS",
                    description=(
                        "The host serves HTTP on port 80 and has no HTTPS listener "
                        "on 443, so traffic may be intercepted."
                    ),
                    solution="Enable TLS (port 443) and redirect HTTP to HTTPS.",
                    severity=Severity.MEDIUM,
                )
            )
    return findings


class NmapConnector(BaseScannerConnector):
    """Adapter that runs nmap and produces host inventory plus hygiene findings."""

    scanner_name: ClassVar[str] = "nmap"

    def __init__(self, settings: Settings | None = None) -> None:
        self._settings = settings or get_settings()

    async def start_scan(self, target: str) -> str:
        profile = get_profile("home")
        out_path = Path(tempfile.gettempdir()) / f"nmap-{abs(hash(target))}.xml"
        await self._run_nmap(target, profile, out_path)
        return str(out_path)

    async def check_scan_status(self, job_id: str) -> ScanStatus:
        def _ready() -> bool:
            path = Path(job_id)
            return path.exists() and path.stat().st_size > 0

        if await asyncio.to_thread(_ready):
            return ScanStatus.COMPLETED
        return ScanStatus.RUNNING

    async def fetch_and_normalize(self, job_id: str) -> list[NormalizedVulnerability]:
        xml_text = await asyncio.to_thread(Path(job_id).read_text, "utf-8")
        return hygiene_findings(normalize_report(xml_text))

    async def scan_network(
        self, targets: list[str], profile: ScanProfileConfig
    ) -> list[Asset]:
        """Discover live hosts across one or more nmap targets (often CIDR chunks)."""
        by_ip: dict[str, Asset] = {}
        for target in targets:
            with tempfile.NamedTemporaryFile(prefix="nmap-", suffix=".xml", delete=False) as handle:
                out_path = Path(handle.name)
            try:
                await self._run_nmap(target, profile, out_path)
                xml_text = await asyncio.to_thread(out_path.read_text, "utf-8")
            finally:
                await asyncio.to_thread(out_path.unlink, missing_ok=True)
            for asset in normalize_report(xml_text):
                existing = by_ip.get(asset.ip)
                if existing is None:
                    by_ip[asset.ip] = asset
                else:
                    seen = {(p.port, p.protocol) for p in existing.ports}
                    merged = list(existing.ports)
                    for port in asset.ports:
                        if (port.port, port.protocol) not in seen:
                            merged.append(port)
                    existing.ports = merged
                    if asset.hostname and not existing.hostname:
                        existing.hostname = asset.hostname
        return list(by_ip.values())

    async def _run_nmap(
        self, target: str, profile: ScanProfileConfig, out_path: Path
    ) -> None:
        timing = profile.nmap_timing if profile.nmap_timing.startswith("-") else f"-{profile.nmap_timing}"
        cmd = [
            self._settings.nmap_binary,
            "-sT",
            "-sV",
            "--top-ports",
            str(profile.nmap_top_ports),
            timing,
            "--max-retries",
            str(profile.nmap_max_retries),
            "--host-timeout",
            profile.nmap_host_timeout,
            "-oX",
            str(out_path),
            target,
        ]
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _stdout, stderr = await process.communicate()
        if process.returncode not in (0, 1):
            # nmap uses 1 when hosts are down; other codes are real failures.
            err_text = stderr.decode("utf-8", errors="replace").strip()
            raise RuntimeError(
                f"nmap scan of {target!r} failed (exit {process.returncode}): {err_text}"
            )
        def _has_output() -> bool:
            return out_path.exists() and out_path.stat().st_size > 0

        if not await asyncio.to_thread(_has_output):
            raise RuntimeError(f"nmap produced no XML output for {target!r}")
