"""Unit tests for Nuclei JSONL normalization and endpoint derivation."""

from __future__ import annotations

from pathlib import Path

from src.connectors.nmap import normalize_report as nmap_normalize
from src.connectors.nuclei import endpoints_from_assets, exclude_tags_for_profile, normalize_report
from src.engine.profiles import get_profile
from src.models.enums import Severity

_FIXTURE = Path(__file__).resolve().parent.parent / "fixtures" / "nuclei_report.jsonl"
_NMAP = Path(__file__).resolve().parent.parent / "fixtures" / "nmap_report.xml"


def test_nuclei_normalization() -> None:
    findings = normalize_report(_FIXTURE.read_text(encoding="utf-8"))
    assert len(findings) == 3
    apache = next(f for f in findings if f.cve_id == "CVE-2021-41773")
    assert apache.scanner == "nuclei"
    assert apache.severity is Severity.HIGH  # from CVSS 7.5
    assert apache.asset_ip == "192.168.1.10"
    assert apache.port == 80
    ssl = next(f for f in findings if f.scanner_vuln_id == "ssl-issuer")
    assert ssl.severity is Severity.INFO
    assert ssl.port == 443
    panel = next(f for f in findings if f.scanner_vuln_id == "exposed-panel")
    assert panel.severity is Severity.MEDIUM
    assert panel.asset_ip == "192.168.1.1"


def test_endpoints_from_nmap_assets() -> None:
    assets = nmap_normalize(_NMAP.read_text(encoding="utf-8"))
    endpoints = endpoints_from_assets(assets)
    assert "192.168.1.1" in endpoints
    assert "http://192.168.1.1:80" in endpoints
    assert "https://192.168.1.10:443" in endpoints
    assert "192.168.1.10:22" in endpoints
    assert "192.168.1.10:445" in endpoints


def test_home_excludes_default_login() -> None:
    tags = exclude_tags_for_profile(get_profile("home"))
    assert "intrusive" in tags
    assert "dos" in tags
    assert "fuzz" in tags
    assert "default-login" in tags


def test_thorough_allows_default_login() -> None:
    tags = exclude_tags_for_profile(get_profile("thorough"))
    assert "intrusive" in tags
    assert "default-login" not in tags
