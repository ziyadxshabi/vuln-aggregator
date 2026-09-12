"""Unit tests for nmap XML normalization and hygiene findings."""

from __future__ import annotations

from pathlib import Path

from src.connectors.nmap import hygiene_findings, infer_criticality, normalize_report
from src.models.enums import AssetCriticality, Severity

_FIXTURE = Path(__file__).resolve().parent.parent / "fixtures" / "nmap_report.xml"


def test_nmap_normalization_skips_down_hosts() -> None:
    assets = normalize_report(_FIXTURE.read_text(encoding="utf-8"))
    assert {a.ip for a in assets} == {"192.168.1.1", "192.168.1.10"}
    router = next(a for a in assets if a.ip == "192.168.1.1")
    assert router.hostname == "router.lan"
    assert router.criticality is AssetCriticality.HIGH
    assert {p.port for p in router.ports} == {80, 23}


def test_hygiene_findings_telnet_smb_and_cleartext_http() -> None:
    assets = normalize_report(_FIXTURE.read_text(encoding="utf-8"))
    findings = hygiene_findings(assets)
    titles = {f.title for f in findings}
    assert any("TELNET" in t or "telnet" in t.lower() for t in titles)
    assert any("445" in t or "SMB" in t.upper() or "microsoft-ds" in t.lower() for t in titles)
    http = next(f for f in findings if f.scanner_vuln_id == "hygiene:http-no-tls")
    assert http.asset_ip == "192.168.1.1"
    assert http.severity is Severity.MEDIUM
    # Host with 443 should not get the cleartext-HTTP finding.
    assert all(not (f.scanner_vuln_id == "hygiene:http-no-tls" and f.asset_ip == "192.168.1.10") for f in findings)


def test_gateway_criticality_heuristic() -> None:
    assert infer_criticality("192.168.1.1") is AssetCriticality.HIGH
    assert infer_criticality("10.0.0.254") is AssetCriticality.HIGH
    assert infer_criticality("10.0.0.50") is AssetCriticality.MEDIUM
