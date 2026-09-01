"""Unit tests for scanner report normalization using fixture reports."""

from __future__ import annotations

import importlib.util
from pathlib import Path

from src.connectors.gvm import normalize_report as gvm_normalize
from src.connectors.nessus import normalize_report as nessus_normalize
from src.connectors.trivy import normalize_report as trivy_normalize
from src.models.enums import Severity
from src.models.vulnerability import fingerprint

_conftest_path = Path(__file__).resolve().parent.parent / "conftest.py"
_spec = importlib.util.spec_from_file_location("unit_conftest", _conftest_path)
_conftest = importlib.util.module_from_spec(_spec)
assert _spec.loader is not None
_spec.loader.exec_module(_conftest)
load_fixture = _conftest.load_fixture


def test_gvm_normalization() -> None:
    findings = gvm_normalize(load_fixture("gvm_report.xml"))
    assert len(findings) == 2

    ssh = next(f for f in findings if f.asset_ip == "10.0.0.5")
    assert ssh.scanner == "gvm"
    assert ssh.cve_id == "CVE-2020-1111"  # extracted from refs/ref
    assert ssh.severity is Severity.HIGH
    assert ssh.cvss_v2_score == 7.5
    assert ssh.port == 22
    assert ssh.protocol == "tcp"
    assert ssh.solution is not None
    # deterministic identity
    assert ssh.id == fingerprint(
        "gvm", "1.3.6.1.4.1.25623.1.0.100001", "10.0.0.5", 22, "tcp"
    )

    apache = next(f for f in findings if f.asset_ip == "10.0.0.6")
    assert apache.cve_id == "CVE-2019-2222"  # extracted from <cve>
    assert apache.severity is Severity.MEDIUM


def test_nessus_normalization() -> None:
    findings = nessus_normalize(load_fixture("nessus_report.json"))
    assert len(findings) == 2

    ssl = next(f for f in findings if f.scanner_vuln_id == "19506")
    assert ssl.scanner == "nessus"
    assert ssl.cve_id == "CVE-2016-2107"
    assert ssl.cvss_v3_score == 7.4
    assert ssl.cvss_v2_score == 5.8
    assert ssl.severity is Severity.HIGH  # derived from CVSS v3 (7.4)
    assert ssl.asset_ip == "10.0.0.10"
    assert ssl.port == 443
    assert ssl.service == "www"

    info = next(f for f in findings if f.scanner_vuln_id == "10287")
    assert info.cve_id is None
    assert info.severity is Severity.INFO


def test_trivy_normalization() -> None:
    findings = trivy_normalize(load_fixture("trivy_report.json"))
    assert len(findings) == 2

    openssl = next(f for f in findings if f.service == "openssl")
    assert openssl.scanner == "trivy"
    assert openssl.cve_id == "CVE-2023-1234"
    assert openssl.scanner_vuln_id == "openssl:CVE-2023-1234"
    assert openssl.severity is Severity.CRITICAL
    assert openssl.cvss_v3_score == 9.8
    assert openssl.solution is not None and "1.1.1t" in openssl.solution
    assert openssl.asset_ip == "myapp:1.0.0"

    ghsa = next(f for f in findings if f.service == "leftpad")
    assert ghsa.cve_id is None  # non-CVE advisory id
    assert ghsa.severity is Severity.LOW
