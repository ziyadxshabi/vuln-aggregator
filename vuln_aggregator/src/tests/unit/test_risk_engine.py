"""Pure unit tests for the deterministic risk engine."""

from __future__ import annotations

import pytest

from src.engine.risk_engine import compute_risk
from src.models.enums import Severity
from src.models.vulnerability import RiskSignal


def _signal(**overrides: object) -> RiskSignal:
    defaults: dict[str, object] = {
        "cvss_v3_score": None,
        "cvss_v2_score": None,
        "epss_score": None,
        "is_known_exploited": False,
        "has_weaponized_exploit": False,
        "severity": Severity.INFO,
        "asset_criticality_multiplier": 1.0,
    }
    defaults.update(overrides)
    return RiskSignal(**defaults)  # type: ignore[arg-type]


def test_cvss_and_epss_weighting() -> None:
    result = compute_risk(_signal(cvss_v3_score=9.8, epss_score=0.5))
    # 0.40*9.8 + 0.30*(0.5*10) = 3.92 + 1.5
    assert result.score == pytest.approx(5.42)
    assert result.tier is Severity.MEDIUM
    assert result.kev_override is False


def test_missing_cvss_falls_back_to_severity() -> None:
    result = compute_risk(_signal(severity=Severity.HIGH))
    assert result.score == pytest.approx(3.2)  # 0.40 * 8.0 baseline
    assert result.components["cvss_base"] == pytest.approx(8.0)


def test_zero_epss_contributes_nothing() -> None:
    result = compute_risk(_signal(cvss_v3_score=7.0, epss_score=0.0))
    assert result.score == pytest.approx(2.8)
    assert result.components["epss_component"] == pytest.approx(0.0)


def test_weaponized_exploit_adds_fixed_bonus() -> None:
    without = compute_risk(_signal(cvss_v3_score=5.0))
    with_exploit = compute_risk(_signal(cvss_v3_score=5.0, has_weaponized_exploit=True))
    assert with_exploit.score - without.score == pytest.approx(1.5)


def test_kev_override_forces_critical_floor() -> None:
    result = compute_risk(_signal(cvss_v3_score=5.0, is_known_exploited=True))
    assert result.kev_override is True
    assert result.score == pytest.approx(9.0)
    assert result.tier is Severity.CRITICAL


def test_asset_multiplier_clamped_and_capped() -> None:
    capped = compute_risk(
        _signal(
            cvss_v3_score=9.8,
            epss_score=1.0,
            has_weaponized_exploit=True,
            is_known_exploited=True,
            asset_criticality_multiplier=1.5,
        )
    )
    assert capped.score == pytest.approx(10.0)
    assert capped.tier is Severity.CRITICAL

    low = compute_risk(_signal(cvss_v3_score=10.0, asset_criticality_multiplier=0.1))
    # multiplier clamped up to 0.5 -> 0.40*10*0.5 = 2.0
    assert low.score == pytest.approx(2.0)


def test_scoring_is_deterministic() -> None:
    signal = _signal(cvss_v3_score=8.1, epss_score=0.2, has_weaponized_exploit=True)
    assert compute_risk(signal) == compute_risk(signal)
