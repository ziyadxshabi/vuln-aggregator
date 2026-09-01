"""Pure, deterministic enterprise risk-scoring engine.

The scoring function has **no** I/O and **no** hidden state: given the same
:class:`RiskSignal` it always returns the same :class:`RiskResult`. This makes
it trivial to unit test and safe to run inside workers or request handlers.

Model (all components normalized to a 0-10 scale before weighting):

* CVSS base severity ....... weight 40%  (prefers CVSS v3.1, then v2, then a
  qualitative severity fallback)
* EPSS exploitation odds ... weight 30%
* Weaponized public exploit  weight 15%  (flat contribution when present)
* CISA KEV active-exploit ... override: applies a fixed boost and forces the
  score into at least the Critical band
* Asset criticality ........ multiplier in the range 0.5x - 1.5x applied last
"""

from __future__ import annotations

from src.models.enums import Severity
from src.models.vulnerability import RiskResult, RiskSignal

CVSS_WEIGHT = 0.40
EPSS_WEIGHT = 0.30
EXPLOIT_WEIGHT = 0.15

KEV_BOOST = 1.5
KEV_CRITICAL_FLOOR = 9.0

MAX_SCORE = 10.0
MIN_SCORE = 0.0

# Fallback CVSS-equivalent when a finding carries only a qualitative severity.
_SEVERITY_BASELINE: dict[Severity, float] = {
    Severity.INFO: 0.0,
    Severity.LOW: 3.0,
    Severity.MEDIUM: 5.5,
    Severity.HIGH: 8.0,
    Severity.CRITICAL: 9.5,
}


def _clamp(value: float, low: float = MIN_SCORE, high: float = MAX_SCORE) -> float:
    return max(low, min(high, value))


def _base_cvss(signal: RiskSignal) -> float:
    """Resolve the effective CVSS base score (0-10)."""
    if signal.cvss_v3_score is not None:
        return _clamp(signal.cvss_v3_score)
    if signal.cvss_v2_score is not None:
        return _clamp(signal.cvss_v2_score)
    return _SEVERITY_BASELINE.get(signal.severity, 0.0)


def severity_from_score(score: float) -> Severity:
    """Map a 0-10 risk score onto the qualitative tier used for triage."""
    return Severity.from_cvss(score)


def compute_risk(signal: RiskSignal) -> RiskResult:
    """Compute a deterministic 0-10 risk score with a transparent breakdown."""

    cvss_base = _base_cvss(signal)
    epss = _clamp(signal.epss_score if signal.epss_score is not None else 0.0, 0.0, 1.0)

    cvss_component = CVSS_WEIGHT * cvss_base
    epss_component = EPSS_WEIGHT * (epss * 10.0)
    exploit_component = EXPLOIT_WEIGHT * (10.0 if signal.has_weaponized_exploit else 0.0)

    base_score = cvss_component + epss_component + exploit_component

    kev_override = False
    if signal.is_known_exploited:
        kev_override = True
        base_score = max(base_score + KEV_BOOST, KEV_CRITICAL_FLOOR)

    multiplier = _clamp(signal.asset_criticality_multiplier, 0.5, 1.5)
    final_score = _clamp(base_score * multiplier)

    components = {
        "cvss_base": round(cvss_base, 3),
        "cvss_component": round(cvss_component, 3),
        "epss": round(epss, 4),
        "epss_component": round(epss_component, 3),
        "exploit_component": round(exploit_component, 3),
        "kev_boost": KEV_BOOST if kev_override else 0.0,
        "asset_multiplier": round(multiplier, 3),
        "pre_multiplier_score": round(_clamp(base_score), 3),
    }

    score = round(final_score, 2)
    return RiskResult(
        score=score,
        tier=severity_from_score(score),
        kev_override=kev_override,
        components=components,
    )
