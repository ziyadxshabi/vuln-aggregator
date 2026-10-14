"""Deterministic risk scoring, scan profiles, and defensive scope."""

from src.engine.profiles import ScanProfileConfig, get_profile
from src.engine.risk_engine import compute_risk, severity_from_score
from src.engine.scope import PreparedScan, ScopeError, classify_target, prepare_scan

__all__ = [
    "PreparedScan",
    "ScanProfileConfig",
    "ScopeError",
    "classify_target",
    "compute_risk",
    "get_profile",
    "prepare_scan",
    "severity_from_score",
]
