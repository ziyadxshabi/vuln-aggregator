"""Domain models and ports (framework-agnostic core)."""

from src.models.enrichment import EnrichmentData
from src.models.enums import (
    AssetCriticality,
    FindingStatus,
    Role,
    ScanStatus,
    Severity,
)
from src.models.ports import (
    CachePort,
    ScanJobRepositoryPort,
    TaskDispatcherPort,
    ThreatIntelPort,
    VulnerabilityRepositoryPort,
)
from src.models.posture import PostureMetrics
from src.models.scan import ScanJob
from src.models.vulnerability import (
    NormalizedVulnerability,
    RiskResult,
    RiskSignal,
    fingerprint,
)

__all__ = [
    "AssetCriticality",
    "CachePort",
    "EnrichmentData",
    "FindingStatus",
    "NormalizedVulnerability",
    "PostureMetrics",
    "RiskResult",
    "RiskSignal",
    "Role",
    "ScanJob",
    "ScanJobRepositoryPort",
    "ScanStatus",
    "Severity",
    "TaskDispatcherPort",
    "ThreatIntelPort",
    "VulnerabilityRepositoryPort",
    "fingerprint",
]
