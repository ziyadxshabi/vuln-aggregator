"""Aggregated security-posture value object returned by the metrics endpoint."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(slots=True)
class PostureMetrics:
    """Point-in-time security posture of the estate."""

    total_findings: int = 0
    open_findings: int = 0
    severity_counts: dict[str, int] = field(default_factory=dict)
    known_exploited_count: int = 0
    weaponized_count: int = 0
    exposure_score: float = 0.0
    mean_finding_age_days: float | None = None
    mttr_days: float | None = None
