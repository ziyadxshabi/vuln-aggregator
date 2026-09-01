"""Threat-intelligence value objects produced by the enrichment pipeline."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(slots=True)
class EnrichmentData:
    """Aggregated intelligence for a single CVE across all feeds."""

    cve_id: str
    epss_score: float | None = None
    epss_percentile: float | None = None
    is_known_exploited: bool = False
    has_weaponized_exploit: bool = False
    cvss_v3_score: float | None = None
    cvss_v3_vector: str | None = None
    sources: list[str] = field(default_factory=list)

    def merge(self, other: EnrichmentData) -> None:
        """Merge another partial result into this one, preferring present values."""
        self.epss_score = self.epss_score if self.epss_score is not None else other.epss_score
        self.epss_percentile = (
            self.epss_percentile if self.epss_percentile is not None else other.epss_percentile
        )
        self.is_known_exploited = self.is_known_exploited or other.is_known_exploited
        self.has_weaponized_exploit = self.has_weaponized_exploit or other.has_weaponized_exploit
        self.cvss_v3_score = (
            self.cvss_v3_score if self.cvss_v3_score is not None else other.cvss_v3_score
        )
        self.cvss_v3_vector = (
            self.cvss_v3_vector if self.cvss_v3_vector is not None else other.cvss_v3_vector
        )
        for source in other.sources:
            if source not in self.sources:
                self.sources.append(source)
