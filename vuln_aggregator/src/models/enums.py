"""Domain enumerations shared across every layer."""

from __future__ import annotations

from enum import Enum


class ScanStatus(str, Enum):
    """Lifecycle state of a scanner job (and of an aggregated scan job)."""

    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class Severity(str, Enum):
    """Normalized qualitative severity."""

    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]

    @classmethod
    def from_cvss(cls, score: float | None) -> Severity:
        """Map a CVSS base score (0-10) to a qualitative severity band."""
        if score is None:
            return cls.INFO
        if score >= 9.0:
            return cls.CRITICAL
        if score >= 7.0:
            return cls.HIGH
        if score >= 4.0:
            return cls.MEDIUM
        if score > 0.0:
            return cls.LOW
        return cls.INFO


_SEVERITY_RANK: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class Role(str, Enum):
    """Role-based access control tiers."""

    ADMIN = "ADMIN"
    ANALYST = "ANALYST"
    READ_ONLY = "READ_ONLY"


class AssetCriticality(str, Enum):
    """Business criticality tier for an asset, driving the risk multiplier."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def multiplier(self) -> float:
        return _CRITICALITY_MULTIPLIER[self]


_CRITICALITY_MULTIPLIER: dict[AssetCriticality, float] = {
    AssetCriticality.LOW: 0.5,
    AssetCriticality.MEDIUM: 1.0,
    AssetCriticality.HIGH: 1.25,
    AssetCriticality.CRITICAL: 1.5,
}


class FindingStatus(str, Enum):
    """Whether a finding is still present or has been remediated."""

    OPEN = "OPEN"
    RESOLVED = "RESOLVED"


class ScanProfile(str, Enum):
    """Defensive scan intensity and host-cap preset."""

    HOME = "home"
    THOROUGH = "thorough"
    LARGE = "large"


class TargetKind(str, Enum):
    """How a scan target is interpreted by the pipeline."""

    NETWORK = "network"
    IMAGE = "image"
