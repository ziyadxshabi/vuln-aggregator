"""Security-posture read model."""

from __future__ import annotations

from src.models.ports import VulnerabilityRepositoryPort
from src.models.posture import PostureMetrics


class PostureService:
    """Computes aggregated posture metrics for the metrics endpoint."""

    def __init__(self, vuln_repo: VulnerabilityRepositoryPort) -> None:
        self._vuln_repo = vuln_repo

    async def snapshot(self) -> PostureMetrics:
        return await self._vuln_repo.posture()
