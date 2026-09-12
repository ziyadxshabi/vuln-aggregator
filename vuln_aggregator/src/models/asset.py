"""Host inventory discovered during a network assessment."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from src.models.enums import AssetCriticality


class DiscoveredPort(BaseModel):
    """One open port/service on a host."""

    model_config = ConfigDict(extra="forbid")

    port: int
    protocol: str = "tcp"
    service: str | None = None
    product: str | None = None
    version: str | None = None


class Asset(BaseModel):
    """A live host observed by discovery (nmap)."""

    model_config = ConfigDict(from_attributes=True, extra="forbid")

    ip: str
    hostname: str | None = None
    os_guess: str | None = None
    ports: list[DiscoveredPort] = Field(default_factory=list)
    criticality: AssetCriticality = AssetCriticality.MEDIUM
    scan_job_id: str | None = None
    first_seen: datetime | None = None
    last_seen: datetime | None = None

    @property
    def service_summary(self) -> str:
        names = [p.service or str(p.port) for p in self.ports]
        return ", ".join(names)
