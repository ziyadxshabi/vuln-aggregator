"""Domain model describing an aggregated scan job across scanners/targets."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from src.models.enums import ScanStatus


class ScanJob(BaseModel):
    """A user-initiated aggregation job that fans out to one or more scanners."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    status: ScanStatus = ScanStatus.PENDING
    targets: list[str] = Field(default_factory=list)
    scanners: list[str] = Field(default_factory=list)
    total_findings: int = 0
    error: str | None = None
    created_at: datetime
    updated_at: datetime
