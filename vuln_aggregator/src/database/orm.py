"""Relational models with compound indexes for high-throughput querying."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy import (
    JSON as SA_JSON,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from src.database.base import Base, utcnow

# JSON on SQLite, JSONB on PostgreSQL.
JSONVariant = SA_JSON().with_variant(JSONB(), "postgresql")


class VulnerabilityRow(Base):
    """Persistent normalized finding."""

    __tablename__ = "vulnerabilities"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    scanner: Mapped[str] = mapped_column(String(32), index=True)
    scanner_vuln_id: Mapped[str] = mapped_column(String(255))
    cve_id: Mapped[str | None] = mapped_column(String(32), nullable=True)

    asset_host: Mapped[str] = mapped_column(String(255), default="")
    asset_ip: Mapped[str] = mapped_column(String(64), default="")
    asset_os: Mapped[str | None] = mapped_column(String(255), nullable=True)
    port: Mapped[int] = mapped_column(Integer, default=0)
    protocol: Mapped[str] = mapped_column(String(16), default="tcp")
    service: Mapped[str | None] = mapped_column(String(128), nullable=True)

    title: Mapped[str] = mapped_column(Text, default="")
    description: Mapped[str] = mapped_column(Text, default="")
    solution: Mapped[str | None] = mapped_column(Text, nullable=True)

    severity: Mapped[str] = mapped_column(String(16), default="INFO", index=True)
    cvss_v2_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    cvss_v3_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    cvss_v3_vector: Mapped[str | None] = mapped_column(String(128), nullable=True)

    epss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    epss_percentile: Mapped[float | None] = mapped_column(Float, nullable=True)
    is_known_exploited: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    has_weaponized_exploit: Mapped[bool] = mapped_column(Boolean, default=False)
    enrichment_sources: Mapped[list[str]] = mapped_column(JSONVariant, default=list)

    risk_score: Mapped[float] = mapped_column(Float, default=0.0, index=True)
    risk_tier: Mapped[str] = mapped_column(String(16), default="INFO")

    status: Mapped[str] = mapped_column(String(16), default="OPEN", index=True)
    scan_job_id: Mapped[str | None] = mapped_column(String(64), nullable=True)

    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        Index("ix_vuln_asset_port_scanner", "asset_ip", "port", "scanner_vuln_id"),
        Index("ix_vuln_cve", "cve_id"),
        Index("ix_vuln_rank", "risk_score", "id"),
    )


class ScanJobRow(Base):
    """Persistent aggregated scan job."""

    __tablename__ = "scan_jobs"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    status: Mapped[str] = mapped_column(String(16), default="PENDING", index=True)
    targets: Mapped[list[str]] = mapped_column(JSONVariant, default=list)
    scanners: Mapped[list[str]] = mapped_column(JSONVariant, default=list)
    total_findings: Mapped[int] = mapped_column(Integer, default=0)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )
