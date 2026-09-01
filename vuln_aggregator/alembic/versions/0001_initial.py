"""initial schema: vulnerabilities and scan_jobs

Revision ID: 0001_initial
Revises:
Create Date: 2026-09-01
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision: str = "0001_initial"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "vulnerabilities",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("scanner", sa.String(length=32), nullable=False),
        sa.Column("scanner_vuln_id", sa.String(length=255), nullable=False),
        sa.Column("cve_id", sa.String(length=32), nullable=True),
        sa.Column("asset_host", sa.String(length=255), nullable=False, server_default=""),
        sa.Column("asset_ip", sa.String(length=64), nullable=False, server_default=""),
        sa.Column("asset_os", sa.String(length=255), nullable=True),
        sa.Column("port", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("protocol", sa.String(length=16), nullable=False, server_default="tcp"),
        sa.Column("service", sa.String(length=128), nullable=True),
        sa.Column("title", sa.Text(), nullable=False, server_default=""),
        sa.Column("description", sa.Text(), nullable=False, server_default=""),
        sa.Column("solution", sa.Text(), nullable=True),
        sa.Column("severity", sa.String(length=16), nullable=False, server_default="INFO"),
        sa.Column("cvss_v2_score", sa.Float(), nullable=True),
        sa.Column("cvss_v3_score", sa.Float(), nullable=True),
        sa.Column("cvss_v3_vector", sa.String(length=128), nullable=True),
        sa.Column("epss_score", sa.Float(), nullable=True),
        sa.Column("epss_percentile", sa.Float(), nullable=True),
        sa.Column("is_known_exploited", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("has_weaponized_exploit", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("enrichment_sources", JSONB(), nullable=True),
        sa.Column("risk_score", sa.Float(), nullable=False, server_default="0"),
        sa.Column("risk_tier", sa.String(length=16), nullable=False, server_default="INFO"),
        sa.Column("status", sa.String(length=16), nullable=False, server_default="OPEN"),
        sa.Column("scan_job_id", sa.String(length=64), nullable=True),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_vuln_asset_port_scanner", "vulnerabilities", ["asset_ip", "port", "scanner_vuln_id"])
    op.create_index("ix_vuln_cve", "vulnerabilities", ["cve_id"])
    op.create_index("ix_vuln_rank", "vulnerabilities", ["risk_score", "id"])
    op.create_index("ix_vulnerabilities_scanner", "vulnerabilities", ["scanner"])
    op.create_index("ix_vulnerabilities_severity", "vulnerabilities", ["severity"])
    op.create_index("ix_vulnerabilities_is_known_exploited", "vulnerabilities", ["is_known_exploited"])
    op.create_index("ix_vulnerabilities_risk_score", "vulnerabilities", ["risk_score"])
    op.create_index("ix_vulnerabilities_status", "vulnerabilities", ["status"])

    op.create_table(
        "scan_jobs",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("status", sa.String(length=16), nullable=False, server_default="PENDING"),
        sa.Column("targets", JSONB(), nullable=True),
        sa.Column("scanners", JSONB(), nullable=True),
        sa.Column("total_findings", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_scan_jobs_status", "scan_jobs", ["status"])


def downgrade() -> None:
    op.drop_index("ix_scan_jobs_status", table_name="scan_jobs")
    op.drop_table("scan_jobs")
    op.drop_index("ix_vulnerabilities_status", table_name="vulnerabilities")
    op.drop_index("ix_vulnerabilities_risk_score", table_name="vulnerabilities")
    op.drop_index("ix_vulnerabilities_is_known_exploited", table_name="vulnerabilities")
    op.drop_index("ix_vulnerabilities_severity", table_name="vulnerabilities")
    op.drop_index("ix_vulnerabilities_scanner", table_name="vulnerabilities")
    op.drop_index("ix_vuln_rank", table_name="vulnerabilities")
    op.drop_index("ix_vuln_cve", table_name="vulnerabilities")
    op.drop_index("ix_vuln_asset_port_scanner", table_name="vulnerabilities")
    op.drop_table("vulnerabilities")
