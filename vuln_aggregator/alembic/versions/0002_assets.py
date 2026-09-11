"""assets table and scan_job audit/progress columns

Revision ID: 0002_assets
Revises: 0001_initial
Create Date: 2026-09-11
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision: str = "0002_assets"
down_revision: str | None = "0001_initial"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "scan_jobs",
        sa.Column("profile", sa.String(length=16), nullable=False, server_default="home"),
    )
    op.add_column("scan_jobs", sa.Column("requested_by", sa.String(length=128), nullable=True))
    op.add_column("scan_jobs", sa.Column("progress", JSONB(), nullable=True))

    op.create_table(
        "assets",
        sa.Column("ip", sa.String(length=64), primary_key=True),
        sa.Column("hostname", sa.String(length=255), nullable=True),
        sa.Column("os_guess", sa.String(length=255), nullable=True),
        sa.Column("ports", JSONB(), nullable=True),
        sa.Column("services", sa.Text(), nullable=False, server_default=""),
        sa.Column("criticality", sa.String(length=16), nullable=False, server_default="MEDIUM"),
        sa.Column("scan_job_id", sa.String(length=64), nullable=True),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_assets_hostname", "assets", ["hostname"])
    op.create_index("ix_assets_criticality", "assets", ["criticality"])


def downgrade() -> None:
    op.drop_index("ix_assets_criticality", table_name="assets")
    op.drop_index("ix_assets_hostname", table_name="assets")
    op.drop_table("assets")
    op.drop_column("scan_jobs", "progress")
    op.drop_column("scan_jobs", "requested_by")
    op.drop_column("scan_jobs", "profile")
