"""Vulnerability query routes with cursor pagination and filtering."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request

from src.api.deps import VulnRepoDep
from src.api.errors import NotFoundError
from src.api.rate_limit import limiter
from src.api.schemas import FindingStatusUpdate, VulnerabilityListResponse, VulnerabilityResponse
from src.api.security import AuthUser, get_current_user, require_roles
from src.models.enums import Role, Severity

router = APIRouter(prefix="/vulnerabilities", tags=["vulnerabilities"])


@router.get("", response_model=VulnerabilityListResponse)
@limiter.limit("120/minute")
async def list_vulnerabilities(
    request: Request,
    vuln_repo: VulnRepoDep,
    _user: Annotated[AuthUser, Depends(get_current_user)],
    cursor: Annotated[str | None, Query(description="Opaque pagination cursor")] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 50,
    severity: Annotated[Severity | None, Query()] = None,
    epss_min: Annotated[float | None, Query(ge=0.0, le=1.0)] = None,
    epss_max: Annotated[float | None, Query(ge=0.0, le=1.0)] = None,
    asset_group: Annotated[str | None, Query(description="Asset IP prefix or host substring")] = None,
    only_known_exploited: Annotated[bool, Query()] = False,
) -> VulnerabilityListResponse:
    """List findings ordered by risk score (descending) with cursor pagination."""
    items, next_cursor = await vuln_repo.list(
        cursor=cursor,
        limit=limit,
        severity=severity,
        epss_min=epss_min,
        epss_max=epss_max,
        asset_group=asset_group,
        only_known_exploited=only_known_exploited,
    )
    responses = [VulnerabilityResponse.from_domain(item) for item in items]
    return VulnerabilityListResponse(
        items=responses,
        count=len(responses),
        next_cursor=next_cursor,
        has_more=next_cursor is not None,
    )


@router.get("/{vuln_id}", response_model=VulnerabilityResponse)
@limiter.limit("120/minute")
async def get_vulnerability(
    request: Request,
    vuln_id: str,
    vuln_repo: VulnRepoDep,
    _user: Annotated[AuthUser, Depends(get_current_user)],
) -> VulnerabilityResponse:
    """Return full detail, enrichment sources, and remediation for one finding."""
    vuln = await vuln_repo.get(vuln_id)
    if vuln is None:
        raise NotFoundError(f"Vulnerability {vuln_id!r} not found")
    return VulnerabilityResponse.from_domain(vuln)


@router.patch("/{vuln_id}", response_model=VulnerabilityResponse)
@limiter.limit("120/minute")
async def update_vulnerability_status(
    request: Request,
    vuln_id: str,
    payload: FindingStatusUpdate,
    vuln_repo: VulnRepoDep,
    _user: Annotated[AuthUser, Depends(require_roles(Role.ANALYST))],
) -> VulnerabilityResponse:
    """Mark a finding resolved (or reopen it) so MTTR can be measured."""
    vuln = await vuln_repo.set_status(vuln_id, payload.status)
    if vuln is None:
        raise NotFoundError(f"Vulnerability {vuln_id!r} not found")
    return VulnerabilityResponse.from_domain(vuln)
