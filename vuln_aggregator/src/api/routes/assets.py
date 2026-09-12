"""Host inventory routes."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request

from src.api.deps import AssetRepoDep
from src.api.rate_limit import limiter
from src.api.schemas import AssetListResponse, AssetResponse
from src.api.security import AuthUser, get_current_user
from src.connectors.nmap import RISKY_PORT_NUMBERS

router = APIRouter(prefix="/assets", tags=["assets"])


@router.get("", response_model=AssetListResponse)
@limiter.limit("120/minute")
async def list_assets(
    request: Request,
    asset_repo: AssetRepoDep,
    _user: Annotated[AuthUser, Depends(get_current_user)],
    limit: Annotated[int, Query(ge=1, le=2000)] = 500,
) -> AssetListResponse:
    """List discovered hosts and open ports from the latest network scans."""
    items = await asset_repo.list(limit=limit)
    risky = 0
    for asset in items:
        if any(port.port in RISKY_PORT_NUMBERS for port in asset.ports):
            risky += 1
    return AssetListResponse(
        items=[AssetResponse.from_domain(item) for item in items],
        count=len(items),
        risky_service_count=risky,
    )
