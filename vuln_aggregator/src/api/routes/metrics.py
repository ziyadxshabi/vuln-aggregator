"""Aggregated security-posture metrics route."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends

from src.api.deps import PostureServiceDep
from src.api.schemas import PostureResponse
from src.api.security import AuthUser, get_current_user

router = APIRouter(prefix="/metrics", tags=["metrics"])


@router.get("/posture", response_model=PostureResponse)
async def posture(
    posture_service: PostureServiceDep,
    _user: Annotated[AuthUser, Depends(get_current_user)],
) -> PostureResponse:
    """Return Critical/High counts, exposure score, MTTR, and KEV exposure."""
    snapshot = await posture_service.snapshot()
    return PostureResponse.from_domain(snapshot)
