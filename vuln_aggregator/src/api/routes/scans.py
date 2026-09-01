"""Scan control-plane routes."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Request, status

from src.api.deps import DispatcherDep, JobRepoDep
from src.api.errors import NotFoundError
from src.api.rate_limit import limiter
from src.api.schemas import ScanJobResponse, ScanRequest
from src.api.security import AuthUser, get_current_user, require_roles
from src.models.enums import Role

router = APIRouter(prefix="/scans", tags=["scans"])


@router.post("", response_model=ScanJobResponse, status_code=status.HTTP_202_ACCEPTED)
@limiter.limit("120/minute")
async def launch_scan(
    request: Request,
    payload: ScanRequest,
    job_repo: JobRepoDep,
    dispatcher: DispatcherDep,
    _user: Annotated[AuthUser, Depends(require_roles(Role.ANALYST))],
) -> ScanJobResponse:
    """Launch an asynchronous aggregation scan across targets and scanners."""
    job = await job_repo.create(payload.targets, payload.scanners)
    task_id = dispatcher.dispatch_scan(job.id, payload.targets, payload.scanners)
    return ScanJobResponse.from_domain(job, task_id=task_id)


@router.get("/{task_id}", response_model=ScanJobResponse)
@limiter.limit("120/minute")
async def get_scan(
    request: Request,
    task_id: str,
    job_repo: JobRepoDep,
    _user: Annotated[AuthUser, Depends(get_current_user)],
) -> ScanJobResponse:
    """Return the status and progress of a scan job."""
    job = await job_repo.get(task_id)
    if job is None:
        raise NotFoundError(f"Scan job {task_id!r} not found")
    return ScanJobResponse.from_domain(job)
