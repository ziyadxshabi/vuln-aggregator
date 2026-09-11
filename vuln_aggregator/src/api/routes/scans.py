"""Scan control-plane routes."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Request, status

from src.api.deps import DispatcherDep, JobRepoDep, SettingsDep
from src.api.errors import BadRequestError, NotFoundError
from src.api.rate_limit import limiter
from src.api.schemas import ScanJobResponse, ScanRequest
from src.api.security import AuthUser, get_current_user, require_roles
from src.connectors import DEFAULT_IMAGE_SCANNERS, DEFAULT_NETWORK_SCANNERS
from src.engine.profiles import get_profile
from src.engine.scope import ScopeError, prepare_scan
from src.models.enums import Role

router = APIRouter(prefix="/scans", tags=["scans"])


def _default_scanners(network_targets: list[str], image_targets: list[str]) -> list[str]:
    names: list[str] = []
    if network_targets:
        names.extend(DEFAULT_NETWORK_SCANNERS)
    if image_targets:
        names.extend(DEFAULT_IMAGE_SCANNERS)
    return names


@router.post("", response_model=ScanJobResponse, status_code=status.HTTP_202_ACCEPTED)
@limiter.limit("120/minute")
async def launch_scan(
    request: Request,
    payload: ScanRequest,
    job_repo: JobRepoDep,
    dispatcher: DispatcherDep,
    settings: SettingsDep,
    user: Annotated[AuthUser, Depends(require_roles(Role.ANALYST))],
) -> ScanJobResponse:
    """Launch an asynchronous detection-only scan of authorized targets."""
    if payload.authorized is not True:
        raise BadRequestError(
            "Scanning requires authorized=true (systems you own or have written permission to test)"
        )
    try:
        prepared = prepare_scan(payload.targets, get_profile(payload.profile), settings.scan_allowlist)
    except ScopeError as exc:
        raise BadRequestError(str(exc)) from exc

    scanners = payload.scanners or _default_scanners(prepared.network_targets, prepared.image_targets)
    if not scanners:
        raise BadRequestError("No scanners selected for the given targets")

    job = await job_repo.create(
        payload.targets,
        scanners,
        requested_by=user.username,
        profile=payload.profile.value,
    )
    task_id = dispatcher.dispatch_scan(
        job.id,
        payload.targets,
        scanners,
        profile=payload.profile.value,
        requested_by=user.username,
    )
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
