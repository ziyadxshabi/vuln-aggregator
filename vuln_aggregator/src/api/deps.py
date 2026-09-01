"""FastAPI dependency-injection providers."""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Annotated

from fastapi import Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession

from src.config import Settings, get_settings
from src.database.base import Database
from src.database.repository import ScanJobRepository, VulnerabilityRepository
from src.models.ports import TaskDispatcherPort
from src.services.posture_service import PostureService


def get_app_settings(request: Request) -> Settings:
    settings: Settings | None = getattr(request.app.state, "settings", None)
    return settings or get_settings()


def get_database(request: Request) -> Database:
    return request.app.state.db  # type: ignore[no-any-return]


async def get_session(request: Request) -> AsyncIterator[AsyncSession]:
    db = get_database(request)
    async with db.session() as session:
        yield session


def get_dispatcher(request: Request) -> TaskDispatcherPort:
    return request.app.state.dispatcher  # type: ignore[no-any-return]


def get_vuln_repo(
    request: Request,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> VulnerabilityRepository:
    return VulnerabilityRepository(session, get_database(request).dialect_name)


def get_job_repo(
    session: Annotated[AsyncSession, Depends(get_session)],
) -> ScanJobRepository:
    return ScanJobRepository(session)


def get_posture_service(
    vuln_repo: Annotated[VulnerabilityRepository, Depends(get_vuln_repo)],
) -> PostureService:
    return PostureService(vuln_repo)


SettingsDep = Annotated[Settings, Depends(get_app_settings)]
SessionDep = Annotated[AsyncSession, Depends(get_session)]
VulnRepoDep = Annotated[VulnerabilityRepository, Depends(get_vuln_repo)]
JobRepoDep = Annotated[ScanJobRepository, Depends(get_job_repo)]
DispatcherDep = Annotated[TaskDispatcherPort, Depends(get_dispatcher)]
PostureServiceDep = Annotated[PostureService, Depends(get_posture_service)]
