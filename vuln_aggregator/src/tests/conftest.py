"""Shared pytest fixtures."""

from __future__ import annotations

import json
from collections.abc import AsyncIterator, Awaitable, Callable
from pathlib import Path
from typing import Any

import httpx
import pytest
import pytest_asyncio
from httpx import ASGITransport

from src.api.main import create_app
from src.config import get_settings
from src.database.base import Database
from src.database.repository import VulnerabilityRepository
from src.models.vulnerability import NormalizedVulnerability

FIXTURES = Path(__file__).parent / "fixtures"


def load_fixture(name: str) -> Any:
    text = (FIXTURES / name).read_text(encoding="utf-8")
    return json.loads(text) if name.endswith(".json") else text


class FakeDispatcher:
    """In-memory task dispatcher used instead of Celery in tests."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, list[str], list[str], str, str | None]] = []

    def dispatch_scan(
        self,
        job_id: str,
        targets: list[str],
        scanners: list[str],
        profile: str = "home",
        requested_by: str | None = None,
    ) -> str:
        self.calls.append((job_id, targets, scanners, profile, requested_by))
        return f"task-{job_id}"


@pytest_asyncio.fixture
async def database(tmp_path: Path) -> AsyncIterator[Database]:
    db = Database(f"sqlite+aiosqlite:///{tmp_path / 'test.db'}")
    await db.create_all()
    try:
        yield db
    finally:
        await db.dispose()


@pytest_asyncio.fixture
async def test_app(database: Database) -> AsyncIterator[Any]:
    app = create_app(get_settings())
    app.state.db = database
    app.state.dispatcher = FakeDispatcher()
    yield app


@pytest_asyncio.fixture
async def client(test_app: Any) -> AsyncIterator[httpx.AsyncClient]:
    transport = ASGITransport(app=test_app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as async_client:
        yield async_client


@pytest.fixture
def dispatcher(test_app: Any) -> FakeDispatcher:
    return test_app.state.dispatcher  # type: ignore[no-any-return]


@pytest_asyncio.fixture
async def seed(
    database: Database,
) -> Callable[[list[NormalizedVulnerability]], Awaitable[int]]:
    async def _seed(vulns: list[NormalizedVulnerability]) -> int:
        async with database.session() as session:
            repo = VulnerabilityRepository(session, database.dialect_name)
            return await repo.bulk_upsert(vulns)

    return _seed


async def auth_token(client: httpx.AsyncClient, username: str, password: str) -> str:
    resp = await client.post(
        "/api/v1/auth/token", data={"username": username, "password": password}
    )
    resp.raise_for_status()
    return str(resp.json()["access_token"])
