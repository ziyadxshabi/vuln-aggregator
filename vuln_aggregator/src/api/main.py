"""FastAPI application factory and process lifespan."""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI, Request, Response
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

from src.api.errors import install_error_handlers
from src.api.rate_limit import limiter
from src.api.routes import api_v1
from src.config import Settings, get_settings
from src.database.base import Database
from src.observability.logging import configure_logging, get_logger
from src.observability.tracing import setup_tracing
from src.workers.dispatcher import CeleryTaskDispatcher

_logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings: Settings = app.state.settings
    database = Database(settings.database_url)
    app.state.db = database
    app.state.dispatcher = CeleryTaskDispatcher()
    # Dev/first-run convenience; production schema is managed by Alembic.
    if settings.environment != "production":
        await database.create_all()
    _logger.info("startup_complete", environment=settings.environment)
    try:
        yield
    finally:
        await database.dispose()
        _logger.info("shutdown_complete")


def create_app(settings: Settings | None = None) -> FastAPI:
    resolved = settings or get_settings()
    configure_logging(json_logs=resolved.log_json)

    app = FastAPI(
        title="Enterprise Vulnerability Aggregation & Prioritization Platform",
        version="1.0.0",
        lifespan=lifespan,
    )
    app.state.settings = resolved
    app.state.limiter = limiter

    # Rate limiting: caps requests per client IP to reduce brute-force and abuse.
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    app.add_middleware(SlowAPIMiddleware)

    install_error_handlers(app)

    @app.middleware("http")
    async def _request_context(request: Request, call_next):  # type: ignore[no-untyped-def]
        request_id = request.headers.get("X-Request-ID", uuid.uuid4().hex)
        request.state.request_id = request_id
        structlog.contextvars.bind_contextvars(request_id=request_id, path=request.url.path)
        try:
            response: Response = await call_next(request)
        finally:
            structlog.contextvars.clear_contextvars()
        response.headers["X-Request-ID"] = request_id
        return response

    @app.get("/health", tags=["system"])
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    app.include_router(api_v1)
    setup_tracing(app, resolved)
    return app


app = create_app()
