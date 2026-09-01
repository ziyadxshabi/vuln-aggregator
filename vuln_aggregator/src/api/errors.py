"""Standard error-response envelopes and exception handlers."""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI, Request, status
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException
from pydantic import BaseModel

from src.observability.logging import get_logger

_logger = get_logger(__name__)


class ErrorBody(BaseModel):
    type: str
    message: str
    request_id: str | None = None
    details: list[dict[str, Any]] | None = None


class ErrorEnvelope(BaseModel):
    error: ErrorBody


class AppError(Exception):
    """Base class for application errors mapped to HTTP responses."""

    status_code: int = status.HTTP_500_INTERNAL_SERVER_ERROR
    error_type: str = "internal_error"

    def __init__(self, message: str, details: list[dict[str, Any]] | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.details = details


class NotFoundError(AppError):
    status_code = status.HTTP_404_NOT_FOUND
    error_type = "not_found"


class AuthError(AppError):
    status_code = status.HTTP_401_UNAUTHORIZED
    error_type = "authentication_error"


class ForbiddenError(AppError):
    status_code = status.HTTP_403_FORBIDDEN
    error_type = "permission_denied"


class ValidationAppError(AppError):
    status_code = status.HTTP_422_UNPROCESSABLE_CONTENT
    error_type = "validation_error"


def install_error_handlers(app: FastAPI) -> None:
    """Register handlers that render every error as an :class:`ErrorEnvelope`."""

    def _request_id(request: Request) -> str | None:
        return getattr(request.state, "request_id", None)

    @app.exception_handler(AppError)
    async def _app_error(request: Request, exc: AppError) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content=jsonable_encoder(
                ErrorEnvelope(
                    error=ErrorBody(
                        type=exc.error_type,
                        message=exc.message,
                        request_id=_request_id(request),
                        details=exc.details,
                    )
                )
            ),
        )

    @app.exception_handler(RequestValidationError)
    async def _validation_error(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            content=jsonable_encoder(
                ErrorEnvelope(
                    error=ErrorBody(
                        type="validation_error",
                        message="Request validation failed",
                        request_id=_request_id(request),
                        details=[dict(err) for err in exc.errors()],
                    )
                )
            ),
        )

    @app.exception_handler(StarletteHTTPException)
    async def _http_error(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content=jsonable_encoder(
                ErrorEnvelope(
                    error=ErrorBody(
                        type="http_error",
                        message=str(exc.detail),
                        request_id=_request_id(request),
                    )
                )
            ),
        )

    @app.exception_handler(Exception)
    async def _unhandled(request: Request, exc: Exception) -> JSONResponse:
        _logger.exception("unhandled_error", path=str(request.url))
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content=jsonable_encoder(
                ErrorEnvelope(
                    error=ErrorBody(
                        type="internal_error",
                        message="An unexpected error occurred",
                        request_id=_request_id(request),
                    )
                )
            ),
        )
