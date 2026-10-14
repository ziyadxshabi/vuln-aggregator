"""API v1 routers."""

from fastapi import APIRouter

from src.api.routes.assets import router as assets_router
from src.api.routes.auth import router as auth_router
from src.api.routes.metrics import router as metrics_router
from src.api.routes.scans import router as scans_router
from src.api.routes.vulnerabilities import router as vulnerabilities_router

api_v1 = APIRouter(prefix="/api/v1")
api_v1.include_router(auth_router)
api_v1.include_router(scans_router)
api_v1.include_router(vulnerabilities_router)
api_v1.include_router(assets_router)
api_v1.include_router(metrics_router)

__all__ = ["api_v1"]
