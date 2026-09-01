"""Application configuration.

All settings are loaded from environment variables (or a local ``.env`` file)
using Pydantic v2 ``BaseSettings``. Access the singleton via :func:`get_settings`.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Annotated

from pydantic import Field, computed_field, field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

_DEFAULT_JWT_SECRET = "dev-only-secret-change-me-0123456789abcdef"


class Settings(BaseSettings):
    """Strongly typed runtime configuration."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # --- Environment -----------------------------------------------------
    environment: str = Field(default="development")
    service_name: str = Field(default="vuln-platform")
    log_json: bool = Field(default=True)

    # --- PostgreSQL ------------------------------------------------------
    postgres_user: str = Field(default="vuln")
    postgres_password: str = Field(default="vulnpass")
    postgres_db: str = Field(default="vulndb")
    postgres_host: str = Field(default="postgres")
    postgres_port: int = Field(default=5432)

    # --- Redis / Task queue ---------------------------------------------
    redis_url: str = Field(default="redis://redis:6379/0")
    celery_broker_url: str | None = Field(default=None)
    celery_result_backend: str | None = Field(default=None)

    # --- JWT / Auth ------------------------------------------------------
    jwt_secret: str = Field(default=_DEFAULT_JWT_SECRET)
    jwt_algorithm: str = Field(default="HS256")
    access_token_expire_minutes: int = Field(default=60)

    # Development seed users: "user:password:role" entries, comma separated.
    auth_users: str = Field(
        default="admin:admin123:ADMIN,analyst:analyst123:ANALYST,viewer:viewer123:READ_ONLY"
    )

    # --- Scanner credentials --------------------------------------------
    gvm_host: str = Field(default="gvm")
    gvm_port: int = Field(default=9390)
    gvm_username: str = Field(default="admin")
    gvm_password: str = Field(default="admin")
    gvm_use_tls: bool = Field(default=True)

    nessus_url: str = Field(default="https://nessus:8834")
    nessus_access_key: str = Field(default="")
    nessus_secret_key: str = Field(default="")
    nessus_verify_tls: bool = Field(default=False)

    trivy_binary: str = Field(default="trivy")

    # --- Threat intelligence feeds --------------------------------------
    cisa_kev_url: str = Field(
        default="https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    )
    epss_api_url: str = Field(default="https://api.first.org/data/v1/epss")
    nvd_api_url: str = Field(default="https://services.nvd.nist.gov/rest/json/cves/2.0")
    nvd_api_key: str | None = Field(default=None)
    vulners_api_key: str | None = Field(default=None)
    vulners_api_url: str = Field(default="https://vulners.com/api/v3/search/id/")

    enrichment_cache_ttl_seconds: int = Field(default=21_600)  # 6 hours
    kev_cache_ttl_seconds: int = Field(default=86_400)  # 24 hours

    # --- Scanning behaviour ---------------------------------------------
    scan_poll_interval_seconds: float = Field(default=10.0)
    scan_poll_timeout_seconds: float = Field(default=7_200.0)
    scan_schedule_hours: int = Field(default=6)
    scan_targets: Annotated[list[str], NoDecode] = Field(default_factory=list)

    # --- HTTP resilience -------------------------------------------------
    http_timeout_seconds: float = Field(default=30.0)
    http_max_retries: int = Field(default=4)

    @field_validator("scan_targets", mode="before")
    @classmethod
    def _split_targets(cls, value: object) -> object:
        """Allow ``SCAN_TARGETS`` to be a comma-separated string."""
        if isinstance(value, str):
            return [item.strip() for item in value.split(",") if item.strip()]
        return value

    @model_validator(mode="after")
    def _validate_jwt_secret(self) -> Settings:
        if len(self.jwt_secret) < 32:
            raise ValueError("JWT_SECRET must be at least 32 characters")
        if self.environment == "production" and self.jwt_secret == _DEFAULT_JWT_SECRET:
            raise ValueError("JWT_SECRET must be changed from the default value in production")
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def database_url(self) -> str:
        """Async SQLAlchemy DSN (asyncpg driver)."""
        return (
            f"postgresql+asyncpg://{self.postgres_user}:{self.postgres_password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def sync_database_url(self) -> str:
        """Synchronous DSN (psycopg) used by Alembic migrations."""
        return (
            f"postgresql+psycopg://{self.postgres_user}:{self.postgres_password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )

    @property
    def broker_url(self) -> str:
        return self.celery_broker_url or self.redis_url

    @property
    def result_backend(self) -> str:
        return self.celery_result_backend or self.redis_url


@lru_cache
def get_settings() -> Settings:
    """Return a cached :class:`Settings` instance."""
    return Settings()
