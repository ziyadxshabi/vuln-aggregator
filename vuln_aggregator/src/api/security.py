"""JWT authentication and role-based access control."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from functools import lru_cache
from typing import Annotated

import jwt
from fastapi import Depends
from fastapi.security import OAuth2PasswordBearer
from passlib.context import CryptContext
from pydantic import BaseModel

from src.api.errors import AuthError, ForbiddenError
from src.config import Settings, get_settings
from src.models.enums import Role

TOKEN_URL = "/api/v1/auth/token"

_pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")
_oauth2_scheme = OAuth2PasswordBearer(tokenUrl=TOKEN_URL, auto_error=False)


class AuthUser(BaseModel):
    """Authenticated principal extracted from a validated JWT."""

    username: str
    role: Role


class _StoredUser(BaseModel):
    username: str
    password_hash: str
    role: Role


class UserStore:
    """In-memory user registry seeded from ``AUTH_USERS`` configuration."""

    def __init__(self, settings: Settings) -> None:
        self._users: dict[str, _StoredUser] = {}
        for entry in settings.auth_users.split(","):
            entry = entry.strip()
            if not entry:
                continue
            username, _, rest = entry.partition(":")
            password, _, role_name = rest.partition(":")
            if not username or not password or not role_name:
                continue
            self._users[username] = _StoredUser(
                username=username,
                password_hash=_pwd_context.hash(password),
                role=Role(role_name.strip().upper()),
            )

    def authenticate(self, username: str, password: str) -> AuthUser | None:
        stored = self._users.get(username)
        if stored is None or not _pwd_context.verify(password, stored.password_hash):
            return None
        return AuthUser(username=stored.username, role=stored.role)


@lru_cache
def get_user_store() -> UserStore:
    return UserStore(get_settings())


def create_access_token(user: AuthUser, settings: Settings) -> tuple[str, int]:
    """Return ``(jwt, expires_in_seconds)`` for an authenticated user."""
    expires_in = settings.access_token_expire_minutes * 60
    payload = {
        "sub": user.username,
        "role": user.role.value,
        "exp": datetime.now(UTC) + timedelta(seconds=expires_in),
        "iat": datetime.now(UTC),
    }
    token = jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)
    return token, expires_in


def decode_token(token: str, settings: Settings) -> AuthUser:
    try:
        payload = jwt.decode(token, settings.jwt_secret, algorithms=[settings.jwt_algorithm])
    except jwt.PyJWTError as exc:
        raise AuthError("Invalid or expired token") from exc
    username = payload.get("sub")
    role = payload.get("role")
    if not username or not role:
        raise AuthError("Malformed token payload")
    return AuthUser(username=str(username), role=Role(str(role)))


async def get_current_user(
    token: Annotated[str | None, Depends(_oauth2_scheme)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> AuthUser:
    if not token:
        raise AuthError("Authentication required")
    return decode_token(token, settings)


def require_roles(*roles: Role):  # type: ignore[no-untyped-def]
    """Dependency factory enforcing RBAC (ADMIN is always permitted)."""

    async def _dependency(
        user: Annotated[AuthUser, Depends(get_current_user)],
    ) -> AuthUser:
        if user.role is Role.ADMIN:
            return user
        if roles and user.role not in roles:
            raise ForbiddenError(
                f"Role {user.role.value} is not permitted to perform this action"
            )
        return user

    return _dependency
