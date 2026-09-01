"""Authentication routes (JWT issuance)."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Request
from fastapi.security import OAuth2PasswordRequestForm

from src.api.deps import SettingsDep
from src.api.errors import AuthError
from src.api.rate_limit import limiter
from src.api.schemas import TokenResponse
from src.api.security import UserStore, create_access_token, get_user_store

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/token", response_model=TokenResponse)
@limiter.limit("20/minute")
async def issue_token(
    request: Request,
    form: Annotated[OAuth2PasswordRequestForm, Depends()],
    settings: SettingsDep,
    store: Annotated[UserStore, Depends(get_user_store)],
) -> TokenResponse:
    """Exchange username/password credentials for a bearer token."""
    user = store.authenticate(form.username, form.password)
    if user is None:
        raise AuthError("Incorrect username or password")
    token, expires_in = create_access_token(user, settings)
    return TokenResponse(access_token=token, expires_in=expires_in)
