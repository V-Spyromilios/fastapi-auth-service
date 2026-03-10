from fastapi import APIRouter, Depends, HTTPException, Response, status

from app.api.deps import get_auth_service_dep
from app.core.errors import (
    DuplicateEmailError,
    InactiveUserError,
    InvalidCredentialsError,
    InvalidTokenError,
    RevokedTokenError,
    TokenExpiredError,
    TokenReplayError,
)
from app.schemas.auth import (
    LoginRequest,
    LogoutRequest,
    RefreshRequest,
    RegisterRequest,
    TokenPair,
)
from app.schemas.users import UserPublic
from app.services.auth_service import AuthService

router = APIRouter()


@router.post("/register", response_model=UserPublic, status_code=status.HTTP_201_CREATED)
def register(payload: RegisterRequest, auth: AuthService = Depends(get_auth_service_dep)) -> UserPublic:
    try:
        return auth.register(email=payload.email, password=payload.password)
    except DuplicateEmailError:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email already registered")


@router.post("/login", response_model=TokenPair)
def login(payload: LoginRequest, auth: AuthService = Depends(get_auth_service_dep)) -> TokenPair:
    try:
        return auth.login(email=payload.email, password=payload.password)
    except (InvalidCredentialsError, InactiveUserError):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )


@router.post("/refresh", response_model=TokenPair)
def refresh(payload: RefreshRequest, auth: AuthService = Depends(get_auth_service_dep)) -> TokenPair:
    try:
        return auth.refresh(refresh_token=payload.refresh_token)
    except (InvalidTokenError, TokenExpiredError, RevokedTokenError, TokenReplayError):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except InactiveUserError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(payload: LogoutRequest, auth: AuthService = Depends(get_auth_service_dep)) -> Response:
    try:
        auth.logout(refresh_token=payload.refresh_token)
    except (InvalidTokenError, TokenExpiredError, RevokedTokenError, TokenReplayError):
        pass
    return Response(status_code=status.HTTP_204_NO_CONTENT)
