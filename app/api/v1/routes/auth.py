from fastapi import APIRouter, Depends, HTTPException, Response, status

from app.api.deps import get_auth_service_dep
from app.core.errors import (
    DuplicateEmailError,
    InactiveUserError,
    InvalidCredentialsError,
    InvalidTokenError,
    PasswordResetTokenExpiredError,
    PasswordResetTokenInvalidError,
    PasswordResetTokenUsedError,
    RevokedTokenError,
    TokenExpiredError,
    TokenReplayError,
)
from app.schemas.auth import (
    ForgotPasswordRequest,
    ForgotPasswordResponse,
    LoginRequest,
    LogoutRequest,
    RefreshRequest,
    RegisterRequest,
    ResetPasswordRequest,
    ResetPasswordResponse,
    TokenPair,
)
from app.schemas.users import UserPublic
from app.services.auth_service import AuthService

router = APIRouter()


@router.post("/register", response_model=UserPublic, status_code=status.HTTP_201_CREATED)
def register(
    payload: RegisterRequest,
    auth: AuthService = Depends(get_auth_service_dep),
) -> UserPublic:
    try:
        return auth.register(email=payload.email, password=payload.password)
    except DuplicateEmailError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email already registered",
        ) from exc


@router.post("/login", response_model=TokenPair)
def login(payload: LoginRequest, auth: AuthService = Depends(get_auth_service_dep)) -> TokenPair:
    try:
        return auth.login(email=payload.email, password=payload.password)
    except (InvalidCredentialsError, InactiveUserError) as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc


@router.post("/refresh", response_model=TokenPair)
def refresh(
    payload: RefreshRequest,
    auth: AuthService = Depends(get_auth_service_dep),
) -> TokenPair:
    try:
        return auth.refresh(refresh_token=payload.refresh_token)
    except (
        InvalidTokenError,
        TokenExpiredError,
        RevokedTokenError,
        TokenReplayError,
    ) as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc
    except InactiveUserError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(payload: LogoutRequest, auth: AuthService = Depends(get_auth_service_dep)) -> Response:
    try:
        auth.logout(refresh_token=payload.refresh_token)
    except (InvalidTokenError, TokenExpiredError, RevokedTokenError, TokenReplayError):
        pass
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/forgot-password", response_model=ForgotPasswordResponse)
def forgot_password(
    payload: ForgotPasswordRequest,
    auth: AuthService = Depends(get_auth_service_dep),
) -> ForgotPasswordResponse:
    auth.request_password_reset(email=payload.email)
    return ForgotPasswordResponse(message="If the account exists, a reset email has been sent.")


@router.post("/reset-password", response_model=ResetPasswordResponse)
def reset_password(
    payload: ResetPasswordRequest,
    auth: AuthService = Depends(get_auth_service_dep),
) -> ResetPasswordResponse:
    try:
        auth.reset_password(reset_token=payload.reset_token, new_password=payload.new_password)
    except (
        PasswordResetTokenInvalidError,
        PasswordResetTokenExpiredError,
        PasswordResetTokenUsedError,
    ) as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired reset token",
        ) from exc
    return ResetPasswordResponse(message="Password has been reset.")
