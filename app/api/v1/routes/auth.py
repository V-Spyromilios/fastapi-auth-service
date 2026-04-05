from fastapi import APIRouter, Depends, Response, status

from app.api.deps import get_auth_service_dep
from app.core.errors import InactiveUserError, InvalidTokenError
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
    return auth.register(email=payload.email, password=payload.password)


@router.post("/login", response_model=TokenPair)
def login(payload: LoginRequest, auth: AuthService = Depends(get_auth_service_dep)) -> TokenPair:
    return auth.login(email=payload.email, password=payload.password)


@router.post("/refresh", response_model=TokenPair)
def refresh(
    payload: RefreshRequest,
    auth: AuthService = Depends(get_auth_service_dep),
) -> TokenPair:
    try:
        return auth.refresh(refresh_token=payload.refresh_token)
    except InactiveUserError as exc:
        raise InvalidTokenError() from exc


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(payload: LogoutRequest, auth: AuthService = Depends(get_auth_service_dep)) -> Response:
    auth.logout(refresh_token=payload.refresh_token)
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
    auth.reset_password(reset_token=payload.reset_token, new_password=payload.new_password)
    return ResetPasswordResponse(message="Password has been reset.")
