from fastapi import APIRouter, Depends, Request, Response, status

from app.api.deps import get_auth_service_dep, get_rate_limiter_dep, get_settings_dep
from app.core.config import Settings
from app.core.errors import InactiveUserError, InvalidTokenError
from app.core.rate_limit import RateLimiter, RateLimitScope, get_client_ip
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


def _check_auth_rate_limit(
    *,
    request: Request,
    settings: Settings,
    limiter: RateLimiter,
    scope: RateLimitScope,
) -> None:
    client_ip = get_client_ip(request, trust_proxy=settings.app_trust_proxy)
    limiter.check(scope, client_ip)


def check_login_rate_limit_dep(
    request: Request,
    settings: Settings = Depends(get_settings_dep),
    limiter: RateLimiter = Depends(get_rate_limiter_dep),
) -> None:
    _check_auth_rate_limit(
        request=request,
        settings=settings,
        limiter=limiter,
        scope=RateLimitScope.LOGIN,
    )


def check_password_reset_rate_limit_dep(
    request: Request,
    settings: Settings = Depends(get_settings_dep),
    limiter: RateLimiter = Depends(get_rate_limiter_dep),
) -> None:
    _check_auth_rate_limit(
        request=request,
        settings=settings,
        limiter=limiter,
        scope=RateLimitScope.PASSWORD_RESET,
    )


@router.post("/register", response_model=UserPublic, status_code=status.HTTP_201_CREATED)
def register(
    payload: RegisterRequest,
    auth: AuthService = Depends(get_auth_service_dep),
) -> UserPublic:
    return auth.register(email=payload.email, password=payload.password)


@router.post(
    "/login",
    response_model=TokenPair,
    dependencies=[Depends(check_login_rate_limit_dep)],
)
def login(
    payload: LoginRequest,
    auth: AuthService = Depends(get_auth_service_dep),
) -> TokenPair:
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


@router.post(
    "/forgot-password",
    response_model=ForgotPasswordResponse,
    dependencies=[Depends(check_password_reset_rate_limit_dep)],
)
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
