from __future__ import annotations

from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse

from app.core.errors import (
    DuplicateEmailError,
    InactiveUserError,
    InvalidCredentialsError,
    InvalidTokenError,
    PasswordResetTokenExpiredError,
    PasswordResetTokenInvalidError,
    PasswordResetTokenUsedError,
    RateLimitExceededError,
    RevokedTokenError,
    TokenExpiredError,
    TokenReplayError,
    UnauthorizedError,
    UserNotFoundError,
)
from app.core.logging import log_security_event

_BEARER_HEADERS = {"WWW-Authenticate": "Bearer"}


def _error_response(
    *,
    status_code: int,
    detail: str,
    headers: dict[str, str] | None = None,
) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content={"detail": detail},
        headers=headers,
    )


def add_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(RateLimitExceededError)
    async def handle_rate_limit_exceeded(
        request: Request,
        exc: RateLimitExceededError,
    ) -> JSONResponse:
        settings = request.app.state.settings
        log_security_event(
            settings,
            "auth.rate_limit.exceeded",
            level="warning",
            outcome="blocked",
            reason=_rate_limit_reason_for_path(request.url.path),
            path=request.url.path,
            method=request.method,
            retry_after_seconds=exc.retry_after_seconds,
        )
        return _error_response(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=str(exc),
            headers={"Retry-After": str(exc.retry_after_seconds)},
        )

    @app.exception_handler(DuplicateEmailError)
    async def handle_duplicate_email(
        request: Request,
        exc: DuplicateEmailError,
    ) -> JSONResponse:
        del request, exc
        return _error_response(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email already registered",
        )

    @app.exception_handler(InvalidCredentialsError)
    @app.exception_handler(InactiveUserError)
    async def handle_invalid_credentials(
        request: Request,
        exc: InvalidCredentialsError | InactiveUserError,
    ) -> JSONResponse:
        del request, exc
        return _error_response(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers=_BEARER_HEADERS,
        )

    @app.exception_handler(InvalidTokenError)
    @app.exception_handler(TokenExpiredError)
    @app.exception_handler(TokenReplayError)
    @app.exception_handler(RevokedTokenError)
    async def handle_invalid_token(
        request: Request,
        exc: InvalidTokenError | TokenExpiredError | TokenReplayError | RevokedTokenError,
    ) -> JSONResponse:
        del request, exc
        return _error_response(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers=_BEARER_HEADERS,
        )

    @app.exception_handler(UnauthorizedError)
    @app.exception_handler(UserNotFoundError)
    async def handle_unauthorized(
        request: Request,
        exc: UnauthorizedError | UserNotFoundError,
    ) -> JSONResponse:
        del request, exc
        return _error_response(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized",
            headers=_BEARER_HEADERS,
        )

    @app.exception_handler(PasswordResetTokenInvalidError)
    @app.exception_handler(PasswordResetTokenExpiredError)
    @app.exception_handler(PasswordResetTokenUsedError)
    async def handle_invalid_reset_token(
        request: Request,
        exc: (
            PasswordResetTokenInvalidError
            | PasswordResetTokenExpiredError
            | PasswordResetTokenUsedError
        ),
    ) -> JSONResponse:
        del request, exc
        return _error_response(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired reset token",
        )


def _rate_limit_reason_for_path(path: str) -> str:
    if path.endswith("/login"):
        return "login"
    if path.endswith("/forgot-password"):
        return "forgot_password"
    return "request"
