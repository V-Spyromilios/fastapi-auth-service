from __future__ import annotations


class AppError(Exception):
    """Base application error."""


class InvalidCredentialsError(AppError):
    """Generic error for invalid login credentials."""


class InactiveUserError(AppError):
    """User is disabled or not allowed to authenticate."""


class UserNotFoundError(AppError):
    """User not found for an authenticated context."""


class DuplicateEmailError(AppError):
    """Email already exists."""


class InvalidTokenError(AppError):
    """Token is malformed or not recognized."""


class TokenExpiredError(AppError):
    """Token is expired."""


class RevokedTokenError(AppError):
    """Token has been revoked."""


class TokenReplayError(AppError):
    """Token reuse detected."""
