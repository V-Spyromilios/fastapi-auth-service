from __future__ import annotations


class AppError(Exception):
    """Base application error."""


class InvalidCredentialsError(AppError):
    """Generic error for invalid login credentials."""


class InactiveUserError(AppError):
    """User is disabled or not allowed to authenticate."""


class UserNotFoundError(AppError):
    """User not found for an authenticated context."""


class UnauthorizedError(AppError):
    """Authenticated context failed with a safe generic response."""


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


class PasswordResetTokenInvalidError(AppError):
    """Password reset token is malformed or unknown."""


class PasswordResetTokenExpiredError(AppError):
    """Password reset token is expired."""


class PasswordResetTokenUsedError(AppError):
    """Password reset token has already been consumed or revoked."""
