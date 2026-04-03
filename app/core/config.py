from __future__ import annotations

import json
import os
from enum import Enum
from functools import lru_cache
from typing import Literal

from pydantic import BaseModel, Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class AppEnv(str, Enum):
    LOCAL = "local"
    DEV = "dev"
    TEST = "test"
    PROD = "prod"


class LogLevel(str, Enum):
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # App (Populate the Python field app_env from the external input key APP_ENV,
    # and so on for the other fields)
    app_env: AppEnv = Field(default=AppEnv.LOCAL, validation_alias="APP_ENV")
    app_name: str = Field(default="fastapi-auth", validation_alias="APP_NAME")
    app_log_level: LogLevel = Field(default=LogLevel.INFO, validation_alias="APP_LOG_LEVEL")

    # HTTP
    app_host: str = Field(default="0.0.0.0", validation_alias="APP_HOST")
    app_port: int = Field(default=8000, validation_alias="APP_PORT")
    app_cors_origins: list[str] = Field(default_factory=list, validation_alias="APP_CORS_ORIGINS")
    app_trusted_hosts: list[str] = Field(default_factory=list, validation_alias="APP_TRUSTED_HOSTS")
    app_trust_proxy: bool = Field(default=False, validation_alias="APP_TRUST_PROXY")

    # DB
    database_url: str = Field(validation_alias="DATABASE_URL")

    # JWT
    jwt_alg: Literal["EdDSA", "RS256"] = Field(default="EdDSA", validation_alias="JWT_ALG")
    jwt_private_key: str | None = Field(default=None, validation_alias="JWT_PRIVATE_KEY")
    jwt_private_key_kid: str | None = Field(default=None, validation_alias="JWT_PRIVATE_KEY_KID")
    jwt_public_keys: str | None = Field(default=None, validation_alias="JWT_PUBLIC_KEYS")
    jwt_access_ttl_minutes: int = Field(default=15, validation_alias="JWT_ACCESS_TTL_MINUTES")
    jwt_refresh_ttl_days: int = Field(default=30, validation_alias="JWT_REFRESH_TTL_DAYS")
    refresh_token_pepper: str | None = Field(default=None, validation_alias="REFRESH_TOKEN_PEPPER")
    password_reset_token_ttl_minutes: int = Field(
        default=30,
        validation_alias="PASSWORD_RESET_TOKEN_TTL_MINUTES",
    )
    password_reset_token_pepper: str | None = Field(
        default=None,
        validation_alias="PASSWORD_RESET_TOKEN_PEPPER",
    )

    # Logging
    log_include_ip: bool = Field(default=False, validation_alias="LOG_INCLUDE_IP")
    log_include_user_agent: bool = Field(default=False, validation_alias="LOG_INCLUDE_USER_AGENT")
    log_include_email: bool = Field(default=False, validation_alias="LOG_INCLUDE_EMAIL")

    # Rate limiting
    rate_limit_enabled: bool = Field(default=False, validation_alias="RATE_LIMIT_ENABLED")
    rate_limit_provider: str | None = Field(default=None, validation_alias="RATE_LIMIT_PROVIDER")

    @field_validator("app_cors_origins", mode="before")
    @classmethod
    def _parse_cors(cls, value):
        return _parse_csv(value)

    @field_validator("app_trusted_hosts", mode="before")
    @classmethod
    def _parse_trusted_hosts(cls, value):
        return _parse_csv(value)

    def parsed_public_keys(self) -> dict[str, str]:
        if not self.jwt_public_keys:
            return {}
        try:
            value = json.loads(self.jwt_public_keys)
        except json.JSONDecodeError as exc:
            raise ValueError("JWT_PUBLIC_KEYS must be valid JSON") from exc
        if not isinstance(value, dict):
            raise ValueError("JWT_PUBLIC_KEYS must be a JSON object mapping kid to key")
        return {str(k): str(v) for k, v in value.items()}

    def validate_jwt_config(self) -> None:
        public_keys = self.parsed_public_keys()
        if self.app_env == AppEnv.TEST and not (self.jwt_private_key or public_keys):
            return

        if not public_keys:
            raise ValueError("JWT_PUBLIC_KEYS must include at least one public key")
        if not self.jwt_private_key:
            raise ValueError("JWT_PRIVATE_KEY is required for signing")
        if not self.jwt_private_key_kid:
            raise ValueError("JWT_PRIVATE_KEY_KID is required for signing")
        if self.jwt_private_key_kid not in public_keys:
            raise ValueError("JWT_PRIVATE_KEY_KID must exist in JWT_PUBLIC_KEYS")

        if not self.refresh_token_pepper:
            raise ValueError("REFRESH_TOKEN_PEPPER is required for refresh token hashing")
        if not self.password_reset_token_pepper:
            raise ValueError(
                "PASSWORD_RESET_TOKEN_PEPPER is required for password reset token hashing"
            )

        if self.jwt_alg == "EdDSA":
            _assert_pem(self.jwt_private_key, "PRIVATE KEY")
            for key in public_keys.values():
                _assert_pem(key, "PUBLIC KEY")
        elif self.jwt_alg == "RS256":
            _assert_pem(self.jwt_private_key, "PRIVATE KEY")
            for key in public_keys.values():
                _assert_pem(key, "PUBLIC KEY")


def _parse_csv(value) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [v for v in value if v]
    if isinstance(value, str):
        items = [v.strip() for v in value.split(",")]
        return [v for v in items if v]
    raise ValueError("Expected CSV string or list")


def _assert_pem(value: str, label: str) -> None:
    if f"BEGIN {label}" not in value:
        raise ValueError(f"Key material must include PEM {label} block")


# Use LRU cache to avoid reloading settings multiple times,
# since they are immutable after startup
@lru_cache
def get_settings() -> Settings:
    env = os.getenv("APP_ENV", "local")
    env_files = [".env", f".env.{env}"]
    settings = Settings(_env_file=env_files)
    settings.validate_jwt_config()
    return settings


class JwtKeySet(BaseModel):
    private_key: str
    private_kid: str
    public_keys: dict[str, str]

    @classmethod
    def from_settings(cls, settings: Settings) -> "JwtKeySet":
        if not settings.jwt_private_key or not settings.jwt_private_key_kid:
            raise ValueError("JWT_PRIVATE_KEY and JWT_PRIVATE_KEY_KID are required")
        return cls(
            private_key=settings.jwt_private_key,
            private_kid=settings.jwt_private_key_kid,
            public_keys=settings.parsed_public_keys(),
        )
