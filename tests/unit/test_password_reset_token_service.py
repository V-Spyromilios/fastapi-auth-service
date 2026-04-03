from __future__ import annotations

from app.services.password_reset_token_service import OpaquePasswordResetTokenService


def test_generate_token_returns_opaque_random_values(settings) -> None:
    service = OpaquePasswordResetTokenService(settings)

    first = service.generate_token()
    second = service.generate_token()

    assert isinstance(first, str)
    assert isinstance(second, str)
    assert first
    assert second
    assert first != second


def test_hash_token_is_deterministic_and_does_not_match_raw_value(settings) -> None:
    service = OpaquePasswordResetTokenService(settings)

    raw_token = "reset-token-value"
    first_hash = service.hash_token(raw_token)
    second_hash = service.hash_token(raw_token)

    assert first_hash == second_hash
    assert first_hash != raw_token
