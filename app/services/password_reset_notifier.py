from __future__ import annotations


class PasswordResetNotifier:
    def send_password_reset(self, *, email: str, reset_token: str) -> None:
        raise NotImplementedError


class NoopPasswordResetNotifier(PasswordResetNotifier):
    def send_password_reset(self, *, email: str, reset_token: str) -> None:
        return None
