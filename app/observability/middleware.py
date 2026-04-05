from __future__ import annotations

import uuid

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from app.core.logging import bind_request_log_context, clear_request_log_context


class RequestContextMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
        request.state.request_id = request_id
        settings = request.app.state.settings
        bind_request_log_context(request, settings)
        try:
            response = await call_next(request)
        except Exception:
            clear_request_log_context()
            raise
        response.headers["X-Request-ID"] = request_id
        clear_request_log_context()
        return response
