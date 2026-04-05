from contextlib import asynccontextmanager

from fastapi import FastAPI, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.middleware.trustedhost import TrustedHostMiddleware

from app.api.exception_handlers import add_exception_handlers
from app.api.v1.routes import auth, users
from app.core.config import get_settings
from app.core.logging import configure_logging
from app.core.rate_limit import build_rate_limiter
from app.db.session import Database
from app.observability.middleware import RequestContextMiddleware


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    configure_logging(settings)
    app.state.settings = settings
    app.state.db = Database(settings)
    app.state.rate_limiter = build_rate_limiter(settings)
    yield


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(title=settings.app_name, lifespan=lifespan)
    add_exception_handlers(app)

    app.add_middleware(RequestContextMiddleware)

    # CORS checks whether a browser frontend origin is allowed to make
    # cross-origin requests to our API. It does not affect non-browser clients.
    if settings.app_cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=settings.app_cors_origins,
            allow_credentials=True,
            allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
            allow_headers=["Authorization", "Content-Type"],
        )

    if settings.app_trusted_hosts:
        #checks whether the request’s host header
        app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.app_trusted_hosts)

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "service": "alive"}

    @app.get("/ready")
    def ready() -> JSONResponse:
        db: Database = app.state.db
        if db.is_ready():
            return JSONResponse(
                status_code=status.HTTP_200_OK,
                content={"status": "ok", "database": "ok"},
            )
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={"status": "error", "database": "unavailable"},
        )

    app.include_router(auth.router, prefix="/api/v1/auth", tags=["auth"])
    app.include_router(users.router, prefix="/api/v1/users", tags=["users"])

    return app
    # uvicorn app.main:app starts here


app = create_app()
