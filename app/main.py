from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware

from app.api.v1.routes import auth, users
from app.core.config import get_settings
from app.core.logging import configure_logging
from app.db.session import Database
from app.observability.middleware import RequestContextMiddleware


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    configure_logging(settings)
    app.state.settings = settings
    app.state.db = Database(settings)
    yield


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(title=settings.app_name, lifespan=lifespan)

    app.add_middleware(RequestContextMiddleware)

    if settings.app_cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=settings.app_cors_origins,
            allow_credentials=True,
            allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
            allow_headers=["Authorization", "Content-Type"],
        )

    if settings.app_trusted_hosts:
        app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.app_trusted_hosts)

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    app.include_router(auth.router, prefix="/api/v1/auth", tags=["auth"])
    app.include_router(users.router, prefix="/api/v1/users", tags=["users"])

    return app


app = create_app()
