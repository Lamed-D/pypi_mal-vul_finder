"""FastAPI 애플리케이션 팩토리."""

from fastapi import FastAPI

from app.core.container import AppContainer
from app.api.routers import register_routers


def create_app() -> FastAPI:
    container = AppContainer()
    app = FastAPI(**container.metadata)
    app.state.container = container

    register_routers(app)

    @app.on_event("shutdown")
    async def shutdown_event() -> None:  # pragma: no cover
        container.engines.lstm.shutdown_executor()
        container.engines.bert.shutdown_executor()

    return app
