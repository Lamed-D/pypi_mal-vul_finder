"""FastAPI 애플리케이션 팩토리."""

from fastapi import FastAPI

from app.core.container import AppContainer
from app.core.config import settings
from app.api.routers import register_routers


def create_app() -> FastAPI:
    container = AppContainer(models_dir=str(settings.model_dir))
    app = FastAPI(**container.metadata)
    app.state.container = container

    register_routers(app)

    @app.on_event("shutdown")
    async def shutdown_event() -> None:  # pragma: no cover
        container.engines.lstm.shutdown()
        container.engines.bert.shutdown()
        container.engines.ml.shutdown()

    return app
