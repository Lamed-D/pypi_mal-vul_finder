"""라우터 등록 헬퍼."""

from fastapi import FastAPI

from app.api.routers import dashboard, upload, sessions, events, files


def register_routers(app: FastAPI) -> None:
    app.include_router(dashboard.router)
    app.include_router(upload.router)
    app.include_router(upload.api_router)
    app.include_router(events.router)
    app.include_router(sessions.router)
    app.include_router(sessions.api_router)
    app.include_router(files.router)
