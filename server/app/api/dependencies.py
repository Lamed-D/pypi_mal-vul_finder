"""FastAPI dependency helpers for accessing shared services."""

from fastapi import Depends, Request

from app.core.container import AppContainer


def get_container(request: Request) -> AppContainer:
    container = getattr(request.app.state, "container", None)
    if container is None:  # pragma: no cover - 런타임 방어 코드
        raise RuntimeError("Application container not initialised")
    return container


def get_file_service(container: AppContainer = Depends(get_container)):
    return container.file_service


def get_event_manager(container: AppContainer = Depends(get_container)):
    return container.event_manager


def get_analysis_orchestrator(container: AppContainer = Depends(get_container)):
    return container.analysis_orchestrator


def get_lstm_analyzer(container: AppContainer = Depends(get_container)):
    return container.engines.lstm.get()


def get_bert_analyzer(container: AppContainer = Depends(get_container)):
    return container.engines.bert.get()


def get_ml_analyzer(container: AppContainer = Depends(get_container)):
    return container.engines.ml.get()


def get_session_service(container: AppContainer = Depends(get_container)):
    return container.session_service


def get_templates(container: AppContainer = Depends(get_container)):
    return container.templates
