import sys
from pathlib import Path

def _ensure_server_on_path() -> None:
    server_dir = Path(__file__).resolve().parents[1] / "server"
    if str(server_dir) not in sys.path:
        sys.path.insert(0, str(server_dir))


def test_create_app_initialises_container():
    _ensure_server_on_path()
    from app import create_app

    app = create_app()
    assert hasattr(app.state, "container")

    container = app.state.container
    assert container.file_service is not None
    assert container.session_service is not None
    assert container.analysis_orchestrator is not None

    # Lazy analyzers should not be initialised until accessed.
    assert not container.engines.lstm.is_initialised
    assert not container.engines.bert.is_initialised
    assert not container.engines.ml.is_initialised

    # Cleanup explicitly to avoid lingering resources during tests.
    container.engines.lstm.shutdown()
    container.engines.bert.shutdown()
    container.engines.ml.shutdown()
