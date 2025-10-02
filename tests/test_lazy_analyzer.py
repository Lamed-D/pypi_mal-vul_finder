import sys
from pathlib import Path

SERVER_ROOT = Path(__file__).resolve().parents[1] / "server"
if str(SERVER_ROOT) not in sys.path:
    sys.path.insert(0, str(SERVER_ROOT))

from app.services.analysis.engines import LazyAnalyzer


def test_lazy_analyzer_initialises_once():
    calls = []

    def factory():
        calls.append("factory")
        return object()

    analyzer = LazyAnalyzer(factory)
    instance1 = analyzer.get()
    instance2 = analyzer.get()

    assert instance1 is instance2
    assert calls == ["factory"]


def test_lazy_analyzer_shutdown(monkeypatch):
    class Dummy:
        def __init__(self):
            self.shutdown_called = False

        def shutdown_executor(self):
            self.shutdown_called = True

    dummy = Dummy()

    def factory():
        return dummy

    analyzer = LazyAnalyzer(factory)
    analyzer.get()
    analyzer.shutdown()

    assert dummy.shutdown_called
    assert analyzer.is_initialised is False
