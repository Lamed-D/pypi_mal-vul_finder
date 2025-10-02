import importlib.util
from pathlib import Path


SERVER_ROOT = Path(__file__).resolve().parents[1] / "server"


def load_settings_class(root: Path) -> type:
    config_path = root / "app" / "core" / "config.py"
    spec = importlib.util.spec_from_file_location("app.core.config", config_path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)  # type: ignore[assignment]
    return module.Settings  # type: ignore[attr-defined]


def test_settings_default_values(tmp_path, monkeypatch):
    for key in [
        "HOST",
        "PORT",
        "LOG_LEVEL",
        "MAX_FILE_SIZE",
        "ALLOWED_EXTENSIONS",
    ]:
        monkeypatch.delenv(key, raising=False)

    Settings = load_settings_class(SERVER_ROOT)
    settings = Settings(base_dir=tmp_path, preload_env=False)
    assert settings.host == "127.0.0.1"
    assert settings.port == 8000
    assert ".zip" in settings.allowed_extension_set
    assert settings.upload_dir.exists()
    assert settings.model_dir.exists()


def test_settings_env_file_override(tmp_path, monkeypatch):
    env_file = tmp_path / ".env.test"
    env_file.write_text("HOST=0.0.0.0\nPORT=9001\nALLOWED_EXTENSIONS=.zip,.tar\n", encoding="utf-8")
    monkeypatch.setenv("APP_ENV", "test")

    Settings = load_settings_class(SERVER_ROOT)
    settings = Settings(base_dir=tmp_path)
    assert settings.host == "0.0.0.0"
    assert settings.port == 9001
    assert settings.allowed_extensions == (".tar", ".zip")

    monkeypatch.delenv("APP_ENV", raising=False)
