"""Application configuration utilities without external dependencies."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Tuple


class Settings:
    """Lightweight settings loader using environment variables."""

    def __init__(self) -> None:
        base_dir = Path(__file__).resolve().parents[2]
        self.base_dir = base_dir

        self.database_url = os.getenv("DATABASE_URL", "sqlite:///./main.db")
        self.host = os.getenv("HOST", "127.0.0.1")
        self.port = int(os.getenv("PORT", "8000"))
        self.log_level = os.getenv("LOG_LEVEL", "INFO")
        self.service_name = os.getenv("SERVICE_NAME", "PySecure")
        self.service_version = os.getenv("SERVICE_VERSION", "2.0.0")

        self.max_file_size = int(os.getenv("MAX_FILE_SIZE", str(100 * 1024 * 1024)))
        allowed_env = os.getenv("ALLOWED_EXTENSIONS")
        if allowed_env:
            allowed = tuple(
                ext.strip().lower() for ext in allowed_env.split(",") if ext.strip()
            )
        else:
            allowed = (".zip",)
        self.allowed_extensions: Tuple[str, ...] = tuple(sorted(set(allowed)))

        self.analysis_timeout = int(os.getenv("ANALYSIS_TIMEOUT", "300"))
        self.batch_size = int(os.getenv("BATCH_SIZE", "8"))
        self.max_code_length = int(os.getenv("MAX_CODE_LENGTH", "512"))
        self.stride = int(os.getenv("STRIDE", "128"))
        self.threshold = float(os.getenv("THRESHOLD", "0.5"))

        self.secret_key = os.getenv("SECRET_KEY", "your-secret-key-here")
        self.access_token_expire_minutes = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))

        upload_dir_env = os.getenv("UPLOAD_DIR")
        self.upload_dir = Path(upload_dir_env) if upload_dir_env else base_dir / "uploads"
        self.upload_dir.mkdir(parents=True, exist_ok=True)

        model_dir_env = os.getenv("MODEL_DIR")
        self.model_dir = Path(model_dir_env) if model_dir_env else base_dir / "models"
        self.model_dir.mkdir(parents=True, exist_ok=True)

        database_path_env = os.getenv("DATABASE_PATH")
        self.database_path = Path(database_path_env) if database_path_env else base_dir / "main.db"

        ml_model_dir_env = os.getenv("ML_MODEL_DIR")
        default_ml_dir = (base_dir / ".." / "safepy_3_malicious_ML").resolve()
        self.ml_model_dir = Path(ml_model_dir_env) if ml_model_dir_env else default_ml_dir

        self.lstm_model_path = self.model_dir / "lstm"
        self.w2v_model_path = self.model_dir / "w2v" / "word2vec_withString10-6-100.model"
        self.xgboost_model_path = self.ml_model_dir / "xgboost_model.pkl"
        self.ml_lstm_model_path = self.ml_model_dir / "model" / "model_mal.pkl"
        self.ml_label_encoder_path = self.ml_model_dir / "model" / "label_encoder_mal.pkl"

    @property
    def allowed_extension_set(self) -> set[str]:
        return set(self.allowed_extensions)


settings = Settings()
