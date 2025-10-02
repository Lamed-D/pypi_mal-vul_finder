"""Backward-compatible configuration exports."""

from app.core.config import settings

BASE_DIR = settings.base_dir
DATABASE_URL = settings.database_url
DATABASE_PATH = settings.database_path

UPLOAD_DIR = settings.upload_dir
MAX_FILE_SIZE = settings.max_file_size
ALLOWED_EXTENSIONS = settings.allowed_extension_set

ANALYSIS_TIMEOUT = settings.analysis_timeout
BATCH_SIZE = settings.batch_size
MAX_CODE_LENGTH = settings.max_code_length
STRIDE = settings.stride
THRESHOLD = settings.threshold

MODEL_DIR = settings.model_dir
LSTM_MODEL_PATH = settings.lstm_model_path
W2V_MODEL_PATH = settings.w2v_model_path

ML_MODEL_DIR = settings.ml_model_dir
XGBOOST_MODEL_PATH = settings.xgboost_model_path
ML_LSTM_MODEL_PATH = settings.ml_lstm_model_path
ML_LABEL_ENCODER_PATH = settings.ml_label_encoder_path

API_V1_PREFIX = "/api/v1"
HOST = settings.host
PORT = settings.port
SERVICE_NAME = settings.service_name
SERVICE_VERSION = settings.service_version

LOG_LEVEL = settings.log_level

SECRET_KEY = settings.secret_key
ACCESS_TOKEN_EXPIRE_MINUTES = settings.access_token_expire_minutes
