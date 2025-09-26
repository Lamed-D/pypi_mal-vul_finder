"""
Configuration settings for the Python Security Analysis System
"""
import os
from pathlib import Path

# Base directory
BASE_DIR = Path(__file__).parent

# Database settings
DATABASE_URL = "sqlite:///./security_analysis.db"
DATABASE_PATH = BASE_DIR / "security_analysis.db"

# File upload settings
UPLOAD_DIR = BASE_DIR / "uploads"
MAX_FILE_SIZE = 100 * 1024 * 1024  # 100MB
ALLOWED_EXTENSIONS = {".zip"}

# Analysis settings
ANALYSIS_TIMEOUT = 300  # 5 minutes
BATCH_SIZE = 8
MAX_CODE_LENGTH = 512
STRIDE = 128
THRESHOLD = 0.5

# Model paths (LSTM-only)
MODEL_DIR = BASE_DIR / "models"
LSTM_MODEL_PATH = MODEL_DIR / "lstm"
W2V_MODEL_PATH = MODEL_DIR / "w2v" / "word2vec_withString10-6-100.model"

# API settings
API_V1_PREFIX = "/api/v1"
HOST = "127.0.0.1"
PORT = 8000

# Logging
LOG_LEVEL = "INFO"
LOG_FILE = BASE_DIR / "logs" / "security_analysis.log"

# Security
SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-here")
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Create necessary directories
UPLOAD_DIR.mkdir(exist_ok=True)
MODEL_DIR.mkdir(exist_ok=True)
(BASE_DIR / "logs").mkdir(exist_ok=True)
