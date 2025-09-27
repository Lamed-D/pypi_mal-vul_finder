"""
Python 패키지 보안 분석 도구 설정 파일
=====================================

이 파일은 분석 도구의 주요 설정값들을 관리합니다.
"""

import os
from pathlib import Path

# 기본 디렉토리 설정
BASE_DIR = Path(__file__).parent
SOURCE_DIR = BASE_DIR / "source"
MODEL_DIR = BASE_DIR / "model"
W2V_DIR = BASE_DIR / "w2v"
RESULT_DIR = BASE_DIR / "result"

# 모델 파일 경로
LSTM_MODEL_PATH = MODEL_DIR / "model_mal.pkl"
LABEL_ENCODER_PATH = MODEL_DIR / "label_encoder_mal.pkl"
XGBOOST_MODEL_PATH = BASE_DIR / "xgboost_model.pkl"
W2V_MODEL_PATH = W2V_DIR / "word2vec_withString10-6-100.model"

# 분석 설정
MAX_SEQUENCE_LENGTH = 100
EMBEDDING_DIM = 100
BATCH_SIZE = 32

# 출력 파일명
OUTPUT_FILES = {
    "merged_source": "merged_sourceCode.csv",
    "typo_analysis": "pypi_typo_analysis5.csv", 
    "vulnerability_analysis": "package_vulnerability_analysis.csv",
    "malicious_report": "pypi_malicious_reason_report.txt"
}

# Google Cloud 설정
GCP_PROJECT_ID = "plated-mantis-471407-m4"
BIGQUERY_DATASET = "pypi_typosquatting"
BIGQUERY_TABLE = "package_metadata"

# 로깅 설정
LOG_LEVEL = "INFO"
LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

# 성능 최적화 설정
TF_OPTIMIZATIONS = {
    "TF_CPP_MIN_LOG_LEVEL": "2",
    "TF_ENABLE_ONEDNN_OPTS": "0", 
    "TF_FORCE_GPU_ALLOW_GROWTH": "true",
    "TF_GPU_THREAD_MODE": "gpu_private"
}

# 메모리 관리 설정
MEMORY_MANAGEMENT = {
    "enable_gc": True,
    "gc_threshold": 1000,  # 처리할 파일 수
    "chunk_size": 100      # 배치 처리 크기
}
