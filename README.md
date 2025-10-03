# PySecure - Python Security Analysis System

PySecure는 Python 코드의 악성 여부 및 취약점을 다중 엔진(LSTM, BERT, ML)으로 분석하고, FastAPI 기반 대시보드와 VS Code 확장을 통해 결과를 제공합니다.

## 빠른 시작

```bash
# 서버 실행 (필요 시 가상환경에서)
cd server
cp .env.example .env  # 환경설정 템플릿 복사 후 값 수정
python run.py
```

기본 서비스 주소는 `http://127.0.0.1:8000` 입니다.

### 필수 의존성
- Python 3.9+
- FastAPI, SQLAlchemy, Uvicorn 등 `server/requirements.txt`에 정의된 패키지

### 선택적 분석 엔진 의존성
다음 패키지는 LSTM/BERT/ML 분석을 활성화할 때 필요합니다.

| 엔진 | 필요 패키지 |
|------|-------------|
| LSTM | `gensim` (Word2Vec), 학습된 LSTM 모델
| BERT | `torch`, `transformers`, CodeBERT 가중치
| ML (메타데이터) | `numpy`, `pandas`, `scikit-learn`, `tensorflow`, `requests`, `python-Levenshtein`, `safepy_3_malicious_ML` 리소스

필요한 엔진만 설치하고 `.env` 또는 환경변수에서 경로를 지정하면 됩니다. 필수 패키지가 없으면 서버는 명확한 오류 메시지와 함께 해당 엔진을 비활성화합니다.

## 환경설정

- `server/.env.example`을 복사해 `.env`로 사용하거나, `APP_ENV` 값을 지정해 `.env.{APP_ENV}` 파일을 자동 로드할 수 있습니다.
- 주요 설정 항목:
  - `HOST`, `PORT`: 서버 접근 주소
  - `DATABASE_URL`, `DATABASE_PATH`: 데이터베이스 위치
  - `MAX_FILE_SIZE`, `ALLOWED_EXTENSIONS`: 업로드 제한
  - `MODEL_DIR`, `ML_MODEL_DIR`: 모델/리소스 위치

## 개발 가이드
- FastAPI 앱 구조는 `app/__init__.py`의 `create_app()`을 통해 초기화됩니다.
- 라우터는 `app/api/routers/`에, 서비스 로직은 `app/services/`에 위치합니다.
- 분석 파이프라인은 `app/services/analysis/orchestrator.py`에서 관리되며, 개별 엔진은 지연 로딩됩니다.

## 테스트

```bash
pytest -q
```

필요한 ML/BERT 패키지가 설치되지 않은 경우 관련 기능은 자동으로 건너뛰거나 명확한 오류를 제공합니다.

## 참고 자료
- 사용 동영상 가이드: https://youtu.be/xs6TBCEsrgY](https://youtu.be/-y6QJE9Cj4s
