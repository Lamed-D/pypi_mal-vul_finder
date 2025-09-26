## Python FastAPI 서버 실행 방법

### 방법 1: uv 사용 (권장)

#### 1) uv 설치 (Windows PowerShell)
```powershell
# Windows에서 uv 설치
pip install uv
```

#### 2) 의존성 설치 및 서버 실행
```powershell
# 의존성 설치
uv pip install -r requirements.txt

# 서버 실행
uv run uvicorn main:app --host 127.0.0.1 --port 8000 --reload
```

### 방법 2: pip 사용

#### 1) 가상환경(권장) 생성 및 활성화 (Windows PowerShell 예시)
```powershell
python -m venv .venv
. .venv/Scripts/Activate.ps1
```

#### 2) 의존성 설치
```powershell
pip install -r requirements.txt
```

#### 3) 서버 실행
```powershell
uvicorn main:app --host 127.0.0.1 --port 8000 --reload
```

엔드포인트: `POST http://127.0.0.1:8000/upload` (form field: `file`)


