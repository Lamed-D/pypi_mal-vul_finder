# VS Code 확장 + Python 서버 프로젝트 설치 가이드

## 📋 프로젝트 개요
이 프로젝트는 VS Code 확장과 Python FastAPI 서버로 구성되어 있습니다:
- **VS Code 확장**: 선택한 폴더를 ZIP으로 압축하여 Python 서버로 업로드
- **Python 서버**: FastAPI 기반으로 ZIP 파일을 받아서 처리 후 응답

## 🛠️ 사전 요구사항

### 1. Node.js 설치
- **다운로드**: [Node.js 공식 사이트](https://nodejs.org/)
- **권장 버전**: LTS 버전 (18.x 이상)
- **확인 방법**:
  ```powershell
  node --version
  npm --version
  ```

### 2. Python 설치
- **다운로드**: [Python 공식 사이트](https://www.python.org/downloads/)
- **권장 버전**: Python 3.8 이상
- **확인 방법**:
  ```powershell
  python --version
  pip --version
  ```

### 3. VS Code 설치
- **다운로드**: [VS Code 공식 사이트](https://code.visualstudio.com/)
- **필수 확장**: TypeScript and JavaScript Language Features (기본 포함)

## 🚀 설치 및 실행 방법

### 1단계: 프로젝트 클론 및 이동
```powershell
# 프로젝트 폴더로 이동
cd C:\Users\Lamed\Downloads\vscode-extension
```

### 2단계: VS Code 확장 의존성 설치
```powershell
# Node.js 의존성 설치
npm install
```

### 3단계: Python 서버 의존성 설치

#### 방법 A: uv 사용 (권장)
```powershell
# uv 설치
pip install uv

# Python 서버 폴더로 이동
cd python-server

# 의존성 설치 (uv 사용)
uv pip install -r requirements.txt
```

#### 방법 B: pip + 가상환경 사용
```powershell
# Python 서버 폴더로 이동
cd python-server

# 가상환경 생성
python -m venv .venv

# 가상환경 활성화 (Windows PowerShell)
./.venv/Scripts/Activate.ps1

# 의존성 설치
uv pip install -r requirements.txt
```

### 4단계: Python 서버 실행
```powershell
# python-server 폴더에서 실행
uv run -m uvicorn main:app --host 127.0.0.1 --port 8000 --reload
```

또는 가상환경을 사용하는 경우:
```powershell
cd python-server
./.venv/Scripts/Activate.ps1
python -m uvicorn main:app --host 127.0.0.1 --port 8000 --reload
```

서버가 성공적으로 실행되면 다음과 같은 메시지가 표시됩니다:
```
INFO:     Uvicorn running on http://127.0.0.1:8000 (Press CTRL+C to quit)
INFO:     Started reloader process
INFO:     Started server process
INFO:     Waiting for application startup.
INFO:     Application startup complete.
```

### 5단계: VS Code 확장 실행

#### 5-1. 확장 개발 환경 실행
1. VS Code에서 프로젝트 루트 폴더(`vscode-extension`)를 엽니다
2. `F5` 키로 Extension Development Host 실행 (또는 `Ctrl+Shift+P` → "Debug: Start Debugging")
3. 새로운 "Extension Development Host" 창이 열립니다

#### 5-2. 확장 사용하기
1. Extension Development Host 창에서 `Ctrl+Shift+P` (명령 팔레트)
2. "Zip folder and upload to Python server" 명령 실행
3. 압축할 폴더 선택
4. 응답 ZIP을 저장할 경로 선택

## 🔧 개발 모드 실행

### TypeScript 컴파일 (자동 감시)
```powershell
# 프로젝트 루트에서 실행
npm run watch
```

### 수동 컴파일
```powershell
npm run compile
```

### 확장 패키징
```powershell
npm run package
```

## 📁 프로젝트 구조
```
vscode-extension/
├── src/
│   └── extension.ts          # VS Code 확장 메인 코드
├── python-server/
│   ├── main.py              # FastAPI 서버 메인 코드
│   ├── requirements.txt     # Python 의존성
│   └── uploads/             # 업로드된 파일 저장소
├── out/                     # 컴파일된 JavaScript 파일
├── package.json             # Node.js 의존성 및 설정
└── tsconfig.json           # TypeScript 설정
```

## 🌐 API 엔드포인트
- **서버 주소**: `http://127.0.0.1:8000`
- **업로드 엔드포인트**: `POST /upload`
- **파라미터**: `file` (multipart/form-data)

## 🐛 문제 해결

### Python 서버가 시작되지 않는 경우
1. 포트 8000이 이미 사용 중인지 확인:
   ```powershell
   netstat -ano | findstr :8000
   ```
2. 다른 포트 사용:
   ```powershell
   uvicorn main:app --host 127.0.0.1 --port 8001 --reload
   ```

### VS Code 확장이 작동하지 않는 경우
1. TypeScript 컴파일 확인:
   ```powershell
   npm run compile
   ```
2. Extension Development Host 창에서 개발자 도구 확인:
   - `Help` → `Toggle Developer Tools`

### 의존성 설치 오류
1. Node.js 버전 확인 (18.x 이상 권장)
2. Python 버전 확인 (3.8 이상 권장)
3. 관리자 권한으로 PowerShell 실행

## 📝 추가 정보
- **VS Code 확장 ID**: `vscode-extension.uploadZipToLocal`
- **서버 재시작**: Python 서버는 `--reload` 옵션으로 파일 변경 시 자동 재시작
- **로그 확인**: VS Code 개발자 도구 콘솔에서 확장 로그 확인 가능

## 🎯 사용 시나리오
1. VS Code에서 작업 중인 프로젝트 폴더 선택
2. 확장 명령 실행으로 ZIP 압축 및 서버 업로드
3. Python 서버에서 파일 처리 후 응답 ZIP 다운로드
4. 로컬에 응답 파일 저장

이제 프로젝트를 성공적으로 설치하고 실행할 수 있습니다! 🎉
