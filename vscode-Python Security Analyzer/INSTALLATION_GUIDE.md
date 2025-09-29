# Python Security Analyzer - 설치 및 사용 가이드

## 📋 프로젝트 개요
이 프로젝트는 Python 코드의 보안 취약점과 악성코드를 AI 기반으로 분석하는 통합 시스템입니다:

- **VS Code 확장**: 프로젝트 폴더를 ZIP으로 압축하여 분석 서버로 전송
- **Python 분석 서버**: FastAPI 기반으로 ZIP 파일을 받아서 AI 모델로 분석
- **다중 AI 모델**: LSTM, BERT, XGBoost 기반 취약점/악성코드 탐지

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
- **권장 버전**: Python 3.8 이상 (3.12 미만)
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
# 프로젝트 루트 폴더로 이동
cd C:\Users\Lamed\Documents\GitHub\pypi_mal-vul_finder
```

### 2단계: VS Code 확장 의존성 설치
```powershell
# VS Code 확장 폴더로 이동
cd vscode-extension

# Node.js 의존성 설치
npm install

# TypeScript 컴파일
npm run compile
```

### 3단계: Python 서버 의존성 설치
```powershell
# 서버 폴더로 이동
cd ..\server

# Python 의존성 설치
pip install -r requirements.txt
```

### 4단계: Python 서버 실행
```powershell
# 서버 실행 (개발 모드)
python run.py
```

또는 직접 실행:
```powershell
uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

### 5단계: VS Code 확장 실행
1. VS Code에서 `vscode-extension` 폴더 열기
2. `F5` 키를 눌러 Extension Development Host 실행
3. 새 창에서 명령 팔레트 (`Ctrl+Shift+P`) 열기
4. "Python Security" 명령어들 사용

## 📁 프로젝트 구조
```
pypi_mal-vul_finder/
├── vscode-extension/              # VS Code 확장
│   ├── src/
│   │   └── extension.ts          # 확장 메인 코드
│   ├── package.json              # Node.js 의존성
│   └── tsconfig.json            # TypeScript 설정
├── server/                       # Python 분석 서버
│   ├── app/
│   │   ├── main.py              # FastAPI 서버
│   │   └── services/            # 서비스 로직
│   ├── analysis/                # AI 분석 모듈
│   │   ├── bert_analyzer.py     # BERT 기반 분석
│   │   └── integrated_lstm_analyzer.py  # LSTM 기반 분석
│   ├── models/                  # AI 모델 파일들
│   │   ├── bert_mal/           # BERT 악성코드 모델
│   │   ├── bert_vul/           # BERT 취약점 모델
│   │   └── lstm/               # LSTM 모델들
│   └── requirements.txt         # Python 의존성
├── codebert_mal/                # BERT 악성코드 분석
├── codebert_test2/              # BERT 취약점 분석
├── safepy_3/                    # LSTM 취약점 분석
├── safepy_3_malicious/          # LSTM 악성코드 분석
└── safepy_3_malicious_ML/       # 통합 ML 분석
```

## 🎯 사용 가능한 명령어

### VS Code 확장 명령어들:
1. **Python Security: 프로젝트 분석 (통합 - 취약점 + 악성코드)**
   - 현재 워크스페이스의 Python 파일들을 분석

2. **Python Security: 설치된 패키지 분석 (통합 - 취약점 + 악성코드)**
   - pip로 설치된 패키지들을 분석

3. **Python Security: 프로젝트 분석 (취약점만)**
   - 취약점 탐지만 수행

4. **Python Security: 프로젝트 분석 (악성코드만)**
   - 악성코드 탐지만 수행

5. **Python Security: 설치된 패키지 분석 (취약점만)**
   - 설치된 패키지의 취약점만 분석

6. **Python Security: 설치된 패키지 분석 (악성코드만)**
   - 설치된 패키지의 악성코드만 분석

## 🌐 API 엔드포인트
- **서버 주소**: `http://127.0.0.1:8000`
- **업로드 엔드포인트**: `POST /upload`
- **대시보드**: `http://127.0.0.1:8000/dashboard`
- **분석 결과**: `http://127.0.0.1:8000/sessions/{session_id}`

## 🐛 문제 해결

### Python 서버가 시작되지 않는 경우
1. 포트 8000이 이미 사용 중인지 확인:
   ```powershell
   netstat -ano | findstr :8000
   ```
2. 다른 포트 사용:
   ```powershell
   uvicorn app.main:app --host 127.0.0.1 --port 8001 --reload
   ```

### VS Code 확장이 작동하지 않는 경우
1. TypeScript 컴파일 확인:
   ```powershell
   cd vscode-extension
   npm run compile
   ```
2. Extension Development Host 창에서 개발자 도구 확인:
   - `Help` → `Toggle Developer Tools`

### 의존성 설치 오류
1. Node.js 버전 확인 (18.x 이상 권장)
2. Python 버전 확인 (3.8 이상, 3.12 미만)
3. 관리자 권한으로 PowerShell 실행
4. torch 버전 충돌 시:
   ```powershell
   pip install torch==2.1.2 --force-reinstall
   ```

### AI 모델 파일 누락
- `server/models/` 폴더에 필요한 모델 파일들이 있는지 확인
- 각 분석 모듈별로 해당 모델 파일이 필요합니다

## 📊 분석 결과 확인
1. 분석 완료 후 대시보드 URL이 표시됩니다
2. 브라우저에서 대시보드 열기 클릭
3. 세션 ID로 상세 결과 확인 가능
4. CSV/JSON 형태로 결과 다운로드 가능

## 🔧 개발자 정보
- **VS Code 확장 ID**: `python-security-analyzer`
- **서버 재시작**: `--reload` 옵션으로 파일 변경 시 자동 재시작
- **로그 확인**: VS Code 개발자 도구 콘솔에서 확장 로그 확인 가능
- **모델 업데이트**: `server/models/` 폴더의 모델 파일 교체

## 🎉 완료!
이제 Python Security Analyzer를 성공적으로 설치하고 실행할 수 있습니다!

분석을 시작하려면:
1. Python 서버 실행 (`python run.py`)
2. VS Code에서 F5로 확장 실행
3. 명령 팔레트에서 "Python Security" 명령어 선택
4. 분석할 프로젝트 또는 패키지 선택