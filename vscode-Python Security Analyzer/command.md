# Python Security Analyzer - VS Code 확장 명령어 가이드

## 개요
Python Security Analyzer VS Code 확장은 Python 코드의 보안 분석을 위한 도구입니다. 프로젝트나 설치된 패키지를 ZIP으로 압축하여 AI 기반 보안 분석 서버로 전송하고, 취약점과 악성 코드를 탐지합니다.

## 사용 가능한 명령어

### 1. 통합 분석 (Integrated Analysis)
통합 분석은 취약점과 악성 코드를 모두 분석하는 종합적인 보안 검사입니다.

#### 1.1 프로젝트 통합 분석
- **명령어**: `Python Security: Analyze Project (Integrated)`
- **기능**: 현재 워크스페이스의 Python 파일들을 압축하여 취약점과 악성 코드를 모두 분석
- **사용법**: 
  1. VS Code에서 프로젝트 폴더를 열기
  2. Command Palette (Ctrl+Shift+P) 열기
  3. "Python Security: Analyze Project (Integrated)" 검색 후 실행
- **결과**: 취약점과 악성 코드 분석 결과를 모두 포함한 통합 보고서

#### 1.2 설치된 패키지 통합 분석
- **명령어**: `Python Security: Analyze Installed Packages (Integrated)`
- **기능**: 현재 Python 환경에 설치된 모든 패키지의 소스코드를 추출하여 취약점과 악성 코드를 모두 분석
- **사용법**:
  1. Command Palette (Ctrl+Shift+P) 열기
  2. "Python Security: Analyze Installed Packages (Integrated)" 검색 후 실행
- **결과**: 설치된 패키지들의 취약점과 악성 코드 분석 결과를 모두 포함한 통합 보고서

### 2. 취약점 분석 (Vulnerability Analysis)
취약점 분석은 코드의 보안 취약점만을 집중적으로 분석합니다.

#### 2.1 프로젝트 취약점 분석
- **명령어**: `Python Security: Analyze Project (Vulnerability Only)`
- **기능**: 현재 워크스페이스의 Python 파일들을 압축하여 취약점만 분석
- **사용법**:
  1. VS Code에서 프로젝트 폴더를 열기
  2. Command Palette (Ctrl+Shift+P) 열기
  3. "Python Security: Analyze Project (Vulnerability Only)" 검색 후 실행
- **결과**: CWE(Common Weakness Enumeration) 분류를 포함한 취약점 분석 보고서

#### 2.2 설치된 패키지 취약점 분석
- **명령어**: `Python Security: Analyze Installed Packages (Vulnerability Only)`
- **기능**: 현재 Python 환경에 설치된 모든 패키지의 소스코드를 추출하여 취약점만 분석
- **사용법**:
  1. Command Palette (Ctrl+Shift+P) 열기
  2. "Python Security: Analyze Installed Packages (Vulnerability Only)" 검색 후 실행
- **결과**: 설치된 패키지들의 취약점 분석 보고서

### 3. 악성 코드 분석 (Malicious Code Analysis)
악성 코드 분석은 악성 코드나 의심스러운 패턴만을 집중적으로 분석합니다.

#### 3.1 프로젝트 악성 코드 분석
- **명령어**: `Python Security: Analyze Project (Malicious Only)`
- **기능**: 현재 워크스페이스의 Python 파일들을 압축하여 악성 코드만 분석
- **사용법**:
  1. VS Code에서 프로젝트 폴더를 열기
  2. Command Palette (Ctrl+Shift+P) 열기
  3. "Python Security: Analyze Project (Malicious Only)" 검색 후 실행
- **결과**: 악성 코드 탐지 결과 보고서

#### 3.2 설치된 패키지 악성 코드 분석
- **명령어**: `Python Security: Analyze Installed Packages (Malicious Only)`
- **기능**: 현재 Python 환경에 설치된 모든 패키지의 소스코드를 추출하여 악성 코드만 분석
- **사용법**:
  1. Command Palette (Ctrl+Shift+P) 열기
  2. "Python Security: Analyze Installed Packages (Malicious Only)" 검색 후 실행
- **결과**: 설치된 패키지들의 악성 코드 분석 보고서

## 분석 결과 확인

### 웹 대시보드
- 모든 분석이 완료되면 자동으로 웹 대시보드가 열립니다
- 대시보드 URL: `http://127.0.0.1:8000/session/{session_id}`
- 분석 타입에 따라 다른 UI로 결과를 표시합니다:
  - **통합 분석**: 취약점과 악성 코드 결과를 모두 표시
  - **취약점 분석**: 취약점 결과만 표시
  - **악성 코드 분석**: 악성 코드 결과만 표시

### 결과 해석
- **안전한 파일**: 취약점이나 악성 코드가 발견되지 않은 파일
- **취약한 파일**: 보안 취약점이 발견된 파일 (CWE 분류 포함)
- **악성 파일**: 악성 코드로 판단된 파일

## 주의사항

### 서버 요구사항
- Python Security Analysis 서버가 `http://127.0.0.1:8000`에서 실행 중이어야 합니다
- 서버가 실행되지 않은 경우 연결 오류 메시지가 표시됩니다

### 권한 요구사항
- 설치된 패키지 분석 시 관리자 권한이 필요할 수 있습니다
- 권한 오류 시 VS Code를 관리자 권한으로 실행해주세요

### 파일 크기 제한
- 업로드 가능한 ZIP 파일 크기: 최대 100MB
- 큰 프로젝트의 경우 분석 시간이 오래 걸릴 수 있습니다

## 문제 해결

### 일반적인 오류
1. **서버 연결 실패**: 서버가 실행 중인지 확인
2. **권한 오류**: VS Code를 관리자 권한으로 실행
3. **파일 크기 초과**: 프로젝트 크기를 줄이거나 필요한 파일만 포함
4. **Python 파일 없음**: 워크스페이스에 .py 파일이 있는지 확인

### 로그 확인
- VS Code의 Output 패널에서 "Python Security Analyzer" 채널을 확인하여 상세한 로그를 볼 수 있습니다

## 기술적 세부사항

### 분석 모델
- **취약점 분석**: LSTM 기반 safepy_3 모델 사용
- **악성 코드 분석**: LSTM 기반 safepy_3_malicious 모델 사용
- **Word2Vec**: 코드 토큰 임베딩을 위한 Word2Vec 모델 사용

### 처리 과정
1. Python 파일 추출 및 압축
2. 서버로 ZIP 파일 업로드
3. 다중 프로세스 병렬 분석 (최대 3개 워커)
4. 결과 데이터베이스 저장
5. 웹 대시보드에서 결과 표시

### 지원 파일 형식
- 입력: ZIP 파일 (Python 파일들 포함)
- 분석 대상: .py 확장자 파일만
- 메타데이터: 패키지 정보, 버전 정보 등
