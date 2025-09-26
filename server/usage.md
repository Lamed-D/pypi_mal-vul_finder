# Python Security Analysis System 사용법

## 🚀 빠른 시작

### 1. 시스템 요구사항
- **Python**: 3.8 ~ 3.11 (권장: 3.11)
- **OS**: Windows 10/11 (현재 테스트 환경)
- **RAM**: 최소 4GB (AI 모델 로딩용)
- **GPU**: 권장 (선택사항, CPU에서도 작동)

**Python 버전 확인**:
```bash
python --version
# 또는
py --version
```

### 2. 설치 및 실행

#### 2.1 의존성 설치
```bash
# server 폴더로 이동
cd server

# 전체 의존성 설치 (시간이 오래 걸림)
py -m pip install -r requirements.txt
```

#### 2.2 서버 실행
```bash
# 서버 시작
py run.py
```

#### 2.3 웹 대시보드 접속
브라우저에서 `http://127.0.0.1:8000` 접속

### 3. VS Code Extension 연동

#### 3.1 Extension 설치
1. VS Code에서 Extension Marketplace 열기
2. "Python Security Analyzer" 검색
3. 설치 및 활성화

#### 3.2 Extension 사용법
1. Python 프로젝트 폴더 열기
2. Command Palette (`Ctrl+Shift+P`) 열기
3. "Python Security: Analyze Project" 명령 실행
4. Extension이 자동으로 ZIP 파일을 생성하여 서버로 전송
5. 웹 대시보드에서 분석 결과 확인

## 📁 파일 업로드 및 분석

### 1. ZIP 파일 준비
- Python 프로젝트를 ZIP으로 압축
- `.py` 파일과 메타데이터 파일(`.txt`, `.json`) 포함
- 최대 파일 크기: 100MB

### 2. 업로드 방법

#### 방법 1: 드래그 앤 드롭
1. 웹 대시보드의 업로드 영역에 ZIP 파일을 드래그
2. 파일이 자동으로 업로드되고 분석 시작

#### 방법 2: 클릭하여 선택
1. 업로드 영역을 클릭
2. 파일 선택 대화상자에서 ZIP 파일 선택
3. 업로드 및 분석 시작

### 3. 분석 과정
- **자동 파일 추출**: ZIP에서 Python 파일과 메타데이터 추출
- **다층 분석**: 
  - CodeBERT로 취약점 탐지
  - LSTM으로 악성 코드 탐지
  - Metadata로 패키지 분석
- **결과 저장**: SQLite 데이터베이스에 저장

## 📊 대시보드 사용법

### 1. 메인 대시보드
- **통계 카드**: 전체 세션, 파일, 악성/취약 파일 수 표시
- **업로드 영역**: ZIP 파일 업로드
- **최근 세션**: 최근 분석 세션 목록
- **분석 차트**: 파일 유형별 분포 시각화

### 2. 세션 상세 보기
1. "View" 버튼 클릭
2. 세션 정보 확인:
   - 파일명, 업로드 시간, 상태
   - 총 파일 수, 처리된 파일 수
3. 파일별 분석 결과:
   - 악성/취약/안전 상태
   - CWE 분류 (취약점인 경우)
   - 신뢰도 점수

### 3. 분석 결과 해석

#### 상태 표시
- 🟢 **Safe**: 안전한 파일
- 🔴 **Malicious**: 악성 코드로 판단
- 🟡 **Vulnerable**: 취약점이 있는 코드

#### 상세 분석 결과

**CodeBERT 취약점 분석**:
- CWE-79: Cross-site Scripting
- CWE-89: SQL Injection
- CWE-78: OS Command Injection
- CWE-22: Path Traversal
- CWE-352: Cross-Site Request Forgery
- 기타 OWASP Top 10 취약점

**LSTM 악성 코드 탐지**:
- 악성 확률: 0.0 ~ 1.0 (1.0에 가까울수록 악성)
- 정상/악성 소스코드 딥러닝 모델 분석 결과

**Metadata 패키지 분석**:
- **download_log**: 인기 라이브러리 1500개의 평균 다운로드 수 대비 수치
- **summary_length**: 메타데이터 설명의 길이
- **summary_entropy**: 메타데이터 설명의 엔트로피 (자동 생성 가능성)
- **summary_low_entropy**: 낮은 엔트로피 여부
- **version_valid**: 버전 형식 유효성
- **is_typo_like**: 30일 기준 인기 라이브러리와의 타이포스쿼팅 유사도
- **package_name**: 패키지 이름
- **version**: 패키지 버전
- **author**: 작성자
- **author_email**: 작성자 이메일

#### 분석 보고서 예시
```
패키지: 1337test
버전: 1.0
작성자: Jonathan Hartley
이메일: tartley@tartley.com

메타데이터 분석:
- 다운로드 로그: 5.04 (인기 라이브러리 평균 대비 낮음)
- 설명 길이: 33자 (짧음)
- 설명 엔트로피: 4.01 (자동 생성 가능성 있음)
- 버전 유효성: FALSE (비정상적)
- 타이포스쿼팅: FALSE (정상)

XGBoost 결과: 1 (악성 패키지로 판단)
코드 악성 확률: 85% (LSTM 모델 결과)
```

## 🔧 고급 사용법

### 1. API 직접 사용

#### 세션 목록 조회
```bash
curl http://127.0.0.1:8000/api/v1/sessions
```

#### 특정 세션 조회
```bash
curl http://127.0.0.1:8000/api/v1/sessions/{session_id}
```

#### 통계 조회
```bash
curl http://127.0.0.1:8000/api/v1/stats
```

#### ZIP 파일 업로드
```bash
curl -X POST -F "file=@your_file.zip" http://127.0.0.1:8000/api/v1/upload
```

### 2. 설정 변경

#### config.py 수정
```python
# 파일 크기 제한 변경
MAX_FILE_SIZE = 200 * 1024 * 1024  # 200MB

# 분석 임계값 조정
THRESHOLD = 0.7  # 0.7 이상일 때 악성/취약으로 판단

# 서버 포트 변경
PORT = 8001
```

### 3. 데이터베이스 관리

#### SQLite 데이터베이스 위치
```
server/security_analysis.db
```

#### 데이터베이스 스키마
- `analysis_sessions`: 분석 세션 정보
- `analyzed_files`: 분석된 파일 결과
- `analysis_logs`: 분석 로그

## 🐛 문제 해결

### 1. 서버 시작 오류

#### ImportError: attempted relative import beyond top-level package
**오류 원인**: Python 모듈 import 경로 문제
**해결방법**:
```bash
# server 폴더에서 실행
cd server
py run.py
```

#### 포트 사용 중
```bash
# 포트 8000 사용 중인 프로세스 확인
netstat -ano | findstr :8000

# 다른 포트 사용 (config.py에서 PORT 수정)
```

#### Python 경로 문제
```bash
# Python 경로 확인
py --version

# pip 업그레이드
py -m pip install --upgrade pip
```

#### PowerShell 명령어 오류
```bash
# 잘못된 방법 (PowerShell에서 작동하지 않음)
cd server && py run.py

# 올바른 방법
cd server
py run.py
```

### 2. 모델 로딩 오류

#### 모델 파일 없음
```
Error: Model file not found
```
**해결방법**: `server/models/` 폴더에 모델 파일들이 있는지 확인

#### 메모리 부족
```
CUDA out of memory
```
**해결방법**: 
- GPU 메모리 확인
- 배치 크기 줄이기 (`config.py`에서 `BATCH_SIZE` 수정)

### 3. 분석 실패

#### 파일 형식 오류
```
Only ZIP files are allowed
```
**해결방법**: ZIP 파일인지 확인

#### 파일 크기 초과
```
File too large
```
**해결방법**: 
- 파일 크기 확인 (100MB 이하)
- `config.py`에서 `MAX_FILE_SIZE` 수정

### 4. 웹 대시보드 접속 불가

#### 서버가 실행되지 않음
**해결방법**: 
```bash
cd server
py run.py
```

#### 방화벽 차단
**해결방법**: 
- Windows 방화벽에서 Python 허용
- 포트 8000 열기

## 📈 성능 최적화

### 1. GPU 사용
```bash
# CUDA 설치 확인
py -c "import torch; print(torch.cuda.is_available())"

# GPU 사용 설정
# config.py에서 DEVICE = "cuda" 설정
```

### 2. 메모리 최적화
```python
# config.py에서 배치 크기 조정
BATCH_SIZE = 4  # 메모리에 따라 조정

# 분석 시간 제한
ANALYSIS_TIMEOUT = 600  # 10분
```

### 3. 대용량 파일 처리
- 파일을 작은 단위로 분할
- 배치 처리로 메모리 사용량 최적화
- 분석 결과 캐싱

## 🔒 보안 고려사항

### 1. 파일 업로드 보안
- ZIP 파일 크기 제한
- 파일 형식 검증
- 악성 파일 스캔

### 2. 데이터 보호
- 분석 결과 암호화 저장
- 개인정보 마스킹
- 접근 로그 기록

### 3. 네트워크 보안
- HTTPS 사용 권장
- API 인증 추가
- 방화벽 설정

## 📞 지원 및 문의

### 1. 로그 확인
```
server/logs/security_analysis.log
```

### 2. 일반적인 문제
- README.md 참조
- log.md 개발 로그 확인
- GitHub Issues 등록

### 3. 성능 문제
- 시스템 리소스 확인
- 모델 로딩 시간 측정
- 분석 시간 최적화

---

## 🎯 사용 시나리오

### 시나리오 1: VS Code Extension을 통한 실시간 분석
1. VS Code에서 Python 프로젝트 열기
2. Command Palette에서 "Python Security: Analyze Project" 실행
3. Extension이 자동으로 ZIP 생성 및 서버 전송
4. 웹 대시보드에서 실시간 분석 결과 확인
5. 취약점 수정 후 재분석

### 시나리오 2: 웹 대시보드를 통한 수동 분석
1. Python 프로젝트를 ZIP으로 압축
2. 웹 대시보드에서 드래그 앤 드롭으로 업로드
3. 다층 분석 결과 확인:
   - CodeBERT 취약점 탐지
   - LSTM 악성 코드 탐지
   - Metadata 패키지 분석
4. 상세 보고서로 보안 이슈 파악

### 시나리오 3: 패키지 보안 검사
1. Python 패키지 소스코드와 메타데이터 준비
2. ZIP 파일로 압축하여 업로드
3. XGBoost 모델을 통한 악성 패키지 탐지
4. 다운로드 수, 엔트로피, 버전 유효성 등 메타데이터 분석
5. 신뢰할 수 있는 패키지인지 종합 판단

### 시나리오 4: 대량 프로젝트 분석
1. 여러 Python 프로젝트를 개별 ZIP으로 준비
2. VS Code Extension 또는 웹 대시보드로 순차 분석
3. 대시보드에서 전체 통계 및 트렌드 확인
4. 문제가 있는 파일들을 우선순위별로 식별
5. 보안 강화 계획 수립

## 🔄 전체 워크플로우

```
VS Code Extension → ZIP 생성 → 서버 전송 → 다층 분석 → SQLite 저장 → 웹 대시보드 표시
     ↓                    ↓              ↓              ↓              ↓
프로젝트 선택        자동 압축      CodeBERT + LSTM    데이터베이스    실시간 결과
Command 실행         메타데이터      + Metadata        저장          시각화
                    포함           분석
```

이제 Python 코드 보안 분석 시스템을 효과적으로 사용할 수 있습니다! 🚀
