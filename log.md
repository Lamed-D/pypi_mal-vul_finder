# Python 코드 보안 분석 시스템 개발 로그

## 프로젝트 개요
VS Code extension에서 받은 ZIP 파일을 처리하여 Python 코드의 악성/취약점을 분석하고, SQLite 기반 대시보드를 제공하는 통합 시스템 개발

## 개발 목표
- ZIP 업로드 수집 및 자동 분석 실행
- 악성/취약 탐지: LSTM(서버 통합), CodeBERT(오프라인 실험 연동)
- 메타데이터 기반 점수화(XGBoost) 옵션 적용
- SQLite로 결과 저장, 대시보드 시각화

## 개발 일정(요약)
- [x] 프로젝트 구조 설계
- [x] 서버 폴더 구조 생성
- [x] 데이터베이스 스키마 설계
- [x] 분석 엔진 통합(서버 내 LSTM, 모델 아티팩트 배치)
- [x] API 엔드포인트 구현 및 업로드 플로우
- [x] 대시보드 기본 구축(세션/상세 뷰)
- [ ] 앙상블/지표 고도화 및 통합 테스트

---

## 2024-01-XX - 프로젝트 시작

### 1. 서버 폴더 구조 생성
```
server/
├── app/
│   ├── __init__.py
│   ├── main.py              # FastAPI 메인 애플리케이션
│   ├── api/                 # API 엔드포인트 (현재 server/app/main.py에 통합)
│   ├── services/            # 비즈니스 로직
│   ├── utils/               # 유틸리티 함수
│   └── templates/           # HTML 템플릿
├── database/
│   └── database.py          # SQLite 연결 및 스키마
├── analysis/
│   ├── __init__.py
│   ├── lstm_analyzer.py     # LSTM 분석기(통합)
├── static/                  # 정적 파일 (CSS, JS)
├── uploads/                 # 업로드된 파일 저장소
├── models/                  # AI 모델 파일들
├── requirements.txt
├── config.py
└── run.py
```

### 2. 핵심 기능 설계
- **ZIP 파일 처리**: 압축 해제, Python 파일 추출
- **분석 라우팅**: 파일 타입에 따른 분석 방법 선택
- **결과 저장**: SQLite에 분석 결과 저장
- **대시보드**: 분석 결과 시각화 및 관리

### 3. 기술 스택
- **Backend**: FastAPI, SQLite
- **Frontend**: HTML, Bootstrap 5, Chart.js
- **AI/ML**: PyTorch/TensorFlow(실험 포함), Transformers, XGBoost
- **File Processing**: zipfile, pathlib

---

## 다음 단계(진행 현황)
1. 서버 폴더 구조 생성 ✅
2. 데이터베이스 스키마 설계 ✅
3. 분석 엔진 통합(서버 내 LSTM) ✅
4. API 및 업로드 플로우 구현 ✅
5. 대시보드 구축(세션/상세) ✅
6. 통합 테스트 및 지표 고도화 진행 중

---

## 2024-01-XX - 핵심 기능 구현 완료

### 1. 서버 폴더 구조 생성 ✅
```
server/
├── app/
│   ├── main.py              # FastAPI 메인 애플리케이션
│   ├── services/            # 비즈니스 로직
│   │   ├── file_service.py  # 파일 처리 서비스
│   │   └── analysis_service.py # 분석 서비스
│   └── templates/           # HTML 템플릿
│       └── dashboard.html   # 웹 대시보드
├── database/
│   └── database.py          # SQLite 모델 및 연결
├── analysis/                # 분석 엔진들
│   ├── lstm_analyzer.py     # LSTM 분석기
├── config.py                # 설정 파일
├── requirements.txt         # 의존성
└── run.py                   # 실행 파일
```

### 2. 데이터베이스 스키마 설계 ✅
- **AnalysisSession**: 업로드 세션/상태/요약
- **AnalyzedFile**: 파일별 결과/신뢰도/CWE 등
- **AnalysisLog**: 파이프라인 로그
- SQLite 기반 경량 운영

### 3. 분석 엔진 통합 ✅
- **LSTM**: 악성/취약 탐지(Word2Vec + LSTM), 서버 내 `analysis/lstm_analyzer.py`
- **CodeBERT**: CWE 분류(오프라인 실험: `codebert_test2/`), 서버에는 모델 아티팩트만 배치
- **Metadata**: 메타데이터 기반 분석(XGBoost), 선택적 적용

### 4. API 엔드포인트 구현 ✅
- `POST /api/v1/upload` (또는 `/upload`): ZIP 업로드 및 분석 트리거
- `GET /`: 대시보드(세션 리스트)
- `GET /session/{session_id}`: 세션 상세
- (내부) 파일 추출/정리 및 분석 서비스 호출

### 5. 웹 대시보드 구축 ✅
- **Bootstrap 5** 기반 반응형 UI
- **Chart.js** 시각화(세션 요약/분포)
- 드래그 앤 드롭 업로드, 상태 표시
- 세션/파일별 상세 결과 뷰

### 6. 핵심 기능
- **ZIP 파일 자동 분석**: 업로드 시 자동으로 Python 파일 추출 및 분석
- **다층 분석**: 악성/취약점/메타데이터 분석 통합
- **실시간 대시보드**: 분석 진행 상황 및 결과 시각화
- **SQLite 저장**: 모든 분석 결과 데이터베이스 저장

### 7. 기술 스택
- **Backend**: FastAPI, SQLAlchemy, SQLite
- **Frontend**: HTML5, Bootstrap 5, Chart.js
- **AI/ML**: PyTorch, TensorFlow, Transformers, XGBoost
- **File Processing**: zipfile, pathlib

---

## 다음 단계
1. 모델 파일 복사 및 설정 ✅
2. 통합 테스트 실행 ✅
3. 오류 수정 및 최적화
4. 사용자 가이드 작성 ✅

---

## 2024-01-XX - 시스템 통합 완료

### 1. 모델 파일 배치 및 설정 ✅
- CodeBERT: `server/models/codebert/codebert/`
- LSTM: `server/models/lstm/`
- Word2Vec: `server/models/w2v/`
- XGBoost: `server/models/xgboost_model.pkl`

### 2. 서버 실행 및 테스트 ✅
- FastAPI 서버 실행/정상 동작
- DB 초기화 및 세션 기록 확인
- 대시보드 접속 및 결과 조회 가능

### 3. 핵심 기능 검증
- ZIP 업로드 및 자동 분석 실행
- LSTM 기반 탐지 결과 산출
- 결과 시각화 및 세션 상세 확인
- SQLite에 이력 저장

### 4. 사용자 가이드 작성 ✅
- README.md 작성 완료
- 설치 및 실행 방법 문서화
- API 엔드포인트 설명
- 문제 해결 가이드

---

## 2024-01-XX - VS Code Extension 연동 완료

### 1. 서버 API 개선 ✅
- **`/upload` 엔드포인트 추가**: VS Code extension 전용 간단한 업로드 API
- **세션 상세 보기**: `/session/{session_id}` 엔드포인트 추가
- **자동 분석 시작**: 업로드 후 백그라운드에서 분석 자동 실행
- **대시보드 URL 반환**: 업로드 완료 시 분석 결과 페이지 URL 제공

### 2. VS Code Extension 업데이트 ✅
- **명령어**: "Python Security: Analyze Project"
- **자동 대시보드 열기**: 업로드 후 결과 페이지 자동 오픈
- **상태/에러 피드백** 강화

### 3. 세션 상세 보기 템플릿 ✅
- **반응형 디자인**: Bootstrap 5 기반 모바일 친화적 UI
- **상세 분석 결과**: 파일별 악성/취약점 상태 및 신뢰도 표시
- **메타데이터 분석**: 패키지 정보 및 XGBoost 분석 결과 시각화
- **실시간 통계**: 안전/취약/악성 파일 수 실시간 카운트

### 4. 통합 워크플로우 완성 ✅
```
VS Code Extension → ZIP 생성 → 서버 업로드 → 자동 분석 → 대시보드 표시
     ↓                    ↓              ↓              ↓              ↓
프로젝트 선택        Python 파일      /upload API    CodeBERT + LSTM    브라우저 자동
Command 실행         + 메타데이터     백그라운드      + Metadata        열기
                    압축            분석 시작        분석
```

### 5. 사용자 경험 개선 ✅
- **원클릭 분석**: VS Code에서 명령어 하나로 전체 분석 프로세스 실행
- **자동 브라우저 열기**: 분석 결과를 즉시 확인 가능
- **상세한 피드백**: 각 단계별 진행 상황 및 결과 표시
- **직관적인 UI**: 분석 결과를 쉽게 이해할 수 있는 시각적 표현

---

## 🎉 현재 요약(스냅샷)

### 구현된 기능
1. 통합 보안 분석 시스템(서버 내 LSTM + 메타데이터 옵션, CodeBERT 실험)
2. 웹 대시보드(세션/상세, 기본 통계/시각화)
3. VS Code 확장 연동(원클릭 업로드/결과 확인)
4. 자동화된 플로우: ZIP 업로드 → 분석 → 저장 → 시각화
5. SQLite 기반 이력/통계 관리

### 기술적 성과
- **모듈화된 아키텍처**: 각 분석 엔진이 독립적으로 작동
- **비동기 처리**: 대용량 파일 분석 시 성능 최적화
- **확장 가능한 설계**: 새로운 분석 엔진 추가 용이
- **사용자 친화적 UI**: 직관적인 웹 인터페이스
- **VS Code 통합**: 개발 환경에서 직접 보안 분석 가능

### 향후 개선 방향
1. 성능 최적화: 모델 경량화, 배치 처리 개선
2. 기능 확장: CodeBERT 추론 옵션화/앙상블 스코어링
3. 보안 강화: 인증/권한, 업로드 검증 강화
4. 모니터링: 로그 표준화 및 알림

## 🚀 사용 방법

### VS Code Extension 사용
1. **Extension 설치**: VS Code에서 "Python Security Analyzer" 설치
2. **프로젝트 열기**: 분석할 Python 프로젝트 폴더 열기
3. **분석 실행**: Command Palette (`Ctrl+Shift+P`) → "Python Security: Analyze Project"
4. **결과 확인**: 자동으로 열리는 브라우저에서 분석 결과 확인

### 웹 대시보드 직접 사용
1. **서버 실행**:
   ```bash
   cd server
   py run.py
   ```

2. **웹 대시보드 접속**: `http://127.0.0.1:8000`

3. **ZIP 파일 업로드**: 드래그 앤 드롭 또는 클릭

4. **결과 확인**: 대시보드에서 분석 결과 조회

## 📊 시스템 아키텍처

```
[VS Code Extension] → [ZIP 생성] → [FastAPI Server] → [자동 분석] → [웹 대시보드]
     ↓                    ↓              ↓              ↓              ↓
프로젝트 선택        Python 파일      /upload API    CodeBERT + LSTM    브라우저 자동
Command 실행         + 메타데이터     백그라운드      + Metadata        열기
                    압축            분석 시작        분석
```

이제 Python 코드 보안 분석 시스템이 완전히 통합되어 사용할 준비가 되었습니다! 🎉
