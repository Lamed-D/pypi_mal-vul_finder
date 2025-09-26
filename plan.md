# 프로젝트 분석 및 계획서

## 📋 프로젝트 개요

이 폴더는 **Python 코드 보안 분석 시스템**으로, 여러 개의 독립적인 프로젝트들이 통합되어 있습니다. 각 프로젝트는 서로 다른 접근 방식으로 Python 코드의 취약점과 악성 코드를 탐지하는 기능을 제공합니다.

## 🗂️ 프로젝트 구조 분석

### 1. **codebert_test2** - CodeBERT 기반 취약점 탐지
**목적**: CodeBERT 모델을 사용한 Python 코드 취약점 분석

**주요 기능**:
- ZIP 파일에서 Python 코드 추출 및 분석
- CodeBERT 모델을 통한 취약점 탐지
- CWE(Common Weakness Enumeration) 분류
- 배치 처리 및 결과 CSV 저장

**기술 스택**:
- PyTorch 2.1+
- Transformers 4.40+
- NumPy 1.26.4

**핵심 파일**:
- `Codebert.py`: 메인 분석 엔진
- `model/codebert/`: 사전 훈련된 CodeBERT 모델
- `model/cwe_labels.txt`: CWE 라벨 정의

**특징**:
- 슬라이딩 윈도우 방식으로 긴 코드 처리
- 단일/다중 라벨 분류 자동 감지
- 안전 클래스 자동 탐지 및 취약도 계산

### 2. **safepy_3_malicious** - LSTM 기반 악성 코드 탐지
**목적**: LSTM 신경망을 사용한 악성 Python 코드 탐지

**주요 기능**:
- Word2Vec 임베딩을 통한 코드 토큰화
- LSTM 모델을 통한 악성 코드 분류
- 다중 파일 배치 분석
- 결과를 CSV/JSON/Excel 형식으로 저장

**기술 스택**:
- TensorFlow 2.16.1
- scikit-learn 1.3.2
- pandas 2.0.3
- gensim 4.3.3

**핵심 파일**:
- `LSTM.py`: 메인 분석 엔진
- `preprocess.py`: 코드 전처리 및 토큰화
- `model/`: 훈련된 LSTM 모델 및 라벨 인코더
- `w2v/`: Word2Vec 모델

**특징**:
- Python 내장 tokenize 모듈 사용
- 멀티라인 문자열 및 주석 제거
- 시퀀스 패딩 및 임베딩 처리

### 3. **unified** - 통합 분석 시스템
**목적**: 메타데이터 기반 악성 패키지 탐지

**주요 기능**:
- PyPI 패키지 메타데이터 분석
- 다운로드 수, 요약, 버전 정보 검증
- 오타 기반 악성 패키지 탐지
- XGBoost 모델을 통한 최종 분류

**기술 스택**:
- pandas, numpy
- Google BigQuery API
- PePy API
- XGBoost

**핵심 파일**:
- `unified_code.py`: 통합 분석 스크립트
- `xgboost_model.pkl`: 훈련된 XGBoost 모델
- `plated-mantis-471407-m4-b14f1b3e761d.json`: GCP 서비스 계정 키

**특징**:
- 메타데이터 기반 피처 엔지니어링
- 엔트로피 기반 자동 생성 텍스트 탐지
- Levenshtein 거리를 이용한 오타 탐지

### 4. **python-server** - FastAPI 웹 서버
**목적**: 파일 업로드 및 처리 API 제공

**주요 기능**:
- ZIP 파일 업로드 엔드포인트
- 파일 메타데이터 반환
- 로컬 파일 시스템 저장

**기술 스택**:
- FastAPI 0.111.0
- uvicorn 0.30.1
- python-multipart 0.0.9

**핵심 파일**:
- `main.py`: FastAPI 서버 메인 코드
- `uploads/`: 업로드된 파일 저장소

### 5. **vscode-extension** - VS Code 확장
**목적**: VS Code에서 직접 분석 도구 사용

**주요 기능**:
- 워크스페이스 폴더 ZIP 압축
- Python 패키지 소스코드 추출
- 로컬 Python 서버로 업로드
- pip show 정보 수집

**기술 스택**:
- TypeScript
- VS Code Extension API
- archiver (ZIP 압축)
- axios (HTTP 클라이언트)

**핵심 파일**:
- `src/extension.ts`: 확장 메인 코드
- `package.json`: 확장 설정 및 의존성

## 🔄 시스템 워크플로우

### 1. 코드 분석 워크플로우
```
1. VS Code 확장으로 프로젝트 폴더 선택
2. Python 파일들만 ZIP으로 압축
3. FastAPI 서버로 업로드
4. CodeBERT/LSTM 모델로 분석 수행
5. 결과를 CSV/JSON 형식으로 저장
```

### 2. 패키지 분석 워크플로우
```
1. VS Code 확장으로 Python 패키지 추출
2. site-packages에서 소스코드 수집
3. pip show 정보로 메타데이터 수집
4. 통합 분석 시스템으로 악성 패키지 탐지
5. 자연어 리포트 생성
```

## 🎯 각 프로젝트의 장단점

### CodeBERT (codebert_test2)
**장점**:
- 최신 트랜스포머 기반 모델
- CWE 분류 제공
- 긴 코드 처리 가능

**단점**:
- GPU 메모리 사용량 높음
- 모델 크기가 큼

### LSTM (safepy_3_malicious)
**장점**:
- 가벼운 모델
- 빠른 추론 속도
- 시퀀스 패턴 학습에 효과적

**단점**:
- 긴 의존성 학습 한계
- 복잡한 문법 구조 이해 제한

### 메타데이터 분석 (unified)
**장점**:
- 빠른 처리 속도
- 패키지 레벨 분석
- 오타 기반 탐지

**단점**:
- 소스코드 내용 미분석
- 외부 API 의존성

## 🚀 개선 방안

### 1. 통합 시스템 구축
- 각 분석 엔진을 하나의 웹 인터페이스로 통합
- 결과 비교 및 앙상블 분석 기능 추가

### 2. 실시간 분석
- 파일 변경 감지 시 자동 분석
- VS Code에서 실시간 취약점 표시

### 3. 성능 최적화
- 모델 경량화
- 배치 처리 최적화
- 캐싱 시스템 도입

### 4. 사용자 경험 개선
- 웹 대시보드 구축
- 시각화 기능 추가
- 상세한 취약점 설명 제공

## 📊 데이터 흐름도

```
[VS Code Extension] 
    ↓ (ZIP 업로드)
[FastAPI Server]
    ↓ (파일 저장)
[CodeBERT Analysis] ←→ [LSTM Analysis] ←→ [Metadata Analysis]
    ↓ (결과 통합)
[Result Storage & Visualization]
```

## 🔧 기술적 고려사항

### 1. 보안
- GCP 서비스 계정 키 보안 관리
- 업로드 파일 검증 및 제한
- 민감한 정보 마스킹

### 2. 확장성
- 마이크로서비스 아키텍처 고려
- 컨테이너화 (Docker)
- 로드 밸런싱

### 3. 모니터링
- 로그 시스템 구축
- 성능 메트릭 수집
- 오류 추적 및 알림

## 📈 향후 개발 계획

### Phase 1: 통합 및 안정화
- [ ] 웹 대시보드 개발
- [ ] API 통합
- [ ] 문서화 완성

### Phase 2: 고도화
- [ ] 앙상블 모델 개발
- [ ] 실시간 분석 기능
- [ ] 클라우드 배포

### Phase 3: 확장
- [ ] 다른 언어 지원
- [ ] 커스텀 모델 훈련
- [ ] 상용화 준비

## 📝 결론

현재 프로젝트는 Python 코드 보안 분석을 위한 다양한 접근 방식을 제공하는 포괄적인 시스템입니다. 각 구성 요소는 독립적으로 작동하지만, 통합된 워크플로우를 통해 강력한 보안 분석 도구로 발전시킬 수 있습니다. 

주요 강점은 CodeBERT의 정확성, LSTM의 효율성, 메타데이터 분석의 속도입니다. 이를 통합하여 다층 보안 분석 시스템을 구축하는 것이 다음 단계의 목표입니다.
