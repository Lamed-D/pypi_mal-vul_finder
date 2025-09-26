# 프로젝트 계획서 (업데이트: 2025-09-26)

## 📋 개요

이 저장소는 Python 코드의 악성 여부 및 취약점을 분석하는 통합 시스템입니다. 현재는 로컬 추론 중심의 구성으로, 웹 서버(FastAPI), VS Code 확장, 그리고 세 가지 오프라인 분석 엔진(CodeBERT, LSTM, 메타데이터 기반)을 포함합니다.

## 🗂️ 현재 프로젝트 구조 요약

### 1. `server` — FastAPI 기반 통합 웹 서버
**목적**: ZIP 업로드, 분석 파이프라인 실행, 결과 시각화 대시보드 제공

**주요 경로/파일**:
- `server/app/main.py`: 애플리케이션 부트스트랩
- `server/app/services/file_service.py`: 업로드/추출 처리
- `server/app/services/analysis_service.py`: 분석 파이프라인 오케스트레이션
- `server/analysis/lstm_analyzer.py`: LSTM 분석기(서버 내 통합)
- `server/app/templates/dashboard.html`, `session_detail.html`: 대시보드/세션 상세
- `server/models/`: 배포용 모델 아티팩트
  - `codebert/codebert/`: CodeBERT 가중치(`model.safetensors`, `training_args.bin`)
  - `lstm/`: LSTM 가중치 및 레이블 인코더(`model_*.pkl`, `label_encoder_*.pkl`)
  - `w2v/`: Word2Vec 모델 및 벡터
  - `xgboost_model.pkl`: 메타데이터 분석용 모델

**상태**: 서버 구동, 업로드, 분석 트리거, 결과 페이지 동작 확인됨.

### 2. `vscode-extension` — VS Code 확장
**목적**: 워크스페이스를 ZIP으로 압축하여 서버에 업로드하고 결과 페이지를 연동

**주요 경로/파일**:
- `src/extension.ts`: ZIP 생성 및 업로드 로직
- `out/extension.js`: 빌드 산출물

**상태**: 로컬 서버와 연동, 업로드/알림/오픈 플로우 지원.

### 3. `codebert_test2` — CodeBERT 기반 취약점 분석(오프라인 실험)
**목적**: CodeBERT로 취약점(CWE) 분류 실험 및 배치 분석

**주요 경로/파일**:
- `Codebert.py`: 배치 분석 스크립트
- `model/codebert/`: 사전훈련/파인튜닝 산출물
- `model/cwe_labels.txt`: 라벨 정의

**상태**: 실험용 모듈. 서버에는 경량화된 아티팩트만 반영.

### 4. `safepy_3` — LSTM 기반 일반 취약점 탐지(오프라인 실험)
**목적**: Word2Vec + LSTM 기반 취약점 탐지 실험

**주요 경로/파일**:
- `LSTM.py`, `preprocess.py`
- `model/`, `w2v/`: 모델/임베딩 산출물

**상태**: 실험/데이터 파이프라인 참고용. 서버에는 통합된 `lstm_analyzer.py` 사용.

### 5. `safepy_3_malicious` — LSTM 기반 악성 코드 탐지(오프라인 실험)
**목적**: 악성/비악성 분류 모델 실험 및 결과 산출

**주요 경로/파일**:
- `LSTM.py`, `preprocess.py`
- `model/`, `w2v/`: 모델/임베딩 산출물

**상태**: 실험용. 서버 배포에는 필요한 모델만 `server/models/`로 반영.

### 6. `codebert_mal` — CodeBERT 악성 탐지 실험(오프라인 실험)
**목적**: 악성 코드 탐지 목적의 CodeBERT 활용 실험

**주요 경로/파일**:
- `analyze_package.py`
- `model/codebert/`: 가중치 및 토크나이저 산출물

**상태**: 실험/리서치용. 대용량 가중치는 `.gitignore`로 제외.

## 🔄 시스템 워크플로우(현재)

1) VS Code 확장에서 현재 워크스페이스 선택 → Python 파일 중심으로 ZIP 생성
2) `server`에 업로드(`uploads/` 보관) → 파일 추출/정리
3) 분석 서비스가 순차 실행
   - LSTM 분석기(악성/취약) 실행
   - 필요 시 CodeBERT/CWE 라벨 참조(실험 결과 반영된 경우)
   - 메타데이터 기반 점수화(XGBoost) 선택적 적용
4) 결과를 DB(`security_analysis.db`) 및 로그로 저장, 대시보드 렌더링

## 🎯 목표 및 우선순위(단기)

- 서버 내 분석 파이프라인 정합성 강화(모델 버전/라벨 스키마 통일)
- 업로드 세션별 상세 페이지 지표 확장(파일 수, 신뢰도 분포, CWE Top-N)
- 대용량 아티팩트 관리(모델 가중치) 최적화 및 문서화
- VS Code 확장 UX 개선(프로그레스/오류 안내 강화)

## 🚀 중기 개선 방안

- CodeBERT 추론 경량화(TorchScript/ONNX 고려) 및 서버 통합 옵션화
- 실시간 분석(파일 변경 감지) 및 IDE 인라인 피드백 연구
- 결과 앙상블 스코어링 규칙 정의(LSTM/CodeBERT/메타데이터 가중 합성)
- Docker 기반 배포 템플릿 제공

## 🔧 기술적 고려사항

- 보안: 업로드 파일 검증, 모델/DB 경로 접근 제어, 민감정보 제외
- 확장성: 모델 교체 가능 구조, 비동기 큐 도입 검토(대용량 시)
- 관측성: 서버 로그 표준화, 실패 케이스 수집/재현 경로 마련

## 📈 일정(권장)

- [ ] 분석 결과 스키마/라벨 체계 정리
- [ ] 대시보드 지표/필터 추가
- [ ] 모델 아티팩트 버저닝/다운로드 스크립트 제공
- [ ] VS Code 확장 상태 표시 고도화
- [ ] Docker 배포 샘플 작성

## 📝 비고

이 문서는 현재 저장소 상태를 기준으로 작성되었습니다. 과거 문서에 존재하던 `unified` 모듈과 GCP 키 사용은 현재 리포지토리에는 포함되어 있지 않습니다. 메타데이터 기반 분석은 `server/models/xgboost_model.pkl`을 통해 선택적으로 적용됩니다.
