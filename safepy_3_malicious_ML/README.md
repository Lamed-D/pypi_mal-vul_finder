# Python 패키지 보안 분석 도구 (ML 버전)

## 📋 개요

이 도구는 Python 패키지의 보안 취약점과 악성 코드를 탐지하는 통합 분석 시스템입니다.

## 🚀 주요 기능

- **LSTM 기반 취약점 탐지**: 코드 패턴 분석을 통한 취약점 식별
- **XGBoost 악성 코드 분류**: 메타데이터와 코드 특성을 종합한 악성 패키지 판단
- **Word2Vec 임베딩**: Python 코드의 의미적 분석을 위한 벡터화
- **통합 분석 파이프라인**: ZIP 파일에서 최종 리포트까지 자동화된 분석

## 📁 디렉토리 구조

```
safepy_3_malicious_ML/
├── 📄 final_unified.py          # 메인 실행 파일
├── 📄 preprocess.py             # 전처리 모듈
├── 📄 requirements.txt          # 의존성 목록
├── 📄 pipeline.md              # 상세 파이프라인 문서
├── 📄 README.md                # 이 파일
├── 🤖 xgboost_model.pkl        # XGBoost 분류 모델
├── 📁 model/                   # LSTM 모델
│   ├── model_mal.pkl
│   └── label_encoder_mal.pkl
├── 📁 w2v/                     # Word2Vec 모델
│   ├── word2vec_withString10-6-100.model
│   ├── word2vec_withString10-6-100.model.syn1neg.npy
│   └── word2vec_withString10-6-100.model.wv.vectors.npy
├── 📁 source/                  # 분석 대상 소스코드 (Git에서 제외)
└── 📁 result/                  # 분석 결과 (Git에서 제외)
```

## 🛠️ 설치 및 실행

### 1. 의존성 설치
```bash
pip install -r requirements.txt
```

### 2. 분석 실행
```bash
python final_unified.py
```

## 📊 출력 파일

- `merged_sourceCode.csv`: 병합된 소스코드 데이터
- `pypi_typo_analysis5.csv`: 메타데이터 분석 결과
- `package_vulnerability_analysis.csv`: LSTM 취약점 분석 결과
- `pypi_malicious_reason_report.txt`: 최종 악성 패키지 판단 리포트

## 🔧 기술 스택

- **TensorFlow/Keras**: LSTM 모델
- **XGBoost**: 악성 코드 분류
- **Gensim**: Word2Vec 임베딩
- **Pandas/NumPy**: 데이터 처리
- **Google Cloud BigQuery**: 메타데이터 분석

## 📖 상세 문서

자세한 파이프라인 설명은 [pipeline.md](pipeline.md)를 참조하세요.

## ⚠️ 주의사항

- `source/` 디렉토리는 분석 대상 파일들이 저장되며 Git에서 제외됩니다
- `result/` 디렉토리는 분석 결과가 저장되며 Git에서 제외됩니다
- Google Cloud API 키가 필요한 경우 적절한 인증 설정이 필요합니다
