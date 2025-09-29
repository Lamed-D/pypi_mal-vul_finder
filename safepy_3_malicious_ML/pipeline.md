# 통합 Python 패키지 보안 분석 파이프라인 (Final Unified)

## 개요
`final_unified.py`는 ZIP/디렉토리 형태의 파이썬 패키지를 받아 메타데이터 분석, LSTM 기반 취약점 탐지, XGBoost 기반 악성 패키지 판별을 수행하는 통합 분석 도구입니다.

## 절차
1. **ZIP 압축 해제**: `extract_zip_and_process_source()` → `extracted_files/`로 해제
2. **소스코드 추출**: `process_directory()` → 모든 `.py` 파일을 병합하여 `result/merged_sourceCode.csv` 생성
3. **메타데이터 파싱**: `extract_and_parse_metadata()` → `metadata/` 폴더의 `.txt` 파일들 파싱
4. **메타데이터 전처리**: `preprocess_metadata()` → 다운로드 수 조회, 피처 엔지니어링
5. **LSTM 모델 로드**: `load_lstm_models()` → `model/model_mal.pkl`, `model/label_encoder_mal.pkl` 로드
6. **LSTM 코드 분석**: `analyze_lstm_codes()` → 각 패키지 코드를 LSTM으로 취약점 분석
7. **결과 통합**: `integrate_lstm_results()` → LSTM 결과와 메타데이터를 병합하여 `result/pypi_typo_analysis5.csv` 생성
8. **XGBoost 모델 로드**: `load_xgboost_model()` → `xgboost_model.pkl` 로드
9. **악성 예측**: `predict_malicious()` → 통합된 피처로 최종 악성 패키지 예측
10. **리포트 생성**: `generate_final_report()` → `result/pypi_malicious_reason_report.txt` 생성
11. **통합 결과 저장**: `save_comprehensive_results()` → `result/comprehensive_analysis_results.csv` 생성
12. **메모리 정리**: `cleanup()` → 전역 모델 및 메모리 정리

## 주요 함수

### 클래스 FinalUnifiedAnalyzer
- `remove_comments(code)`: 파이썬 소스코드에서 주석을 제거
- `process_directory(root_path)`: 지정 디렉토리 내 .py파일들을 병합하여 코드 추출
- `save_to_csv(data, output_file)`: 추출된 데이터를 CSV 파일로 저장
- `extract_zip_and_process_source()`: ZIP 압축 해제 후 소스코드 추출 및 CSV 저장
- `parse_name_email(text)`: 문자열에서 이름과 이메일을 분리 추출
- `parse_metadata(file_path)`: 메타데이터 파일에서 주요 필드(name, author 등) 파싱
- `extract_and_parse_metadata()`: 모든 메타데이터 파일을 읽어 파싱
- `get_pepy_downloads(package_name, api_key)`: PePy API로 다운로드 수 조회
- `get_download_count_bq(package_name, service_account_json)`: BigQuery를 이용해 다운로드 수 조회
- `download_unified(package_name)`: PePy → 실패 시 BigQuery 순으로 다운로드 수 조회
- `shannon_entropy(s)`: 문자열의 엔트로피 계산
- `is_valid_version(v)`: 버전 문자열 형식 검증 (x.y.z)
- `get_pypi_top_packages()`: PyPI 인기 패키지 목록 가져오기
- `extract_core_name(name)`: 패키지 이름에서 핵심 단어 추출
- `is_typo_like(pkg_name, legit_list)`: 인기 패키지와의 오타 기반 유사성 판별
- `preprocess_metadata()`: 다운로드 수, summary, 버전 등 메타데이터 전처리
- `detect_encoding(file_path)`: CSV 인코딩 후보 목록 반환
- `read_csv_data(csv_file_path)`: CSV 파일을 다양한 인코딩으로 읽어 DataFrame 변환
- `load_lstm_models()`: LSTM 모델과 라벨 인코더 로드
- `analyze_single_code(source_code, package_name)`: 단일 패키지 코드를 LSTM으로 취약점 분석
- `analyze_lstm_codes(source_csv)`: CSV 내 모든 코드에 대해 LSTM 분석 실행
- `integrate_lstm_results()`: LSTM 결과를 메타데이터 DataFrame과 통합
- `combined_threat(row)`: LSTM 분석 결과 기반 위협 수준 계산
- `load_xgboost_model()`: XGBoost 모델 로드
- `predict_malicious()`: XGBoost로 최종 악성 여부 예측
- `get_malicious_reasons(row)`: 악성 패키지로 분류된 이유 생성
- `get_normal_reasons(row)`: 정상 패키지로 분류된 이유 생성
- `generate_final_report()`: 최종 분석 결과 리포트(txt) 작성
- `save_comprehensive_results()`: 모든 결과를 포함한 통합 CSV 저장
- `cleanup()`: 메모리 및 전역 변수 정리

### 전역 함수
- `main()`: 전체 실행 파이프라인 제어 (ZIP 해제 → 메타데이터 파싱 → 전처리 → LSTM 분석 → XGBoost 예측 → 리포트/CSV 생성 → 정리)

## 환경 요구사항
- **Python**: 3.8 ~ 3.11
- **TensorFlow**: 2.16.1 (LSTM 모델 호환성 필수)
- **XGBoost**: 2.0.3
- **기타**: pandas==2.0.3, numpy==1.26.4, scikit-learn==1.3.2, gensim==4.3.3, requests==2.31.0

## 설치 방법
```bash
# 가상환경 생성 (권장)
python -m venv venv
source venv/bin/activate  # Linux/Mac
# 또는
venv\Scripts\activate     # Windows

# 의존성 설치
pip install -r requirements_final_unified.txt
```

## 실행
```bash
python final_unified.py
```

## 주의사항
- **TensorFlow 버전**: 2.16.1 고정 (다른 버전 사용 시 pickle 모델 로딩 실패)
- **모델 파일**: `model/` 디렉토리에 사전 훈련된 pickle 모델 필요
- **Word2Vec**: `w2v/word2vec_withString10-6-100.model` 파일 필요
- **XGBoost 모델**: `xgboost_model.pkl` 파일 필요
- **입력 형식**: `python-packages-1757531529324.zip` 파일 배치
- **출력**: `result/` 디렉토리에 결과 저장

## 트러블슈팅
- **DLL 로딩 실패**: TensorFlow 2.16.1과 numpy 1.26.4 버전 정확히 맞추기
- **pickle 모델 오류**: `model/` 디렉토리에 `model_mal.pkl`, `label_encoder_mal.pkl` 파일 존재 확인
- **XGBoost 모델 오류**: `xgboost_model.pkl` 파일 존재 확인
- **Word2Vec 오류**: `w2v/word2vec_withString10-6-100.model` 파일 존재 확인
- **Python 3.11 오류**: Python 3.10 이하 버전 사용 권장

## 결과 파일
- `result/merged_sourceCode.csv`: 병합된 소스코드
- `result/pypi_typo_analysis5.csv`: 통합 분석 데이터 (메타데이터 + LSTM 결과)
- `result/package_vulnerability_analysis.csv`: LSTM 분석 결과
- `result/comprehensive_analysis_results.csv`: 모든 결과 통합 CSV
- `result/pypi_malicious_reason_report.txt`: 최종 판단 리포트

## 결과 CSV 컬럼 (comprehensive_analysis_results.csv)
- `name`: 패키지명
- `xgboost_prediction`: XGBoost 최종 예측 (0: 정상, 1: 악성)
- `lstm_vulnerability_status`: LSTM 취약점 상태 ("Vulnerable" 또는 "Not Vulnerable")
- `lstm_cwe_label`: LSTM CWE 라벨 (취약 시 구체적 CWE, 정상 시 "Benign")
- `lstm_confidence`: LSTM 신뢰도 (0.0~1.0)
- `summary`: 패키지 설명
- `author`: 작성자
- `author-email`: 작성자 이메일
- `version`: 버전
- `download`: 다운로드 수
- `download_log`: 로그 변환된 다운로드 수

## 출력 예시
```csv
name,xgboost_prediction,lstm_vulnerability_status,lstm_cwe_label,lstm_confidence,summary,author,download
test-package,1,Vulnerable,CWE-79,0.85,Test package,John Doe,1000
safe-package,0,Not Vulnerable,Benign,0.12,Safe package,Jane Smith,50000
```

## 성능 최적화
- **GPU 자동 감지**: TensorFlow GPU 사용 가능 시 자동으로 GPU 사용
- **동적 메모리 할당**: GPU 메모리 증가 허용으로 효율성 향상
- **고정 시퀀스 길이**: 100으로 일관된 LSTM 처리
- **Word2Vec 임베딩**: 빠른 전처리
- **통합 파이프라인**: 메타데이터 + LSTM + XGBoost 통합 분석

## DB 연동 권장 함수
기존 결과를 DB에 저장할 경우 다음 함수들을 활용하는 것을 권장합니다:

### 1. 메타데이터 저장용
- `extract_and_parse_metadata()`: 메타데이터 추출 후 DB 저장
- `preprocess_metadata()`: 전처리된 메타데이터를 DB에 저장

### 2. LSTM 분석 결과 저장용
- `analyze_lstm_codes()`: LSTM 분석 결과를 DB에 저장
- `integrate_lstm_results()`: 통합된 결과를 DB에 저장

### 3. 최종 예측 결과 저장용
- `predict_malicious()`: XGBoost 예측 결과를 DB에 저장
- `save_comprehensive_results()`: 통합 결과를 DB에 저장

### 4. 리포트 저장용
- `generate_final_report()`: 리포트 내용을 DB에 저장

### DB 연동 시 권장 구조
```python
# 예시: DB 저장 함수 추가
def save_to_database(self, table_name, data):
    """분석 결과를 데이터베이스에 저장"""
    # DB 연결 및 저장 로직
    pass

def load_from_database(self, table_name, conditions=None):
    """데이터베이스에서 분석 결과 로드"""
    # DB 연결 및 조회 로직
    pass
```

### 비고
- 통합 파이프라인으로 메타데이터, LSTM, XGBoost 분석을 순차적으로 수행
- 결과 저장 경로: `result/`
- LSTM은 취약점 탐지, XGBoost는 최종 악성 패키지 판별에 사용
- 모든 중간 결과와 최종 결과를 CSV 형태로 저장하여 추후 분석 가능
