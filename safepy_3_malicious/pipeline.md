## 파이프라인: safepy_3_malicious (LSTM 기반 악성/정상 판별)

### 개요
- 입력: `source/` 폴더의 파이썬 프로젝트 ZIP
- 모델: `model/model_mal.pkl`(악성 판별), `model/label_encoder_mal.pkl`
- 임베딩: `w2v/word2vec_withString10-6-100.model`

### 흐름
1) ZIP 추출: `extract_zip_files()` → 추출 디렉터리 목록
2) 파일 찾기: `find_python_files(dir)` → `.py` 목록
3) 읽기: `read_python_file(path)`
4) 전처리: `preprocess.tokenize_python` → 토큰 시퀀스
5) 임베딩: `preprocess.embed_sequences([tokens], w2v_model)`
6) 패딩: 고정 길이 100, 임베딩 차원(w2v) 기준 제로패딩
7) 예측: `analyze_single_file()` 내부에서 `model_mal.predict` 결과를 라벨/확률로 변환
8) 배치: `analyze_multiple_files()` → DataFrame 생성 및 저장

### 핵심 함수
- `analyze_single_file(code, path)`: 단일 파일 분석 로직
- `analyze_multiple_files()`: ZIP 풀기→순회→분석→DataFrame
- `save_analysis_results(df, format)`: csv/json/xlsx 저장

## 실행 방법
```bash
# 자동 실행 (원본과 동일한 동작)
python LSTM.py

# 또는 main() 함수 호출
python -c "from LSTM import main; main()"
```

## 환경 요구사항
- **Python**: 3.8 ~ 3.11
- **TensorFlow**: 2.16.1 (pickle 모델 호환성 필수)
- **기타**: scikit-learn==1.3.2, pandas==2.0.3, numpy==1.26.4, gensim==4.3.3

## 설치 방법
```bash
# 가상환경 생성 (권장)
python -m venv venv
source venv/bin/activate  # Linux/Mac
# 또는
venv\Scripts\activate     # Windows

# 의존성 설치
pip install -r requirements.txt
```

## 주의사항
- **TensorFlow 버전**: 2.16.1 고정 (다른 버전 사용 시 pickle 모델 로딩 실패)
- **모델 파일**: `model/` 디렉토리에 사전 훈련된 pickle 모델 필요
- **Word2Vec**: `w2v/word2vec_withString10-6-100.model` 파일 필요
- **입력 형식**: `source/` 폴더에 ZIP 파일 배치
- **출력**: `result/` 디렉토리에 결과 저장

## 트러블슈팅
- **DLL 로딩 실패**: TensorFlow 2.16.1과 numpy 1.26.4 버전 정확히 맞추기
- **pickle 모델 오류**: `model/` 디렉토리에 `model_mal.pkl` 파일 존재 확인
- **Word2Vec 오류**: `w2v/word2vec_withString10-6-100.model` 파일 존재 확인
- **Python 3.11 오류**: Python 3.10 이하 버전 사용 권장

## 원본 대비 개선사항 팀장(박은찬) 작업
- **자동 실행 제거**: import 시 자동 실행 대신 `main()` 함수로 제어
- **Keras backend 제거**: DLL 문제 해결을 위해 `tensorflow.keras.backend` import 제거
- **불필요한 함수 제거**: 콘솔 전용 `analyze_python_code` 함수 제거
- **GPU 최적화**: TensorFlow GPU 동적 메모리 할당 추가
- **한글 docstring**: 모든 함수에 상세한 한글 설명 추가

## 결과 CSV 컬럼
- `file_path`: 파일 상대 경로
- `file_name`: 파일명 (예: main.py)
- `malicious_status`: 악성 여부 ("malicious" 또는 "benign")
- `malicious_probability`: 악성 확률 (0.0~1.0 부동소수점)

## 출력 예시
```
file_path,file_name,malicious_status,malicious_probability
src/main.py,main.py,malicious,0.87
utils/helper.py,helper.py,benign,0.12
```

## 성능 최적화
- **GPU 자동 감지**: TensorFlow GPU 사용 가능 시 자동으로 GPU 사용
- **동적 메모리 할당**: GPU 메모리 증가 허용으로 효율성 향상
- **고정 시퀀스 길이**: 100으로 일관된 처리
- **Word2Vec 임베딩**: 빠른 전처리
- **단일 모델**: 악성/정상 판별로 빠른 처리

### 비고
- LSTM만 사용하며 CodeBERT/메타데이터 파이프라인과 독립
- 결과 저장 경로: `result/`
- 이진/다중분류 모두 지원하며, 악성 확률을 직접 제공

