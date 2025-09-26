## 파이프라인: safepy_3 (LSTM 기반 취약/정상 + CWE 분류)

### 개요
- 입력: `source/` 폴더의 파이썬 프로젝트 ZIP
- 모델: `model/model_final.pkl`(이진: 취약/정상), `model/model_full.pkl`(다중: CWE), 라벨 인코더 2종
- 임베딩: `w2v/word2vec_withString10-6-100.model`

### 흐름
1) ZIP 추출: `extract_zip_files()` → 추출 디렉터리 목록
2) 파일 찾기: `find_python_files(dir)` → `.py` 목록
3) 읽기: `read_python_file(path)`
4) 전처리: `preprocess.tokenize_python` → 토큰 시퀀스
5) 임베딩: `preprocess.embed_sequences([tokens], w2v_model)`
6) 패딩: 고정 길이 100, 임베딩 차원(w2v) 기준 제로패딩
7) 예측(이진): `model_final.predict` → 1(취약) / 0(정상)
8) 예측(다중): 취약일 때만 `model_full.predict` → CWE 라벨
9) 배치: `analyze_multiple_files()` → DataFrame 생성 및 저장

### 핵심 함수
- `analyze_single_file(code, path)`: 단일 파일 분석 로직
- `analyze_multiple_files()`: ZIP 풀기→순회→분석→DataFrame
- `save_analysis_results(df, format)`: csv/json/xlsx 저장

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
- **pickle 모델 오류**: `model/` 디렉토리에 `model_final.pkl`, `model_full.pkl` 파일 존재 확인
- **Word2Vec 오류**: `w2v/word2vec_withString10-6-100.model` 파일 존재 확인
- **Python 3.11 오류**: Python 3.10 이하 버전 사용 권장

## 결과 CSV 컬럼
- `file_path`: 파일 상대 경로
- `file_name`: 파일명 (예: main.py)
- `vulnerability_status`: 취약점 상태 ("Vulnerable" 또는 "Benign")
- `cwe_label`: CWE 라벨 (취약 시 구체적 CWE, 정상 시 "Benign")

## 출력 예시
```
file_path,file_name,vulnerability_status,cwe_label
src/main.py,main.py,Vulnerable,CWE-79
utils/helper.py,helper.py,Benign,Benign
```

## 성능 최적화
- **GPU 자동 감지**: TensorFlow GPU 사용 가능 시 자동으로 GPU 사용
- **동적 메모리 할당**: GPU 메모리 증가 허용으로 효율성 향상
- **고정 시퀀스 길이**: 100으로 일관된 처리
- **Word2Vec 임베딩**: 빠른 전처리
- **2단계 분류**: 이진(취약/정상) → 다중(CWE) 분류로 정확도 향상

### 비고
- Word2Vec 모델 경로를 `preprocess.py`에서 자동 탐색
- 결과 저장 경로: `result/`
- 이진 모델로 취약 여부 판정 후, 취약 시에만 다중분류로 CWE 추정

