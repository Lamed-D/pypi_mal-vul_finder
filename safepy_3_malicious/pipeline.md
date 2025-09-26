### 파이프라인: safepy_3_malicious (LSTM 기반 악성/정상 판별)

개요
- 입력: `source/` 폴더의 파이썬 프로젝트 ZIP
- 모델: `model/model_mal.pkl`(악성 판별), `model/label_encoder_mal.pkl`
- 임베딩: `w2v/word2vec_withString10-6-100.model`

흐름
1) ZIP 추출: `extract_zip_files()` → 추출 디렉터리 목록
2) 파일 찾기: `find_python_files(dir)` → `.py` 목록
3) 읽기: `read_python_file(path)`
4) 전처리: `preprocess.tokenize_python` → 토큰 시퀀스
5) 임베딩: `preprocess.embed_sequences([tokens], w2v_model)`
6) 패딩: 고정 길이 100, 임베딩 차원(w2v) 기준 제로패딩
7) 예측: `model_mal.predict` → 이진 또는 다중 라벨 대응, 라벨 인코딩 복원
8) 배치: `analyze_multiple_files()` → DataFrame 생성 및 저장

핵심 함수
- `analyze_single_file(code, path)`: 단일 파일 분석 로직
- `analyze_multiple_files()`: ZIP 풀기→순회→분석→DataFrame
- `save_analysis_results(df, format)`: csv/json 저장 (필요시 xlsx)

비고
- LSTM만 사용하며 CodeBERT/메타데이터 파이프라인과 독립
- 결과 저장 경로: `result/`

