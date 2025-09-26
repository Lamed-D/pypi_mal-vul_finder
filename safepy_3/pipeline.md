### 파이프라인: safepy_3 (LSTM 기반 취약/정상 + CWE 분류)

개요
- 입력: `source/` 폴더의 파이썬 프로젝트 ZIP
- 모델: `model/model_final.pkl`(이진: 취약/정상), `model/model_full.pkl`(다중: CWE), 라벨 인코더 2종
- 임베딩: `w2v/word2vec_withString10-6-100.model`

흐름
1) ZIP 추출: `extract_zip_files()` → 추출 디렉터리 목록
2) 파일 찾기: `find_python_files(dir)` → `.py` 목록
3) 읽기: `read_python_file(path)`
4) 전처리: `preprocess.tokenize_python` → 토큰 시퀀스
5) 임베딩: `preprocess.embed_sequences([tokens], w2v_model)`
6) 패딩: 고정 길이 100, 임베딩 차원(w2v) 기준 제로패딩
7) 예측(이진): `model_final.predict` → 1(취약) / 0(정상)
8) 예측(다중): 취약일 때만 `model_full.predict` → CWE 라벨
9) 배치: `analyze_multiple_files()` → DataFrame 생성 및 저장

핵심 함수
- `analyze_single_file(code, path)`: 단일 파일 분석 로직
- `analyze_multiple_files()`: ZIP 풀기→순회→분석→DataFrame
- `save_analysis_results(df, format)`: csv/json/xlsx 저장

비고
- Word2Vec 모델 경로를 `preprocess.py`에서 자동 탐색
- 결과 저장 경로: `result/`

