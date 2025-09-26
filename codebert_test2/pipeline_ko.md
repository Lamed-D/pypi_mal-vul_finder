### 파이프라인: codebert_test2

- 입력: `source/` 폴더의 파이썬 프로젝트가 담긴 ZIP 파일들
- 모델: HuggingFace CodeBERT 시퀀스 분류 (`model/codebert/`)

흐름
- ZIP 추출: `extract_zip_files(source_dir)` → 추출된 디렉터리 목록
- 파일 검색: `find_python_files(extracted_dir)` → `.py` 파일 목록
- 파일 읽기: `read_text(path)`
- 토크나이즈/청크: `chunk_with_overflow(tokenizer, text, MAX_LEN, STRIDE)`
- 추론: `predict_unified(device, tokenizer, model, text, ...)` →
  - 이진/다중/멀티라벨 모두 대응
  - 파일 단위 취약 확률 및 Top-K CWE 산출
- 파일 단위 결과: `analyze_python_code(file, ...)` → `FileResult`
- 결과 저장: `save_results_to_csv(results, LOG_PATH)`
- 진입점: `main()`이 전 과정을 연결하고 요약을 출력

주요 파라미터
- `MAX_LEN=512`, `STRIDE=128`, `BATCH_SZ=8`, `THRESHOLD=0.50`, `DEVICE=auto`

비고
- `find_safe_index`로 모델 라벨에서 안전(정상) 클래스를 자동 추정
- `model/config.json`의 `id2label` 사용, 있으면 `model/cwe_labels.txt`가 라벨명을 우선함

